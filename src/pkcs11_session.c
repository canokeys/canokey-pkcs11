#include "pkcs11_session.h"
#include "pcsc_canokey.h"

#include <stdlib.h>
#include <string.h>

// Session table and related variables
static PKCS11_SESSION **session_table = NULL;
static CK_ULONG session_table_size = 0;
static CK_ULONG session_count = 0;
static CK_SESSION_HANDLE next_handle = 1; // Start from 1, 0 is invalid
static nsync_mu session_mutex = NSYNC_MU_INIT;

// Initialize the session manager
CK_RV session_manager_init(void) {
  nsync_mu_lock(&session_mutex);

  // Initial allocation for the session table
  if (session_table == NULL) {
    session_table_size = 10; // Initial size, will grow as needed
    session_table = (PKCS11_SESSION **)ck_malloc(session_table_size * sizeof(PKCS11_SESSION *));
    if (session_table == NULL) {
      nsync_mu_unlock(&session_mutex);
      return CKR_HOST_MEMORY;
    }
    memset(session_table, 0, session_table_size * sizeof(PKCS11_SESSION *));
  }

  nsync_mu_unlock(&session_mutex);
  return CKR_OK;
}

// Clean up the session manager
void session_manager_cleanup(void) {
  nsync_mu_lock(&session_mutex);

  if (session_table != NULL) {
    // Free all session structures
    for (CK_ULONG i = 0; i < session_table_size; i++) {
      if (session_table[i] != NULL) {
        ck_free(session_table[i]);
        session_table[i] = NULL;
      }
    }

    // Free the session table
    ck_free(session_table);
    session_table = NULL;
    session_table_size = 0;
    session_count = 0;
    next_handle = 1;
  }

  nsync_mu_unlock(&session_mutex);
}

// Helper function to resize the session table if needed
static CK_RV resize_session_table(void) {
  // Check if we need to resize (if table is 80% full)
  if (session_count < (session_table_size * 0.8)) {
    return CKR_OK;
  }

  // Double the size
  CK_ULONG new_size = session_table_size * 2;
  PKCS11_SESSION **new_table = (PKCS11_SESSION **)ck_malloc(new_size * sizeof(PKCS11_SESSION *));
  if (new_table == NULL) {
    return CKR_HOST_MEMORY;
  }

  // Initialize new table
  memset(new_table, 0, new_size * sizeof(PKCS11_SESSION *));

  // Copy existing sessions
  for (CK_ULONG i = 0; i < session_table_size; i++) {
    if (session_table[i] != NULL) {
      new_table[i] = session_table[i];
    }
  }

  // Free old table and update pointers
  ck_free(session_table);
  session_table = new_table;
  session_table_size = new_size;

  return CKR_OK;
}

// Find a free slot in the session table
static CK_LONG find_free_slot(void) {
  for (CK_ULONG i = 0; i < session_table_size; i++) {
    if (session_table[i] == NULL) {
      return i;
    }
  }
  return -1; // No free slot found
}

// Open a new session
CK_RV session_open(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify,
                   CK_SESSION_HANDLE_PTR phSession) {
  if (phSession == NULL) {
    return CKR_ARGUMENTS_BAD;
  }

  // Check if the slot ID is valid
  CK_ULONG i;
  CK_BBOOL slot_found = CK_FALSE;
  for (i = 0; i < g_num_readers; i++) {
    if (g_readers[i].slot_id == slotID) {
      slot_found = CK_TRUE;
      break;
    }
  }

  if (!slot_found) {
    return CKR_SLOT_ID_INVALID;
  }

  // Check if the flags are valid
  if (!(flags & CKF_SERIAL_SESSION)) {
    return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
  }

  nsync_mu_lock(&session_mutex);

  // Initialize session manager if needed
  if (session_table == NULL) {
    CK_RV rv = session_manager_init();
    if (rv != CKR_OK) {
      nsync_mu_unlock(&session_mutex);
      return rv;
    }
  }

  // Resize session table if needed
  CK_RV rv = resize_session_table();
  if (rv != CKR_OK) {
    nsync_mu_unlock(&session_mutex);
    return rv;
  }
  
  // Find a free slot in the session table
  CK_LONG slot = find_free_slot();
  if (slot < 0) {
    nsync_mu_unlock(&session_mutex);
    return CKR_HOST_MEMORY;
  }

  // Allocate a new session
  PKCS11_SESSION *session = (PKCS11_SESSION *)ck_malloc(sizeof(PKCS11_SESSION));
  if (session == NULL) {
    nsync_mu_unlock(&session_mutex);
    return CKR_HOST_MEMORY;
  }

  // Initialize the session
  memset(session, 0, sizeof(PKCS11_SESSION));
  session->handle = next_handle++;
  session->slot_id = slotID;
  session->flags = flags;
  session->application = pApplication;
  session->notify = Notify;
  session->is_open = CK_TRUE;
  
  // Initialize PIN fields
  memset(session->piv_pin, 0xFF, sizeof(session->piv_pin));
  session->piv_pin_len = 0;

  // Set the session state based on flags
  if (flags & CKF_RW_SESSION) {
    session->state = SESSION_STATE_RW_PUBLIC;
  } else {
    session->state = SESSION_STATE_RO_PUBLIC;
  }

  // Add the session to the table
  session_table[slot] = session;
  session_count++;

  // Return the session handle
  *phSession = session->handle;

  nsync_mu_unlock(&session_mutex);
  return CKR_OK;
}

// Close a session
CK_RV session_close(CK_SESSION_HANDLE hSession) {
  nsync_mu_lock(&session_mutex);

  // Find the session
  CK_BBOOL found = CK_FALSE;
  CK_ULONG index = 0;

  for (CK_ULONG i = 0; i < session_table_size; i++) {
    if (session_table[i] != NULL && session_table[i]->handle == hSession) {
      found = CK_TRUE;
      index = i;
      break;
    }
  }

  if (!found) {
    nsync_mu_unlock(&session_mutex);
    return CKR_SESSION_HANDLE_INVALID;
  }

  // No need to disconnect card as we don't maintain the handle

  // Free the session
  ck_free(session_table[index]);
  session_table[index] = NULL;
  session_count--;

  nsync_mu_unlock(&session_mutex);
  return CKR_OK;
}

// Close all sessions for a slot
CK_RV session_close_all(CK_SLOT_ID slotID) {
  nsync_mu_lock(&session_mutex);

  // Check if the slot ID is valid
  CK_ULONG i;
  CK_BBOOL slot_found = CK_FALSE;
  for (i = 0; i < g_num_readers; i++) {
    if (g_readers[i].slot_id == slotID) {
      slot_found = CK_TRUE;
      break;
    }
  }

  if (!slot_found) {
    nsync_mu_unlock(&session_mutex);
    return CKR_SLOT_ID_INVALID;
  }

  // Close all sessions for this slot
  for (i = 0; i < session_table_size; i++) {
    if (session_table[i] != NULL && session_table[i]->slot_id == slotID) {
      // No need to disconnect card as we don't maintain the handle

      // Free the session
      ck_free(session_table[i]);
      session_table[i] = NULL;
      session_count--;
    }
  }

  nsync_mu_unlock(&session_mutex);
  return CKR_OK;
}

// Get session info
CK_RV session_get_info(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
  if (pInfo == NULL) {
    return CKR_ARGUMENTS_BAD;
  }

  nsync_mu_lock(&session_mutex);

  // Find the session
  PKCS11_SESSION *session = NULL;
  CK_BBOOL found = CK_FALSE;

  for (CK_ULONG i = 0; i < session_table_size; i++) {
    if (session_table[i] != NULL && session_table[i]->handle == hSession) {
      session = session_table[i];
      found = CK_TRUE;
      break;
    }
  }

  if (!found) {
    nsync_mu_unlock(&session_mutex);
    return CKR_SESSION_HANDLE_INVALID;
  }

  // Fill in the session info
  pInfo->slotID = session->slot_id;
  pInfo->state = (CK_STATE)session->state;
  pInfo->flags = session->flags;
  pInfo->ulDeviceError = 0;

  nsync_mu_unlock(&session_mutex);
  return CKR_OK;
}

// Find a session by handle
CK_RV session_find(CK_SESSION_HANDLE hSession, PKCS11_SESSION **session) {
  if (session == NULL) {
    return CKR_ARGUMENTS_BAD;
  }

  nsync_mu_lock(&session_mutex);

  // Find the session
  CK_BBOOL found = CK_FALSE;

  for (CK_ULONG i = 0; i < session_table_size; i++) {
    if (session_table[i] != NULL && session_table[i]->handle == hSession) {
      *session = session_table[i];
      found = CK_TRUE;
      break;
    }
  }

  nsync_mu_unlock(&session_mutex);

  if (!found) {
    return CKR_SESSION_HANDLE_INVALID;
  }

  return CKR_OK;
}