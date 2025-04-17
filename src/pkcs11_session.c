#include "pkcs11_session.h"

#include "logging.h"
#include "utils.h"
#include "pcsc_backend.h"

#include <string.h>

// Session table and related variables
static CNK_PKCS11_SESSION **session_table = NULL;
static CK_LONG session_table_size = 0;
static CK_LONG session_count = 0;
static CK_SESSION_HANDLE next_handle = 1; // Start from 1, 0 is invalid
static CNK_PKCS11_MUTEX session_mutex;

// Initialize the session manager
CK_RV cnk_session_manager_init(void) {
  CNK_LOG_FUNC();

  // Initialize the session mutex
  CNK_ENSURE_OK(cnk_mutex_create(&session_mutex));

  cnk_mutex_lock(&session_mutex);

  // Initial allocation for the session table
  if (session_table == NULL) {
    session_table_size = 10; // Initial size, will grow as needed
    session_table = (CNK_PKCS11_SESSION **)ck_malloc(session_table_size * sizeof(CNK_PKCS11_SESSION *));
    if (session_table == NULL) {
      cnk_mutex_unlock(&session_mutex);
      CNK_RETURN(CKR_HOST_MEMORY, "Failed to allocate memory for session table");
    }
    memset(session_table, 0, session_table_size * sizeof(CNK_PKCS11_SESSION *));
  }

  cnk_mutex_unlock(&session_mutex);
  CNK_RET_OK;
}

// Clean up the session manager
void cnk_session_manager_cleanup(void) {
  CNK_LOG_FUNC();

  cnk_mutex_lock(&session_mutex);

  if (session_table != NULL) {
    // Free all session structures
    for (CK_LONG i = 0; i < session_table_size; i++) {
      if (session_table[i] != NULL) {
        // Destroy the session mutex
        cnk_mutex_destroy(&session_table[i]->lock);
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

  cnk_mutex_unlock(&session_mutex);

  // Destroy the session manager mutex
  cnk_mutex_destroy(&session_mutex);
}

// Helper function to resize the session table if needed
static CK_RV resize_session_table(void) {
  // Check if we need to resize (if table is 80% full)
  if (session_count < (session_table_size * 10 / 8)) {
    CNK_RET_OK;
  }

  // Double the size
  CK_ULONG new_size = session_table_size * 2;
  CNK_PKCS11_SESSION **new_table = (CNK_PKCS11_SESSION **)ck_malloc(new_size * sizeof(CNK_PKCS11_SESSION *));
  if (new_table == NULL)
    CNK_RETURN(CKR_HOST_MEMORY, "Failed to allocate memory for session table");

  // Initialize new table
  memset(new_table, 0, new_size * sizeof(CNK_PKCS11_SESSION *));

  // Copy existing sessions
  for (CK_LONG i = 0; i < session_table_size; i++) {
    if (session_table[i] != NULL) {
      new_table[i] = session_table[i];
    }
  }

  // Free old table and update pointers
  ck_free(session_table);
  session_table = new_table;
  session_table_size = new_size;

  CNK_RET_OK;
}

// Find a free slot in the session table
static CK_LONG find_free_slot(void) {
  for (CK_LONG i = 0; i < session_table_size; i++) {
    if (session_table[i] == NULL) {
      return i;
    }
  }
  return -1; // No free slot found
}

// Open a new session
CK_RV cnk_session_open(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify,
                       CK_SESSION_HANDLE_PTR phSession) {
  CNK_LOG_FUNC();

  CNK_ENSURE_NONNULL(phSession);

  cnk_mutex_lock(&session_mutex);

  if (!g_cnk_is_managed_mode) {
    cnk_mutex_lock(&g_cnk_readers_mutex);
    // Check if the slot ID is valid
    CK_BBOOL slot_found = CK_FALSE;
    for (CK_LONG i = 0; i < g_cnk_num_readers; i++) {
      if (g_cnk_readers[i].slot_id == slotID) {
        slot_found = CK_TRUE;
        break;
      }
    }
    cnk_mutex_unlock(&g_cnk_readers_mutex);

    if (!slot_found) {
      cnk_mutex_unlock(&session_mutex);
      CNK_RETURN(CKR_SLOT_ID_INVALID, "Invalid slot ID");
    }
  }

  // Check if the flags are valid
  if (!(flags & CKF_SERIAL_SESSION)) {
    cnk_mutex_unlock(&session_mutex);
    CNK_RETURN(CKR_SESSION_PARALLEL_NOT_SUPPORTED, "Invalid session flags");
  }

  // Initialize session manager if needed
  if (session_table == NULL) {
    CK_RV rv = cnk_session_manager_init();
    if (rv != CKR_OK) {
      cnk_mutex_unlock(&session_mutex);
      CNK_RETURN(CKR_HOST_MEMORY, "Failed to initialize session manager");
    }
  }

  // Resize session table if needed
  CK_RV rv = resize_session_table();
  if (rv != CKR_OK) {
    cnk_mutex_unlock(&session_mutex);
    CNK_RETURN(CKR_HOST_MEMORY, "Failed to resize session table");
  }

  // Find a free slot in the session table
  CK_LONG sessionIdx = find_free_slot();
  if (sessionIdx < 0) {
    cnk_mutex_unlock(&session_mutex);
    CNK_RETURN(CKR_HOST_MEMORY, "No free session slots available");
  }

  CNK_DEBUG("found free session index: %ld", sessionIdx);

  // Allocate a new session
  CNK_PKCS11_SESSION *session = (CNK_PKCS11_SESSION *)ck_malloc(sizeof(CNK_PKCS11_SESSION));
  if (session == NULL) {
    cnk_mutex_unlock(&session_mutex);
    CNK_RETURN(CKR_HOST_MEMORY, "Failed to allocate memory for session");
  }

  // Initialize the session
  memset(session, 0, sizeof(CNK_PKCS11_SESSION));
  session->handle = next_handle++;
  session->slot_id = slotID;
  session->flags = flags;
  session->application = pApplication;
  session->notify = Notify;
  session->is_open = CK_TRUE;

  // Initialize PIN fields
  memset(session->piv_pin, 0xFF, sizeof(session->piv_pin));
  session->piv_pin_len = 0;

  // Initialize the session mutex
  rv = cnk_mutex_create(&session->lock);
  if (rv != CKR_OK) {
    ck_free(session);
    cnk_mutex_unlock(&session_mutex);
    CNK_RETURN(rv, "Failed to create session mutex");
  }

  // Set the session state based on flags
  if (flags & CKF_RW_SESSION) {
    session->state = SESSION_STATE_RW_PUBLIC;
  } else {
    session->state = SESSION_STATE_RO_PUBLIC;
  }

  // Add the session to the table
  session_table[sessionIdx] = session;
  session_count++;

  // Return the session handle
  *phSession = session->handle;

  cnk_mutex_unlock(&session_mutex);

  CNK_RET_OK;
}

// Close a session
CK_RV cnk_session_close(CK_SESSION_HANDLE hSession) {
  CNK_LOG_FUNC();

  cnk_mutex_lock(&session_mutex);

  // Find the session
  CK_BBOOL found = CK_FALSE;
  CK_LONG index = 0;

  for (CK_LONG i = 0; i < session_table_size; i++) {
    if (session_table[i] != NULL && session_table[i]->handle == hSession) {
      found = CK_TRUE;
      index = i;
      break;
    }
  }

  if (!found) {
    cnk_mutex_unlock(&session_mutex);
    CNK_RETURN(CKR_SESSION_HANDLE_INVALID, "Session not found");
  }

  // No need to disconnect card as we don't maintain the handle

  // Free the session
  ck_free(session_table[index]);
  session_table[index] = NULL;
  session_count--;

  cnk_mutex_unlock(&session_mutex);

  CNK_RET_OK;
}

// Close all sessions for a slot
CK_RV cnk_session_close_all(CK_SLOT_ID slotID) {
  cnk_mutex_lock(&session_mutex);

  // Close all sessions for this slot
  for (CK_LONG i = 0; i < session_table_size; i++) {
    if (session_table[i] != NULL && session_table[i]->slot_id == slotID) {
      // No need to disconnect card as we don't maintain the handle

      // Free the session
      ck_free(session_table[i]);
      session_table[i] = NULL;
      session_count--;
    }
  }

  cnk_mutex_unlock(&session_mutex);
  CNK_RET_OK;
}

// Get session info
CK_RV cnk_session_get_info(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
  if (pInfo == NULL) {
    return CKR_ARGUMENTS_BAD;
  }

  cnk_mutex_lock(&session_mutex);

  // Find the session
  CNK_PKCS11_SESSION *session = NULL;
  CK_BBOOL found = CK_FALSE;

  for (CK_LONG i = 0; i < session_table_size; i++) {
    if (session_table[i] != NULL && session_table[i]->handle == hSession) {
      session = session_table[i];
      found = CK_TRUE;
      break;
    }
  }

  if (!found) {
    cnk_mutex_unlock(&session_mutex);
    CNK_RETURN(CKR_SESSION_HANDLE_INVALID, "Session not found");
  }

  // Fill in the session info
  pInfo->slotID = session->slot_id;
  pInfo->state = (CK_STATE)session->state;
  pInfo->flags = session->flags;
  pInfo->ulDeviceError = 0;

  cnk_mutex_unlock(&session_mutex);
  CNK_RET_OK;
}

// Find a session by handle
CK_RV cnk_session_find(CK_SESSION_HANDLE hSession, CNK_PKCS11_SESSION **session) {

  CNK_ENSURE_NONNULL(session);

  cnk_mutex_lock(&session_mutex);

  // Find the session
  CK_BBOOL found = CK_FALSE;

  for (CK_LONG i = 0; i < session_table_size; i++) {
    if (session_table[i] != NULL && session_table[i]->handle == hSession) {
      *session = session_table[i];
      found = CK_TRUE;
      CNK_DEBUG("Found session with handle %lu at session idx %ld", hSession, i);
      break;
    }
  }

  cnk_mutex_unlock(&session_mutex);

  if (!found) {
    CNK_RETURN(CKR_SESSION_HANDLE_INVALID, "Session not found");
  }

  CNK_RET_OK;
}
