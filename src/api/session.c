#include "api/session.h"

#include "api/operation.h"
#include "backend/pcsc.h"
#include "internal/logging.h"
#include "internal/macros.h"
#include "internal/util.h"

#include <mbedtls/platform_util.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sched.h>
#endif

// Session table and related variables
static CNK_PKCS11_SESSION **session_table = NULL;
static CK_LONG session_table_size = 0;
static CK_LONG session_count = 0;
static CK_SESSION_HANDLE next_handle = 1; // Start from 1, 0 is invalid
static CNK_PKCS11_MUTEX session_mutex;
// Close removes a session only after activeCalls reaches zero, so a concurrent
// lookup cannot observe freed storage after releasing the table lock.
static CNK_PKCS11_TOKEN_STATE *token_states = NULL;

static void yield_session_close(void) {
#ifdef _WIN32
  Sleep(0);
#else
  sched_yield();
#endif
}

// Helper function to resize the session table if needed
static CK_RV resize_session_table(void) {
  if (session_count < session_table_size) {
    CNK_RET_OK;
  }

  // Double the size
  CK_LONG new_size = session_table_size * 2;
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

static void free_session(CNK_PKCS11_SESSION *session) {
  if (session == NULL)
    return;

  // Operation contexts can own copied parameters, buffered messages, and key
  // material independently of whether the operation reached its final call.
  cnk_reset_signing_context(session);
  cnk_reset_verifying_context(session);
  cnk_reset_encrypting_context(session);
  cnk_reset_decrypting_context(session);
  cnk_reset_digesting_context(session);
  for (CK_ULONG i = 0; i < MAX_SESSION_SECRET_KEYS; i++) {
    if (session->secretKeys[i].active)
      mbedtls_platform_zeroize(session->secretKeys[i].value, sizeof(session->secretKeys[i].value));
  }
  cnk_mutex_destroy(&session->lock);
  mbedtls_platform_zeroize(session, sizeof(*session));
  ck_free(session);
}

static void clear_token_auth(CNK_PKCS11_TOKEN_STATE *token) {
  // Authentication is token-scoped. Clear both caches together on logout,
  // last-session close, and finalize so later sessions cannot inherit secrets.
  memset(token->pin, 0xFF, sizeof(token->pin));
  token->cbPin = 0;
  mbedtls_platform_zeroize(token->managementKey, sizeof(token->managementKey));
  token->cbManagementKey = 0;
  token->managementLoginPending = CK_FALSE;
  token->loginState = TOKEN_LOGIN_PUBLIC;
}

static CNK_PKCS11_TOKEN_STATE *find_token_state(CK_SLOT_ID slotId) {
  for (CNK_PKCS11_TOKEN_STATE *token = token_states; token != NULL; token = token->next)
    if (token->slotId == slotId)
      return token;
  return NULL;
}

static CK_RV get_or_create_token_state(CK_SLOT_ID slotId, CNK_PKCS11_TOKEN_STATE **result) {
  CNK_PKCS11_TOKEN_STATE *token = find_token_state(slotId);
  if (token != NULL) {
    *result = token;
    return CKR_OK;
  }
  token = ck_calloc(1, sizeof(*token));
  if (token == NULL)
    return CKR_HOST_MEMORY;
  CK_RV rv = cnk_mutex_create(&token->lock);
  if (rv != CKR_OK) {
    ck_free(token);
    return rv;
  }
  token->slotId = slotId;
  clear_token_auth(token);
  token->next = token_states;
  token_states = token;
  *result = token;
  return CKR_OK;
}

static SessionState get_session_state(const CNK_PKCS11_SESSION *session) {
  CK_BBOOL rw = (session->flags & CKF_RW_SESSION) != 0;
  switch (session->token->loginState) {
  case TOKEN_LOGIN_USER:
    return rw ? SESSION_STATE_RW_USER : SESSION_STATE_RO_USER;
  case TOKEN_LOGIN_SO:
    return SESSION_STATE_RW_SO;
  default:
    return rw ? SESSION_STATE_RW_PUBLIC : SESSION_STATE_RO_PUBLIC;
  }
}

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
        free_session(session_table[i]);
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

  while (token_states != NULL) {
    CNK_PKCS11_TOKEN_STATE *token = token_states;
    token_states = token->next;
    clear_token_auth(token);
    cnk_mutex_destroy(&token->lock);
    ck_free(token);
  }

  cnk_mutex_unlock(&session_mutex);

  // Destroy the session manager mutex
  cnk_mutex_destroy(&session_mutex);
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
      (*session)->activeCalls++;
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

void cnk_session_release_ref(CNK_PKCS11_SESSION **session) {
  if (session == NULL || *session == NULL)
    return;
  cnk_mutex_lock(&session_mutex);
  if ((*session)->activeCalls > 0)
    (*session)->activeCalls--;
  cnk_mutex_unlock(&session_mutex);
  *session = NULL;
}

CK_BBOOL cnk_token_pin_is_cached(CNK_PKCS11_SESSION *session) {
  CK_BBOOL result;
  cnk_mutex_lock(&session->token->lock);
  result =
      !session->token->logoutPending && session->token->loginState == TOKEN_LOGIN_USER && session->token->cbPin > 0;
  cnk_mutex_unlock(&session->token->lock);
  return result;
}

CK_RV cnk_token_copy_pin(CNK_PKCS11_SESSION *session, CK_BYTE pin[8], CK_ULONG_PTR pinLen) {
  CNK_ENSURE_NONNULL(session, pin, pinLen);
  cnk_mutex_lock(&session->token->lock);
  if (session->token->logoutPending || session->token->loginState != TOKEN_LOGIN_USER || session->token->cbPin == 0) {
    cnk_mutex_unlock(&session->token->lock);
    return CKR_USER_NOT_LOGGED_IN;
  }
  memcpy(pin, session->token->pin, sizeof(session->token->pin));
  *pinLen = session->token->cbPin;
  cnk_mutex_unlock(&session->token->lock);
  return CKR_OK;
}

CK_RV cnk_token_cache_pin(CNK_PKCS11_SESSION *session, CK_UTF8CHAR_PTR pin, CK_ULONG pinLen) {
  CNK_ENSURE_NONNULL(session, pin);
  if (pinLen > sizeof(session->token->pin))
    return CKR_PIN_LEN_RANGE;
  cnk_mutex_lock(&session->token->lock);
  memset(session->token->pin, 0xFF, sizeof(session->token->pin));
  memcpy(session->token->pin, pin, pinLen);
  session->token->cbPin = pinLen;
  cnk_mutex_unlock(&session->token->lock);
  return CKR_OK;
}

CK_RV cnk_token_update_cached_pin(CNK_PKCS11_SESSION *session, CK_UTF8CHAR_PTR oldPin, CK_ULONG oldPinLen,
                                  CK_UTF8CHAR_PTR newPin, CK_ULONG newPinLen) {
  cnk_mutex_lock(&session->token->lock);
  if (session->token->cbPin > 0 && session->token->cbPin == oldPinLen &&
      memcmp(session->token->pin, oldPin, oldPinLen) == 0) {
    memset(session->token->pin, 0xFF, sizeof(session->token->pin));
    memcpy(session->token->pin, newPin, newPinLen);
    session->token->cbPin = newPinLen;
  }
  cnk_mutex_unlock(&session->token->lock);
  return CKR_OK;
}

CK_BBOOL cnk_token_management_key_is_cached(CNK_PKCS11_SESSION *session) {
  CK_BBOOL result;
  cnk_mutex_lock(&session->token->lock);
  result = !session->token->logoutPending && session->token->cbManagementKey == sizeof(session->token->managementKey);
  cnk_mutex_unlock(&session->token->lock);
  return result;
}

CK_RV cnk_token_copy_management_key(CNK_PKCS11_SESSION *session, CK_BYTE key[24]) {
  CNK_ENSURE_NONNULL(session, key);
  cnk_mutex_lock(&session->token->lock);
  if (session->token->logoutPending || session->token->cbManagementKey != sizeof(session->token->managementKey)) {
    cnk_mutex_unlock(&session->token->lock);
    return CKR_USER_NOT_LOGGED_IN;
  }
  memcpy(key, session->token->managementKey, sizeof(session->token->managementKey));
  cnk_mutex_unlock(&session->token->lock);
  return CKR_OK;
}

CK_RV cnk_token_begin_protected_management_login(CNK_PKCS11_SESSION *session) {
  CNK_ENSURE_NONNULL(session, session->token);
  cnk_mutex_lock(&session->token->lock);
  if (session->token->logoutPending || session->token->loginState != TOKEN_LOGIN_USER || session->token->cbPin == 0) {
    cnk_mutex_unlock(&session->token->lock);
    return CKR_USER_NOT_LOGGED_IN;
  }
  if (session->token->cbManagementKey == sizeof(session->token->managementKey)) {
    cnk_mutex_unlock(&session->token->lock);
    return CKR_USER_ALREADY_LOGGED_IN;
  }
  if (session->token->managementLoginPending) {
    cnk_mutex_unlock(&session->token->lock);
    return CKR_OPERATION_ACTIVE;
  }
  session->token->managementLoginPending = CK_TRUE;
  cnk_mutex_unlock(&session->token->lock);
  return CKR_OK;
}

CK_RV cnk_token_complete_protected_management_login(CNK_PKCS11_SESSION *session, CK_BYTE_PTR key, CK_ULONG keyLen,
                                                    CK_RV verificationRv) {
  CNK_ENSURE_NONNULL(session, session->token, key);
  if (keyLen != sizeof(session->token->managementKey))
    return CKR_PIN_LEN_RANGE;
  cnk_mutex_lock(&session->token->lock);
  CK_RV rv = verificationRv;
  if (rv == CKR_OK && session->token->managementLoginPending && session->token->loginState == TOKEN_LOGIN_USER &&
      session->token->cbPin > 0) {
    memcpy(session->token->managementKey, key, keyLen);
    session->token->cbManagementKey = keyLen;
  } else if (rv == CKR_OK) {
    rv = CKR_USER_NOT_LOGGED_IN;
  }
  session->token->managementLoginPending = CK_FALSE;
  cnk_mutex_unlock(&session->token->lock);
  return rv;
}

void cnk_token_get_session_counts(CK_SLOT_ID slotId, CK_ULONG_PTR openSessions, CK_ULONG_PTR readOnlySessions) {
  if (openSessions == NULL || readOnlySessions == NULL)
    return;
  *openSessions = 0;
  *readOnlySessions = 0;
  cnk_mutex_lock(&session_mutex);
  CNK_PKCS11_TOKEN_STATE *token = find_token_state(slotId);
  if (token != NULL) {
    cnk_mutex_lock(&token->lock);
    *openSessions = token->openSessions;
    *readOnlySessions = token->readOnlySessions;
    cnk_mutex_unlock(&token->lock);
  }
  cnk_mutex_unlock(&session_mutex);
}

CK_RV cnk_token_revoke_private_operations(CNK_PKCS11_TOKEN_STATE *token) {
  CNK_ENSURE_NONNULL(token);

  // Take guarded references while holding the table lock, then acquire each
  // session lock after releasing it. This preserves the global lock order and
  // keeps session storage alive while Logout clears operation contexts.
  cnk_mutex_lock(&session_mutex);
  CK_ULONG count = 0;
  for (CK_LONG i = 0; i < session_table_size; i++)
    if (session_table[i] != NULL && session_table[i]->token == token)
      count++;

  CNK_PKCS11_SESSION **sessions = count == 0 ? NULL : ck_malloc(count * sizeof(*sessions));
  if (count != 0 && sessions == NULL) {
    cnk_mutex_unlock(&session_mutex);
    return CKR_HOST_MEMORY;
  }

  CK_ULONG index = 0;
  for (CK_LONG i = 0; i < session_table_size; i++) {
    if (session_table[i] != NULL && session_table[i]->token == token) {
      sessions[index] = session_table[i];
      sessions[index]->activeCalls++;
      index++;
    }
  }
  cnk_mutex_unlock(&session_mutex);

  for (CK_ULONG i = 0; i < count; i++) {
    CNK_PKCS11_SESSION *session = sessions[i];
    cnk_mutex_lock(&session->lock);
    cnk_reset_signing_context(session);
    cnk_reset_decrypting_context(session);
    cnk_mutex_unlock(&session->lock);
    CNK_PKCS11_SESSION *reference = session;
    cnk_session_release_ref(&reference);
  }
  ck_free(sessions);
  return CKR_OK;
}

CK_RV cnk_session_cancel_operations(CNK_PKCS11_SESSION *session, CK_FLAGS flags) {
  CNK_ENSURE_NONNULL(session);
  cnk_mutex_lock(&session->lock);

  if ((flags & CKF_FIND_OBJECTS) != 0) {
    session->findActive = CK_FALSE;
    session->findObjectsCount = 0;
    session->findObjectsPosition = 0;
  }
  if ((flags & CKF_DIGEST) != 0 && session->digestingContext.mechanismType != 0) {
    cnk_reset_digesting_context(session);
  }
  if ((flags & CKF_SIGN) != 0 && session->signingContext.hKey != 0) {
    cnk_reset_signing_context(session);
  }
  if ((flags & CKF_VERIFY) != 0 && session->verifyingContext.hKey != 0) {
    cnk_reset_verifying_context(session);
  }
  if ((flags & CKF_ENCRYPT) != 0 && session->encryptingContext.hKey != 0) {
    cnk_reset_encrypting_context(session);
  }
  if ((flags & CKF_DECRYPT) != 0 && session->decryptingContext.hKey != 0) {
    cnk_reset_decrypting_context(session);
  }

  cnk_mutex_unlock(&session->lock);
  CNK_RET_OK;
}

// Open a new session
CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify,
                    CK_SESSION_HANDLE_PTR phSession) {
  CNK_LOG_FUNC(": slotID: %lu, flags: %lu, pApplication: %p, Notify: %p, phSession: %p", slotID, flags, pApplication,
               Notify, phSession);
  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(phSession);

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
  session->slotId = slotID;
  session->flags = flags;
  session->application = pApplication;
  session->notify = Notify;
  session->isOpen = CK_TRUE;

  rv = get_or_create_token_state(slotID, &session->token);
  if (rv != CKR_OK) {
    ck_free(session);
    cnk_mutex_unlock(&session_mutex);
    return rv;
  }
  // PQC exists only behind the firmware algorithm-extension contract. Keep
  // IDs unavailable until that contract is read successfully.
  session->mldsa65Algorithm = 0;
  session->mlkem768Algorithm = 0;
  session->ed25519Algorithm = 0;
  session->x25519Algorithm = 0;
  session->rsa3072Algorithm = 0;
  session->rsa4096Algorithm = 0;
  session->secp256k1Algorithm = 0;
  session->secp521r1Algorithm = 0;
  session->sm2Algorithm = 0;
  CNK_PIV_ALGORITHM_EXTENSION_CONFIG algorithmConfig;
  if (cnk_get_piv_algorithm_extension(slotID, &algorithmConfig) == CKR_OK && algorithmConfig.enabled) {
    session->mldsa65Algorithm = algorithmConfig.mldsa65;
    session->mlkem768Algorithm = algorithmConfig.mlkem768;
    session->ed25519Algorithm = algorithmConfig.ed25519;
    session->x25519Algorithm = algorithmConfig.x25519;
    session->rsa3072Algorithm = algorithmConfig.rsa3072;
    session->rsa4096Algorithm = algorithmConfig.rsa4096;
    session->secp256k1Algorithm = algorithmConfig.secp256k1;
    session->secp521r1Algorithm = algorithmConfig.secp521r1;
    session->sm2Algorithm = algorithmConfig.sm2;
  }
  session->nextSecretKeyId = CNK_SESSION_SECRET_KEY_FIRST_ID;

  // Initialize the session mutex
  rv = cnk_mutex_create(&session->lock);
  if (rv != CKR_OK) {
    ck_free(session);
    cnk_mutex_unlock(&session_mutex);
    CNK_RETURN(rv, "Failed to create session mutex");
  }

  // Reserve token-wide session state atomically with the SO login state.
  cnk_mutex_lock(&session->token->lock);
  if (!(flags & CKF_RW_SESSION) &&
      (session->token->loginState == TOKEN_LOGIN_SO || session->token->loginState == TOKEN_LOGIN_PENDING_SO)) {
    cnk_mutex_unlock(&session->token->lock);
    cnk_mutex_destroy(&session->lock);
    ck_free(session);
    cnk_mutex_unlock(&session_mutex);
    return CKR_SESSION_READ_WRITE_SO_EXISTS;
  }
  session->token->openSessions++;
  if (!(flags & CKF_RW_SESSION))
    session->token->readOnlySessions++;
  cnk_mutex_unlock(&session->token->lock);

  // Add the session to the table only after every reservation succeeds.
  session_table[sessionIdx] = session;
  session_count++;

  // Return the session handle
  *phSession = session->handle;

  cnk_mutex_unlock(&session_mutex);

  CNK_RET_OK;
}

// Close a session
CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
  CNK_LOG_FUNC(": hSession: %lu", hSession);
  CNK_ENSURE_INITIALIZED();

  CNK_PKCS11_SESSION *session = NULL;
  CK_LONG index = -1;
  cnk_mutex_lock(&session_mutex);
  for (;;) {
    for (CK_LONG i = 0; i < session_table_size; i++) {
      if (session_table[i] != NULL && session_table[i]->handle == hSession) {
        session = session_table[i];
        index = i;
        break;
      }
    }
    if (session == NULL) {
      cnk_mutex_unlock(&session_mutex);
      CNK_RETURN(CKR_SESSION_HANDLE_INVALID, "Session not found");
    }
    if (session->activeCalls == 0)
      break;
    // Existing calls retain a reference after leaving session_mutex. Wait for
    // those calls to finish before removing and freeing the session.
    cnk_mutex_unlock(&session_mutex);
    yield_session_close();
    cnk_mutex_lock(&session_mutex);
    session = NULL;
    index = -1;
  }

  session_table[index] = NULL;
  session_count--;
  session->isOpen = CK_FALSE;
  cnk_mutex_unlock(&session_mutex);

  // Never acquire the per-session lock while holding session_mutex. This is
  // the global lock-order boundary used by object enumeration and cancellation.
  cnk_session_cancel_operations(session, ~(CK_FLAGS)0);
  cnk_mutex_lock(&session->token->lock);
  session->token->openSessions--;
  if (!(session->flags & CKF_RW_SESSION))
    session->token->readOnlySessions--;
  CK_BBOOL lastSession = session->token->openSessions == 0;
  CK_BBOOL hadPin = session->token->cbPin > 0;
  if (lastSession) {
    session->token->logoutPending = CK_TRUE;
    clear_token_auth(session->token);
  }
  cnk_mutex_unlock(&session->token->lock);
  CK_RV logoutRv = CKR_OK;
  if (lastSession && hadPin)
    logoutRv = cnk_logout_piv_pin_with_session(session->slotId);
  if (lastSession) {
    cnk_mutex_lock(&session->token->lock);
    session->token->logoutPending = CK_FALSE;
    cnk_mutex_unlock(&session->token->lock);
  }
  free_session(session);

  return logoutRv;
}

// Close all sessions for a slot
CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
  CNK_LOG_FUNC(": slotID: %lu", slotID);
  CNK_ENSURE_INITIALIZED();

  for (;;) {
    CK_SESSION_HANDLE handle = CK_INVALID_HANDLE;
    cnk_mutex_lock(&session_mutex);
    for (CK_LONG i = 0; i < session_table_size; i++) {
      if (session_table[i] != NULL && session_table[i]->slotId == slotID) {
        handle = session_table[i]->handle;
        break;
      }
    }
    cnk_mutex_unlock(&session_mutex);
    if (handle == CK_INVALID_HANDLE)
      break;
    CK_RV rv = C_CloseSession(handle);
    if (rv != CKR_OK && rv != CKR_SESSION_HANDLE_INVALID)
      return rv;
  }

  CNK_RET_OK;
}

// Get session info
CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
  CNK_LOG_FUNC(": hSession: %lu, pInfo: %p", hSession, pInfo);

  // Validate arguments
  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pInfo);

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
  pInfo->slotID = session->slotId;
  cnk_mutex_lock(&session->token->lock);
  pInfo->state = (CK_STATE)get_session_state(session);
  cnk_mutex_unlock(&session->token->lock);
  pInfo->flags = session->flags;
  pInfo->ulDeviceError = 0;

  cnk_mutex_unlock(&session_mutex);

  CNK_DEBUG("C_GetSessionInfo: slotID = %lu, state = %lu, flags = 0x%lx", pInfo->slotID, pInfo->state, pInfo->flags);

  CNK_RET_OK;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen) {
  CNK_LOG_FUNC(": hSession: %lu, pOperationState: %p, pulOperationStateLen: %p", hSession, pOperationState,
               pulOperationStateLen);
  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pOperationState);
  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pulOperationStateLen);

  CNK_RET_UNSUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen,
                          CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey) {
  CNK_LOG_FUNC(
      ": hSession: %lu, pOperationState: %p, ulOperationStateLen: %lu, hEncryptionKey: %lu, hAuthenticationKey: %lu",
      hSession, pOperationState, ulOperationStateLen, hEncryptionKey, hAuthenticationKey);

  CNK_RET_UNSUPPORTED;
}

CK_RV C_CNK_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
                  CK_BYTE_PTR pPinTries) {
  CNK_LOG_FUNC(": hSession: %lu, userType: %d, pPin: %p, ulPinLen: %lu, pPinTries: %p", hSession, userType, pPin,
               ulPinLen, pPinTries);

  // Check if the cryptoki library is initialized
  CNK_ENSURE_INITIALIZED();

  // Validate arguments
  if (pPin == NULL && ulPinLen > 0) {
    return CKR_ARGUMENTS_BAD;
  }

  // Find the session
  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CK_RV rv = CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  if (userType == CKU_CONTEXT_SPECIFIC) {
    CNK_PKCS11_MUTEX_GUARD sessionLock CNK_MUTEX_GUARD = {.mutex = &session->lock};
    CNK_ENSURE_OK(cnk_mutex_lock_guard(&sessionLock));
    cnk_mutex_lock(&session->token->lock);
    CK_BBOOL logoutPending = session->token->logoutPending;
    cnk_mutex_unlock(&session->token->lock);
    if (logoutPending)
      CNK_RETURN(CKR_OPERATION_ACTIVE, "Token logout is in progress");
    // PIN-always authentication is attached to the initialized private-key
    // operation. It deliberately does not populate the token USER PIN cache.
    if (ulPinLen > sizeof(session->signingContext.contextPin) ||
        ulPinLen > sizeof(session->decryptingContext.contextPin))
      CNK_RETURN(CKR_PIN_LEN_RANGE, "Context-specific PIN exceeds operation buffer");
    CK_BBOOL signAlways =
        session->signingContext.hKey != 0 && session->signingContext.pinPolicy == CNK_PIV_PIN_POLICY_ALWAYS;
    CK_BBOOL decryptAlways =
        session->decryptingContext.hKey != 0 && session->decryptingContext.pinPolicy == CNK_PIV_PIN_POLICY_ALWAYS;
    if (!signAlways && !decryptAlways)
      CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "No PIN-always private-key operation is active");
    if (signAlways && decryptAlways)
      CNK_RETURN(CKR_OPERATION_ACTIVE, "Context-specific login is ambiguous with two PIN-always operations");
    rv = cnk_verify_piv_pin_for_context(session->slotId, pPin, ulPinLen, pPinTries);
    if (rv == CKR_OK) {
      cnk_mutex_lock(&session->token->lock);
      if (session->token->logoutPending) {
        rv = CKR_OPERATION_ACTIVE;
      } else {
        if (signAlways) {
          session->signingContext.contextAuthenticated = CK_TRUE;
          memset(session->signingContext.contextPin, 0xFF, sizeof(session->signingContext.contextPin));
          memcpy(session->signingContext.contextPin, pPin, ulPinLen);
          session->signingContext.contextPinLen = ulPinLen;
        }
        if (decryptAlways) {
          session->decryptingContext.contextAuthenticated = CK_TRUE;
          memset(session->decryptingContext.contextPin, 0xFF, sizeof(session->decryptingContext.contextPin));
          memcpy(session->decryptingContext.contextPin, pPin, ulPinLen);
          session->decryptingContext.contextPinLen = ulPinLen;
        }
      }
      cnk_mutex_unlock(&session->token->lock);
    }
    return rv;
  } else if (userType == CKU_USER) {
    cnk_mutex_lock(&session->token->lock);
    CNK_TOKEN_LOGIN_STATE loginState = session->token->loginState;
    if (session->token->logoutPending) {
      cnk_mutex_unlock(&session->token->lock);
      CNK_RETURN(CKR_OPERATION_ACTIVE, "Token logout is in progress");
    }
    if (loginState == TOKEN_LOGIN_USER) {
      cnk_mutex_unlock(&session->token->lock);
      CNK_RETURN(CKR_USER_ALREADY_LOGGED_IN, "User already logged in");
    }
    if (loginState == TOKEN_LOGIN_SO || loginState == TOKEN_LOGIN_PENDING_SO) {
      cnk_mutex_unlock(&session->token->lock);
      CNK_RETURN(CKR_USER_ANOTHER_ALREADY_LOGGED_IN, "SO is already logged in");
    }
    if (loginState == TOKEN_LOGIN_PENDING_USER) {
      cnk_mutex_unlock(&session->token->lock);
      CNK_RETURN(CKR_OPERATION_ACTIVE, "User login is already in progress");
    }
    session->token->loginState = TOKEN_LOGIN_PENDING_USER;
    cnk_mutex_unlock(&session->token->lock);

    rv = cnk_verify_piv_pin_with_session(session->slotId, session, pPin, ulPinLen, pPinTries);
    cnk_mutex_lock(&session->token->lock);
    if (session->token->loginState == TOKEN_LOGIN_PENDING_USER)
      session->token->loginState = TOKEN_LOGIN_USER;
    if (rv != CKR_OK)
      session->token->loginState = TOKEN_LOGIN_PUBLIC;
    cnk_mutex_unlock(&session->token->lock);

    CNK_RETURN(rv, "verify_piv_pin_with_session");
  } else if (userType == CKU_SO) {
    if (!(session->flags & CKF_RW_SESSION))
      CNK_RETURN(CKR_SESSION_READ_ONLY, "SO login requires a read-write session");
    cnk_mutex_lock(&session->token->lock);
    CNK_TOKEN_LOGIN_STATE loginState = session->token->loginState;
    if (session->token->logoutPending) {
      cnk_mutex_unlock(&session->token->lock);
      CNK_RETURN(CKR_OPERATION_ACTIVE, "Token logout is in progress");
    }
    CK_ULONG readOnlySessions = session->token->readOnlySessions;
    if (readOnlySessions > 0) {
      cnk_mutex_unlock(&session->token->lock);
      CNK_RETURN(CKR_SESSION_READ_ONLY_EXISTS, "SO login is blocked by a read-only session");
    }
    if (loginState == TOKEN_LOGIN_USER || loginState == TOKEN_LOGIN_PENDING_USER) {
      cnk_mutex_unlock(&session->token->lock);
      CNK_RETURN(CKR_USER_ANOTHER_ALREADY_LOGGED_IN, "User PIN session is already logged in");
    }
    if (loginState == TOKEN_LOGIN_SO) {
      cnk_mutex_unlock(&session->token->lock);
      CNK_RETURN(CKR_USER_ALREADY_LOGGED_IN, "SO already logged in");
    }
    if (loginState == TOKEN_LOGIN_PENDING_SO) {
      cnk_mutex_unlock(&session->token->lock);
      CNK_RETURN(CKR_OPERATION_ACTIVE, "SO login is already in progress");
    }
    if (pPin == NULL || ulPinLen != sizeof(session->token->managementKey)) {
      cnk_mutex_unlock(&session->token->lock);
      CNK_RETURN(CKR_PIN_LEN_RANGE, "Invalid management key length");
    }
    session->token->loginState = TOKEN_LOGIN_PENDING_SO;
    cnk_mutex_unlock(&session->token->lock);

    rv = cnkVerifyManagementKey(session, pPin);
    if (rv != CKR_OK) {
      cnk_mutex_lock(&session->token->lock);
      if (session->token->loginState == TOKEN_LOGIN_PENDING_SO)
        session->token->loginState = TOKEN_LOGIN_PUBLIC;
      cnk_mutex_unlock(&session->token->lock);
      CNK_RETURN(rv, "cnkVerifyManagementKey");
    }

    cnk_mutex_lock(&session->token->lock);
    if (session->token->loginState == TOKEN_LOGIN_PENDING_SO) {
      memcpy(session->token->managementKey, pPin, ulPinLen);
      session->token->cbManagementKey = ulPinLen;
      session->token->loginState = TOKEN_LOGIN_SO;
    }
    cnk_mutex_unlock(&session->token->lock);

    CNK_RET_OK;
  } else {
    CNK_RETURN(CKR_USER_TYPE_INVALID, "Invalid user type");
  }
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  // just forward to our custom C_CNK_Login function without pPinTries
  return C_CNK_Login(hSession, userType, pPin, ulPinLen, NULL);
}

CK_RV C_CNK_LoginProtectedManagementKey(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pKey, CK_ULONG ulKeyLen) {
  CNK_LOG_FUNC(": hSession: %lu, pKey: %p, ulKeyLen: %lu", hSession, pKey, ulKeyLen);
  CNK_ENSURE_INITIALIZED();
  CNK_ENSURE_NONNULL(pKey);

  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (ulKeyLen != sizeof(session->token->managementKey))
    CNK_RETURN(CKR_PIN_LEN_RANGE, "Invalid management key length");

  // Reserve the token authorization transition before the card round trip.
  // Logout observes this reservation and cannot clear USER state underneath
  // verification, then leave a management key cached in PUBLIC state.
  CNK_ENSURE_OK(cnk_token_begin_protected_management_login(session));

  CK_RV rv = cnkVerifyManagementKey(session, pKey);
  rv = cnk_token_complete_protected_management_login(session, pKey, ulKeyLen, rv);
  if (rv != CKR_OK)
    CNK_RETURN(rv, "Management key verification failed or USER state changed");
  CNK_RET_OK;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
  CNK_LOG_FUNC(": hSession: %lu", hSession);

  // Check if the cryptoki library is initialized
  CNK_ENSURE_INITIALIZED();

  // Find the session
  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  cnk_mutex_lock(&session->token->lock);
  if (session->token->loginState == TOKEN_LOGIN_PENDING_USER || session->token->loginState == TOKEN_LOGIN_PENDING_SO ||
      session->token->managementLoginPending || session->token->logoutPending) {
    cnk_mutex_unlock(&session->token->lock);
    return CKR_OPERATION_ACTIVE;
  }
  CK_BBOOL hasPin = session->token->cbPin > 0;
  CK_BBOOL hasManagementKey = session->token->cbManagementKey > 0;
  session->token->logoutPending = CK_TRUE;
  cnk_mutex_unlock(&session->token->lock);
  if (!hasPin && !hasManagementKey) {
    cnk_mutex_lock(&session->token->lock);
    session->token->logoutPending = CK_FALSE;
    cnk_mutex_unlock(&session->token->lock);
    return CKR_USER_NOT_LOGGED_IN;
  }

  // Send the logout APDU only for user PIN sessions. Management-key
  // authentication is per-card transaction and has no matching logout APDU.
  CK_RV revokeRv = cnk_token_revoke_private_operations(session->token);
  if (revokeRv != CKR_OK) {
    cnk_mutex_lock(&session->token->lock);
    session->token->logoutPending = CK_FALSE;
    cnk_mutex_unlock(&session->token->lock);
    return revokeRv;
  }
  CK_RV logoutRv = hasPin ? cnk_logout_piv_pin_with_session(session->slotId) : CKR_OK;

  cnk_mutex_lock(&session->token->lock);
  clear_token_auth(session->token);
  session->token->logoutPending = CK_FALSE;
  cnk_mutex_unlock(&session->token->lock);

  return logoutRv;
}
