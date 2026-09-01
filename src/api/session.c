#include "api/session.h"

#include "backend/pcsc.h"
#include "internal/logging.h"
#include "internal/macros.h"
#include "internal/util.h"

#include <mbedtls/platform_util.h>
#include <string.h>

// Session table and related variables
static CNK_PKCS11_SESSION **session_table = NULL;
static CK_LONG session_table_size = 0;
static CK_LONG session_count = 0;
static CK_SESSION_HANDLE next_handle = 1; // Start from 1, 0 is invalid
static CNK_PKCS11_MUTEX session_mutex;
static CNK_PKCS11_SESSION *retired_sessions = NULL;
static CNK_PKCS11_TOKEN_STATE *token_states = NULL;

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

  ck_free(session->signingContext.mechanism.pParameter);
  if (session->signingContext.message != NULL) {
    mbedtls_platform_zeroize(session->signingContext.message, session->signingContext.messageCapacity);
    ck_free(session->signingContext.message);
  }
  ck_free(session->decryptingContext.mechanism.pParameter);
  for (CK_ULONG i = 0; i < MAX_SESSION_SECRET_KEYS; i++) {
    if (session->secretKeys[i].active)
      mbedtls_platform_zeroize(session->secretKeys[i].value, sizeof(session->secretKeys[i].value));
  }
  cnk_mutex_destroy(&session->lock);
  mbedtls_platform_zeroize(session, sizeof(*session));
  ck_free(session);
}

static void clear_token_auth(CNK_PKCS11_TOKEN_STATE *token) {
  memset(token->pin, 0xFF, sizeof(token->pin));
  token->cbPin = 0;
  mbedtls_platform_zeroize(token->managementKey, sizeof(token->managementKey));
  token->cbManagementKey = 0;
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

  while (retired_sessions != NULL) {
    CNK_PKCS11_SESSION *session = retired_sessions;
    retired_sessions = session->retiredNext;
    free_session(session);
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

CK_BBOOL cnk_token_pin_is_cached(CNK_PKCS11_SESSION *session) {
  CK_BBOOL result;
  cnk_mutex_lock(&session->token->lock);
  result = session->token->loginState == TOKEN_LOGIN_USER && session->token->cbPin > 0;
  cnk_mutex_unlock(&session->token->lock);
  return result;
}

CK_RV cnk_token_copy_pin(CNK_PKCS11_SESSION *session, CK_BYTE pin[8], CK_ULONG_PTR pinLen) {
  CNK_ENSURE_NONNULL(session, pin, pinLen);
  cnk_mutex_lock(&session->token->lock);
  if (session->token->loginState != TOKEN_LOGIN_USER || session->token->cbPin == 0) {
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
  result = session->token->cbManagementKey == sizeof(session->token->managementKey);
  cnk_mutex_unlock(&session->token->lock);
  return result;
}

CK_RV cnk_token_copy_management_key(CNK_PKCS11_SESSION *session, CK_BYTE key[24]) {
  CNK_ENSURE_NONNULL(session, key);
  cnk_mutex_lock(&session->token->lock);
  if (session->token->cbManagementKey != sizeof(session->token->managementKey)) {
    cnk_mutex_unlock(&session->token->lock);
    return CKR_USER_NOT_LOGGED_IN;
  }
  memcpy(key, session->token->managementKey, sizeof(session->token->managementKey));
  cnk_mutex_unlock(&session->token->lock);
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
    mbedtls_md_free(&session->digestingContext.context);
    memset(&session->digestingContext, 0, sizeof(session->digestingContext));
  }
  if ((flags & CKF_SIGN) != 0 && session->signingContext.hKey != 0) {
    ck_free(session->signingContext.mechanism.pParameter);
    if (session->signingContext.message != NULL) {
      mbedtls_platform_zeroize(session->signingContext.message, session->signingContext.messageCapacity);
      ck_free(session->signingContext.message);
    }
    memset(&session->signingContext, 0, sizeof(session->signingContext));
  }
  if ((flags & CKF_DECRYPT) != 0 && session->decryptingContext.hKey != 0) {
    ck_free(session->decryptingContext.mechanism.pParameter);
    memset(&session->decryptingContext, 0, sizeof(session->decryptingContext));
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
  cnk_mutex_lock(&session->token->lock);
  CK_BBOOL soLoggedIn = session->token->loginState == TOKEN_LOGIN_SO;
  cnk_mutex_unlock(&session->token->lock);
  if (!(flags & CKF_RW_SESSION) && soLoggedIn) {
    ck_free(session);
    cnk_mutex_unlock(&session_mutex);
    return CKR_SESSION_READ_WRITE_SO_EXISTS;
  }
  session->mldsa65Algorithm = PIV_ALG_MLDSA65;
  session->mlkem768Algorithm = PIV_ALG_MLKEM768;
  CNK_PIV_ALGORITHM_EXTENSION_CONFIG algorithmConfig;
  if (cnk_get_piv_algorithm_extension(slotID, &algorithmConfig) == CKR_OK && algorithmConfig.enabled) {
    session->mldsa65Algorithm = algorithmConfig.mldsa65;
    session->mlkem768Algorithm = algorithmConfig.mlkem768;
  }
  session->nextSecretKeyId = CNK_SESSION_SECRET_KEY_FIRST_ID;

  // Initialize the session mutex
  rv = cnk_mutex_create(&session->lock);
  if (rv != CKR_OK) {
    ck_free(session);
    cnk_mutex_unlock(&session_mutex);
    CNK_RETURN(rv, "Failed to create session mutex");
  }

  // Add the session to the table
  session_table[sessionIdx] = session;
  session_count++;
  cnk_mutex_lock(&session->token->lock);
  session->token->openSessions++;
  if (!(flags & CKF_RW_SESSION))
    session->token->readOnlySessions++;
  cnk_mutex_unlock(&session->token->lock);

  // Return the session handle
  *phSession = session->handle;

  cnk_mutex_unlock(&session_mutex);

  CNK_RET_OK;
}

// Close a session
CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
  CNK_LOG_FUNC(": hSession: %lu", hSession);
  CNK_ENSURE_INITIALIZED();

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

  CNK_PKCS11_SESSION *session = session_table[index];
  session_table[index] = NULL;
  session_count--;
  session->isOpen = CK_FALSE;
  cnk_mutex_lock(&session->token->lock);
  session->token->openSessions--;
  if (!(session->flags & CKF_RW_SESSION))
    session->token->readOnlySessions--;
  CK_BBOOL lastSession = session->token->openSessions == 0;
  CK_BBOOL hadPin = session->token->cbPin > 0;
  if (lastSession)
    clear_token_auth(session->token);
  cnk_mutex_unlock(&session->token->lock);
  if (lastSession && hadPin)
    cnk_logout_piv_pin_with_session(session->slotId);
  session->retiredNext = retired_sessions;
  retired_sessions = session;

  cnk_mutex_unlock(&session_mutex);

  CNK_RET_OK;
}

// Close all sessions for a slot
CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
  CNK_LOG_FUNC(": slotID: %lu", slotID);
  CNK_ENSURE_INITIALIZED();

  cnk_mutex_lock(&session_mutex);

  // Close all sessions for this slot
  for (CK_LONG i = 0; i < session_table_size; i++) {
    if (session_table[i] != NULL && session_table[i]->slotId == slotID) {
      CNK_PKCS11_SESSION *session = session_table[i];
      session_table[i] = NULL;
      session_count--;
      session->isOpen = CK_FALSE;
      cnk_mutex_lock(&session->token->lock);
      session->token->openSessions--;
      if (!(session->flags & CKF_RW_SESSION))
        session->token->readOnlySessions--;
      cnk_mutex_unlock(&session->token->lock);
      session->retiredNext = retired_sessions;
      retired_sessions = session;
    }
  }

  CNK_PKCS11_TOKEN_STATE *token = find_token_state(slotID);
  if (token != NULL) {
    cnk_mutex_lock(&token->lock);
    CK_BBOOL hadPin = token->cbPin > 0;
    clear_token_auth(token);
    cnk_mutex_unlock(&token->lock);
    if (hadPin)
      cnk_logout_piv_pin_with_session(slotID);
  }

  cnk_mutex_unlock(&session_mutex);

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
  CNK_PKCS11_SESSION *session;
  CK_RV rv = CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  if (userType == CKU_CONTEXT_SPECIFIC) {
    CK_BBOOL signAlways =
        session->signingContext.hKey != 0 && session->signingContext.pinPolicy == CNK_PIV_PIN_POLICY_ALWAYS;
    CK_BBOOL decryptAlways =
        session->decryptingContext.hKey != 0 && session->decryptingContext.pinPolicy == CNK_PIV_PIN_POLICY_ALWAYS;
    if (!signAlways && !decryptAlways)
      CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "No PIN-always private-key operation is active");
    rv = cnk_verify_piv_pin_for_context(session->slotId, pPin, ulPinLen, pPinTries);
    if (rv == CKR_OK) {
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
    return rv;
  } else if (userType == CKU_USER) {
    cnk_mutex_lock(&session->token->lock);
    CNK_TOKEN_LOGIN_STATE loginState = session->token->loginState;
    cnk_mutex_unlock(&session->token->lock);
    if (loginState == TOKEN_LOGIN_USER)
      CNK_RETURN(CKR_USER_ALREADY_LOGGED_IN, "User already logged in");
    if (loginState == TOKEN_LOGIN_SO)
      CNK_RETURN(CKR_USER_ANOTHER_ALREADY_LOGGED_IN, "SO is already logged in");

    rv = cnk_verify_piv_pin_with_session(session->slotId, session, pPin, ulPinLen, pPinTries);
    if (rv == CKR_OK) {
      cnk_mutex_lock(&session->token->lock);
      session->token->loginState = TOKEN_LOGIN_USER;
      cnk_mutex_unlock(&session->token->lock);
    }

    CNK_RETURN(rv, "verify_piv_pin_with_session");
  } else if (userType == CKU_SO) {
    if (!(session->flags & CKF_RW_SESSION))
      CNK_RETURN(CKR_SESSION_READ_ONLY, "SO login requires a read-write session");
    cnk_mutex_lock(&session->token->lock);
    CNK_TOKEN_LOGIN_STATE loginState = session->token->loginState;
    CK_ULONG readOnlySessions = session->token->readOnlySessions;
    cnk_mutex_unlock(&session->token->lock);
    if (readOnlySessions > 0)
      CNK_RETURN(CKR_SESSION_READ_ONLY_EXISTS, "SO login is blocked by a read-only session");
    if (loginState == TOKEN_LOGIN_USER)
      CNK_RETURN(CKR_USER_ANOTHER_ALREADY_LOGGED_IN, "User PIN session is already logged in");
    if (loginState == TOKEN_LOGIN_SO)
      CNK_RETURN(CKR_USER_ALREADY_LOGGED_IN, "SO already logged in");
    if (pPin == NULL || ulPinLen != sizeof(session->token->managementKey))
      CNK_RETURN(CKR_PIN_LEN_RANGE, "Invalid management key length");

    rv = cnkVerifyManagementKey(session, pPin);
    if (rv != CKR_OK)
      CNK_RETURN(rv, "cnkVerifyManagementKey");

    cnk_mutex_lock(&session->token->lock);
    memcpy(session->token->managementKey, pPin, ulPinLen);
    session->token->cbManagementKey = ulPinLen;
    session->token->loginState = TOKEN_LOGIN_SO;
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

  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (!cnk_token_pin_is_cached(session))
    CNK_RETURN(CKR_USER_NOT_LOGGED_IN, "User PIN login is required");
  if (cnk_token_management_key_is_cached(session))
    CNK_RETURN(CKR_USER_ALREADY_LOGGED_IN, "Protected management key is already cached");
  if (ulKeyLen != sizeof(session->token->managementKey))
    CNK_RETURN(CKR_PIN_LEN_RANGE, "Invalid management key length");

  CK_RV rv = cnkVerifyManagementKey(session, pKey);
  if (rv != CKR_OK)
    CNK_RETURN(rv, "Management key verification failed");

  cnk_mutex_lock(&session->token->lock);
  memcpy(session->token->managementKey, pKey, ulKeyLen);
  session->token->cbManagementKey = ulKeyLen;
  cnk_mutex_unlock(&session->token->lock);
  CNK_RET_OK;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
  CNK_LOG_FUNC(": hSession: %lu", hSession);

  // Check if the cryptoki library is initialized
  CNK_ENSURE_INITIALIZED();

  // Find the session
  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  cnk_mutex_lock(&session->token->lock);
  CK_BBOOL hasPin = session->token->cbPin > 0;
  CK_BBOOL hasManagementKey = session->token->cbManagementKey > 0;
  cnk_mutex_unlock(&session->token->lock);
  if (!hasPin && !hasManagementKey) {
    return CKR_USER_NOT_LOGGED_IN;
  }

  // Send the logout APDU only for user PIN sessions. Management-key
  // authentication is per-card transaction and has no matching logout APDU.
  if (hasPin)
    CNK_ENSURE_OK(cnk_logout_piv_pin_with_session(session->slotId));

  cnk_mutex_lock(&session->token->lock);
  clear_token_auth(session->token);
  cnk_mutex_unlock(&session->token->lock);

  CNK_RET_OK;
}
