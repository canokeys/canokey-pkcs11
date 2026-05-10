#include "api/session.h"
#include "backend/pcsc.h"
#include "internal/logging.h"
#include "internal/macros.h"
#include "internal/util.h"
#include "pkcs11.h"
#include "pkcs11_canokey.h"

#include <mbedtls/platform.h>
#include <nsync_malloc.h>
#include <stdlib.h>

// Function pointers for memory allocation (global)
CNK_MALLOC_FUNC g_cnk_malloc_func = malloc;
CNK_FREE_FUNC g_cnk_free_func = free;

CK_BBOOL g_cnk_is_managed_mode = CK_FALSE; // False for standalone mode, True for managed mode
SCARDCONTEXT g_cnk_pcsc_context = 0L;
SCARDHANDLE g_cnk_scard = 0L;

CK_RV C_CNK_EnableManagedMode(CNK_MANAGED_MODE_INIT_ARGS_PTR pInitArgs) {
  CNK_LOG_FUNC(": pInitArgs: %p", pInitArgs);

  // Check if initialization arguments are provided
  if (pInitArgs != NULL_PTR) {
    if (pInitArgs->malloc_func == NULL || pInitArgs->free_func == NULL || pInitArgs->hSCardCtx == 0 ||
        pInitArgs->hScard == 0) {
      return CKR_ARGUMENTS_BAD;
    }

    g_cnk_is_managed_mode = CK_TRUE;
    g_cnk_malloc_func = pInitArgs->malloc_func;
    g_cnk_free_func = pInitArgs->free_func;
    // call mbedtls hook to use the same malloc/free functions
    mbedtls_platform_set_calloc_free(ck_calloc, ck_free);
    // tell nsync to use the same malloc/free functions
    nsync_malloc_ptr_ = g_cnk_malloc_func;
    nsync_free_ptr_ = g_cnk_free_func;
    g_cnk_pcsc_context = pInitArgs->hSCardCtx;
    g_cnk_scard = pInitArgs->hScard;
    return CKR_OK;
  }

  return CKR_ARGUMENTS_BAD;
}

CK_RV C_CNK_ConfigLogging(int level, FILE *file, CK_BBOOL unsafe_log_apdu) {
  return cnk_config_logging(level, file, unsafe_log_apdu);
}

CK_RV C_CNK_SetPIN(CK_SESSION_HANDLE hSession, CK_BYTE pinType, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen,
                   CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen, CK_BYTE_PTR pPinTries) {
  CNK_LOG_FUNC(": hSession: %lu, pinType: 0x%02x, pOldPin: %p, ulOldLen: %lu, pNewPin: %p, ulNewLen: %lu, "
               "pPinTries: %p",
               hSession, pinType, pOldPin, ulOldLen, pNewPin, ulNewLen, pPinTries);

  CNK_ENSURE_INITIALIZED();
  CNK_ENSURE_NONNULL(pOldPin, pNewPin);

  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (!(session->flags & CKF_RW_SESSION))
    CNK_RETURN(CKR_SESSION_READ_ONLY, "write session is required");

  return cnk_change_piv_secret_with_session(session->slotId, session, pinType, pOldPin, ulOldLen, pNewPin, ulNewLen,
                                            pPinTries);
}

CK_RV C_CNK_UnblockPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPuk, CK_ULONG ulPukLen, CK_UTF8CHAR_PTR pNewPin,
                       CK_ULONG ulNewPinLen, CK_BYTE_PTR pPinTries) {
  CNK_LOG_FUNC(": hSession: %lu, pPuk: %p, ulPukLen: %lu, pNewPin: %p, ulNewPinLen: %lu, pPinTries: %p", hSession, pPuk,
               ulPukLen, pNewPin, ulNewPinLen, pPinTries);

  CNK_ENSURE_INITIALIZED();
  CNK_ENSURE_NONNULL(pPuk, pNewPin);

  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (!(session->flags & CKF_RW_SESSION))
    CNK_RETURN(CKR_SESSION_READ_ONLY, "write session is required");

  return cnk_unblock_piv_pin_with_session(session->slotId, session, pPuk, ulPukLen, pNewPin, ulNewPinLen, pPinTries);
}
