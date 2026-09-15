#include "api/session.h"
#include "backend/pcsc.h"
#include "backend/piv_operation.h"
#include "internal/lifecycle.h"
#include "internal/logging.h"
#include "internal/macros.h"
#include "internal/util.h"
#include "pkcs11.h"
#include "pkcs11_canokey.h"

#include <mbedtls/platform.h>
#include <mbedtls/platform_util.h>
#include <nsync_malloc.h>
#include <psa/crypto.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sched.h>
#endif

#define CNK_ADMIN_DATA_MAX_LEN 128
#define CNK_ADMIN_PUK_BLOCKED_BIT 0x01
#define CNK_ADMIN_PIN_PROTECTED_BIT 0x02

static const CK_BYTE CNK_ADMIN_DATA_TAG[] = {0x5F, 0xFF, 0x00};

static CK_RV readAdminProtectionFlags(const CK_BYTE *data, CK_ULONG dataLen, uint32_t *flags) {
  cnk_error_v1 error = {.struct_size = sizeof(error)};
  uint32_t status = CNK_EXTERNAL_CALL(cnk_piv_admin_data_flags, data, dataLen, flags, &error);
  // Invalid protection data must not be confused with an absent policy.
  return cnk_piv_operation_status(status, &error, CKR_DEVICE_ERROR);
}

// Function pointers for memory allocation (global)
#if defined(CNK_TEST_EXPORT) && defined(_WIN32)
#define CNK_TEST_DATA_EXPORT __declspec(dllexport)
#else
#define CNK_TEST_DATA_EXPORT
#endif
CNK_TEST_DATA_EXPORT CNK_MALLOC_FUNC g_cnk_malloc_func = malloc;
CNK_TEST_DATA_EXPORT CNK_FREE_FUNC g_cnk_free_func = free;

CNK_TEST_DATA_EXPORT _Atomic CK_BBOOL g_cnk_is_managed_mode =
    CK_FALSE; // False for standalone mode, True for managed mode
CNK_TEST_DATA_EXPORT _Atomic SCARDCONTEXT g_cnk_pcsc_context = 0L;
CNK_TEST_DATA_EXPORT _Atomic SCARDHANDLE g_cnk_scard = 0L;
CNK_TEST_DATA_EXPORT _Atomic CK_ULONG g_cnk_managed_binding_epoch = 0;

void cnk_store_managed_binding(SCARDCONTEXT context, SCARDHANDLE card) {
  atomic_fetch_add(&g_cnk_managed_binding_epoch, 1);
  atomic_store(&g_cnk_pcsc_context, context);
  atomic_store(&g_cnk_scard, card);
  atomic_fetch_add(&g_cnk_managed_binding_epoch, 1);
}

void cnk_load_managed_binding(SCARDCONTEXT *context, SCARDHANDLE *card) {
  if (context == NULL || card == NULL)
    return;
  for (;;) {
    CK_ULONG before = atomic_load(&g_cnk_managed_binding_epoch);
    if ((before & 1u) != 0)
      continue;
    SCARDCONTEXT snapshotContext = atomic_load(&g_cnk_pcsc_context);
    SCARDHANDLE snapshotCard = atomic_load(&g_cnk_scard);
    CK_ULONG after = atomic_load(&g_cnk_managed_binding_epoch);
    if (before == after && (after & 1u) == 0) {
      *context = snapshotContext;
      *card = snapshotCard;
      return;
    }
#ifdef _WIN32
    Sleep(0);
#else
    sched_yield();
#endif
  }
}

CK_RV C_CNK_EnableManagedMode(CNK_MANAGED_MODE_INIT_ARGS_PTR pInitArgs) {
  CNK_LOG_FUNC(": pInitArgs: %p", pInitArgs);

  if (pInitArgs == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  // Serialize the process-wide binding transition. Without this barrier two
  // simultaneous first acquisitions can both pass validation and publish
  // different card handles/allocators.
  cnk_lifecycle_lock();

  CK_RV rv = CKR_OK;
  // A pending cleanup still owns the previous allocator and card binding.
  // Standalone callers must let C_Initialize retry that cleanup before a
  // managed binding can be installed; an existing managed binding may be
  // reaffirmed with the same handles so that retry can proceed.
  if (cnk_cleanup_is_pending() && !g_cnk_is_managed_mode) {
    rv = CKR_OPERATION_ACTIVE;
    goto done;
  }
  if (pInitArgs->malloc_func == NULL || pInitArgs->free_func == NULL || pInitArgs->hSCardCtx == 0 ||
      pInitArgs->hScard == 0) {
    rv = CKR_ARGUMENTS_BAD;
    goto done;
  }

  // An initialized standalone module owns its PC/SC context and allocator;
  // switching it to managed mode would invalidate existing allocations and
  // make Finalize skip the standalone cleanup path.
  if (g_cnk_is_initialized && !g_cnk_is_managed_mode) {
    rv = CKR_OPERATION_ACTIVE;
    goto done;
  }
  if (cnk_pcsc_operations_active() &&
      (atomic_load(&g_cnk_pcsc_context) != pInitArgs->hSCardCtx || atomic_load(&g_cnk_scard) != pInitArgs->hScard)) {
    // Do not replace process-wide handles while an admitted card operation
    // can still be using the previous binding. The caller may retry after it
    // completes.
    rv = CKR_OPERATION_ACTIVE;
    goto done;
  }

  // Windows may create several CARD_DATA instances for one physical card.
  // Their PC/SC handles and CSP allocator callbacks can differ. Keep all
  // process-wide PKCS#11 state on the DLL allocator instead of mixing blocks
  // from unrelated CARD_DATA heaps; minidriver-owned output buffers continue
  // to use the callback belonging to the CARD_DATA that returned them.

  g_cnk_is_managed_mode = CK_TRUE;
  g_cnk_malloc_func = malloc;
  g_cnk_free_func = free;
  // call mbedtls hook to use the same malloc/free functions
  mbedtls_platform_set_calloc_free(ck_calloc, ck_free);
  // tell nsync to use the same malloc/free functions
  nsync_malloc_ptr_ = malloc;
  nsync_free_ptr_ = free;
  // The current caller owns the live handle for this operation. Minidriver
  // entry points reassert this binding before using the PKCS#11 session, so a
  // CARD_DATA whose handle was deleted is never retained indefinitely.
  cnk_store_managed_binding(pInitArgs->hSCardCtx, pInitArgs->hScard);
  rv = CKR_OK;

done:
  cnk_lifecycle_unlock();
  return rv;
}

CK_RV C_CNK_ResetManagedMode(void) {
  cnk_lifecycle_lock();
  if (!g_cnk_is_managed_mode) {
    cnk_lifecycle_unlock();
    return CKR_OK;
  }
  if (g_cnk_is_initialized) {
    cnk_lifecycle_unlock();
    return CKR_OPERATION_ACTIVE;
  }
  if (cnk_cleanup_is_pending()) {
    cnk_lifecycle_unlock();
    return CKR_OPERATION_ACTIVE;
  }
  g_cnk_is_managed_mode = CK_FALSE;
  cnk_store_managed_binding(0, 0);
  g_cnk_malloc_func = malloc;
  g_cnk_free_func = free;
  mbedtls_platform_set_calloc_free(calloc, free);
  nsync_malloc_ptr_ = malloc;
  nsync_free_ptr_ = free;
  cnk_lifecycle_unlock();
  return CKR_OK;
}

CK_RV C_CNK_ConfigLogging(int level, FILE *file, CK_BBOOL unsafe_log_apdu) {
  return cnk_config_logging(level, file, unsafe_log_apdu);
}

CK_RV C_CNK_GetPivData(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pTag, CK_ULONG ulTagLen, CK_BYTE_PTR pValue,
                       CK_ULONG_PTR pulValueLen) {
  CNK_LOG_FUNC(": hSession: %lu, pTag: %p, ulTagLen: %lu, pValue: %p, pulValueLen: %p", hSession, pTag, ulTagLen,
               pValue, pulValueLen);
  CNK_ENSURE_INITIALIZED();
  CNK_ENSURE_NONNULL(pTag, pulValueLen);
  if (ulTagLen == 0 || ulTagLen > 4)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "Invalid PIV data-object tag");

  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  return cnk_get_piv_data_by_tag_with_session(session->slotId, session, pTag, ulTagLen, pValue, pulValueLen, CK_TRUE);
}

CK_RV C_CNK_GetPivMetadataDirectory(CK_SESSION_HANDLE hSession, CNK_PIV_METADATA_DIRECTORY_ENTRY *entries,
                                    CK_ULONG_PTR entryCount) {
  CNK_LOG_FUNC(": hSession: %lu, entries: %p, entryCount: %p", hSession, entries, entryCount);
  CNK_ENSURE_INITIALIZED();
  CNK_ENSURE_NONNULL(entryCount);
  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  return cnk_get_piv_metadata_directory_cached(session, entries, entryCount);
}

static CK_RV loginPinManaged(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_BBOOL finalize) {
  CNK_ENSURE_INITIALIZED();
  CNK_ENSURE_NONNULL(pPin);
  if (ulPinLen < 1 || ulPinLen > 8)
    return CKR_PIN_LEN_RANGE;
  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (finalize && !(session->flags & CKF_RW_SESSION))
    return CKR_SESSION_READ_ONLY;
  CNK_ENSURE_OK(cnk_token_begin_card_operation(session));
  CK_BBOOL establishedUserLogin = CK_FALSE, pending = CK_FALSE;
  CK_BYTE entropy[8] = {0}, key[24] = {0};
  cnk_operation_t *operation = NULL;
  cnk_error_v1 error = {.struct_size = sizeof(error)};
  SCARDHANDLE card = 0;
  CK_RV rv = cnk_token_allow_owner_login(session, CK_TRUE);
  if (rv != CKR_OK)
    goto cleanup;
  rv = C_CNK_Login(hSession, CKU_USER, pPin, ulPinLen, NULL);
  establishedUserLogin = rv == CKR_OK;
  if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
    goto cleanup;
  rv = cnk_token_begin_protected_management_login(session, CK_TRUE);
  if (rv != CKR_OK)
    goto cleanup;
  pending = CK_TRUE;
  if (finalize && psa_generate_random(entropy, sizeof(entropy)) != PSA_SUCCESS) {
    rv = CKR_RANDOM_NO_RNG;
    goto cleanup;
  }
  rv = cnk_ensure_libcanokey_profile(session);
  if (rv != CKR_OK)
    goto cleanup;
  rv = CNK_PIV_CREATE(session, cnk_piv_pin_managed_new, &operation, &error, finalize ? entropy : NULL,
                      finalize ? sizeof(entropy) : 0, NULL);
  if (rv != CKR_OK)
    goto cleanup;
  rv = cnk_connect_for_private_key_operation(session->slotId, session, CNK_PIV_PIN_POLICY_ONCE, NULL, 0, &card,
                                             "PIN-managed login");
  if (rv == CKR_OK)
    rv = cnk_run_piv_operation(card, operation, CKR_DATA_INVALID, NULL);
  if (rv != CKR_OK) {
    if (CNK_EXTERNAL_CALL(cnk_operation_error, operation, &error) == CNK_OK && error.kind == CNK_ERROR_CONDITIONS)
      rv = CKR_ACTION_PROHIBITED;
    goto cleanup;
  }
  size_t keyLen = sizeof(key);
  if (CNK_EXTERNAL_CALL(cnk_operation_result_copy_bytes, operation, key, &keyLen) != CNK_OK || keyLen != sizeof(key))
    rv = CKR_DEVICE_ERROR;
cleanup:
  if (pending)
    rv = cnk_token_complete_protected_management_login(session, key, sizeof(key), rv);
  if (operation)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  if (card)
    cnk_disconnect_card(card);
  mbedtls_platform_zeroize(entropy, sizeof(entropy));
  mbedtls_platform_zeroize(key, sizeof(key));
  cnk_token_end_management_operation(session);
  if (rv != CKR_OK && establishedUserLogin) {
    CK_RV logoutRv = C_Logout(hSession);
    if (logoutRv != CKR_OK && logoutRv != CKR_USER_NOT_LOGGED_IN)
      CNK_WARN("PIN-managed USER rollback failed: 0x%lx", logoutRv);
  }
  return rv;
}

CK_RV C_CNK_LoginPinManaged(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  return loginPinManaged(hSession, pPin, ulPinLen, CK_FALSE);
}
CK_RV C_CNK_FinalizePinManaged(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  return loginPinManaged(hSession, pPin, ulPinLen, CK_TRUE);
}

CK_RV C_CNK_SetPIN(CK_SESSION_HANDLE hSession, CK_BYTE pinType, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen,
                   CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen, CK_BYTE_PTR pPinTries) {
  CNK_LOG_FUNC(": hSession: %lu, pinType: 0x%02x, pOldPin: %p, ulOldLen: %lu, pNewPin: %p, ulNewLen: %lu, "
               "pPinTries: %p",
               hSession, pinType, pOldPin, ulOldLen, pNewPin, ulNewLen, pPinTries);

  CNK_ENSURE_INITIALIZED();
  CNK_ENSURE_NONNULL(pOldPin, pNewPin);

  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (!(session->flags & CKF_RW_SESSION))
    CNK_RETURN(CKR_SESSION_READ_ONLY, "write session is required");

  CK_RV beginRv =
      pinType == CNK_PIV_PIN_TYPE_PIN ? cnk_token_begin_pin_change(session) : cnk_token_begin_card_operation(session);
  if (beginRv != CKR_OK)
    return beginRv;
  CK_RV rv = cnk_change_piv_secret_with_session(session->slotId, session, pinType, pOldPin, ulOldLen, pNewPin, ulNewLen,
                                                pPinTries);
  cnk_token_end_management_operation(session);
  return rv;
}

CK_RV C_CNK_UnblockPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPuk, CK_ULONG ulPukLen, CK_UTF8CHAR_PTR pNewPin,
                       CK_ULONG ulNewPinLen, CK_BYTE_PTR pPinTries) {
  CNK_LOG_FUNC(": hSession: %lu, pPuk: %p, ulPukLen: %lu, pNewPin: %p, ulNewPinLen: %lu, pPinTries: %p", hSession, pPuk,
               ulPukLen, pNewPin, ulNewPinLen, pPinTries);

  CNK_ENSURE_INITIALIZED();
  CNK_ENSURE_NONNULL(pPuk, pNewPin);

  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (!(session->flags & CKF_RW_SESSION))
    CNK_RETURN(CKR_SESSION_READ_ONLY, "write session is required");
  if (ulPukLen < 1 || ulPukLen > 8 || ulNewPinLen < 1 || ulNewPinLen > 8)
    return CKR_PIN_LEN_RANGE;

  CK_RV beginRv = cnk_token_begin_card_operation(session);
  if (beginRv != CKR_OK)
    return beginRv;

  SCARDHANDLE card = 0;
  CK_RV rv = cnk_ensure_libcanokey_profile(session);
  if (rv == CKR_OK)
    rv = cnk_begin_piv_transaction(session->slotId, &card);
  if (rv != CKR_OK)
    goto cleanup;

  // Refuse the PUK path once protected management-key recovery is configured.
  // Otherwise the PUK could set a known user PIN and immediately elevate to SO.
  // Keep the policy read and mutation in one transaction so another process
  // cannot provision protection between the check and Reset Retry Counter.
  CK_BYTE adminData[CNK_ADMIN_DATA_MAX_LEN];
  CK_ULONG adminDataLen = sizeof(adminData);
  CK_RV policyRv = cnk_get_public_piv_data_on_card(session, card, CNK_ADMIN_DATA_TAG, sizeof(CNK_ADMIN_DATA_TAG),
                                                   adminData, &adminDataLen);
  uint32_t protectionFlags = 0;
  if (policyRv == CKR_OK)
    policyRv = readAdminProtectionFlags(adminData, adminDataLen, &protectionFlags);
  mbedtls_platform_zeroize(adminData, sizeof(adminData));
  // The stored-key flag is enough to forbid PUK recovery. A missing/false
  // PUK-blocked claim must not turn protected key retrieval into a bypass.
  if (policyRv == CKR_OK && (protectionFlags & CNK_ADMIN_PIN_PROTECTED_BIT)) {
    rv = CKR_ACTION_PROHIBITED;
    CNK_DEBUG("PUK reset is disabled for PIN-managed management keys");
    goto cleanup;
  }
  if (policyRv != CKR_OK && policyRv != CKR_DATA_INVALID) {
    rv = policyRv;
    goto cleanup;
  }

  rv = cnk_unblock_piv_pin_on_card(session, card, pPuk, ulPukLen, pNewPin, ulNewPinLen, pPinTries);
cleanup:
  if (card)
    cnk_disconnect_card(card);
  cnk_token_end_management_operation(session);
  return rv;
}

static CK_BBOOL regularPivSlot(CK_BYTE slot) {
  return (slot >= 0x82 && slot <= 0x95) || slot == 0x9a || slot == 0x9c || slot == 0x9d || slot == 0x9e;
}

CK_RV C_CNK_Attest(CK_SESSION_HANDLE hSession, CK_BYTE pivSlot, CK_BYTE_PTR certificate, CK_ULONG_PTR certificateLen) {
  CNK_ENSURE_INITIALIZED();
  CNK_ENSURE_NONNULL(certificateLen);
  if (!regularPivSlot(pivSlot))
    return CKR_ARGUMENTS_BAD;
  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  CNK_ENSURE_OK(cnk_ensure_libcanokey_profile(session));
  cnk_operation_t *operation = NULL;
  cnk_error_v1 error = {.struct_size = sizeof(error)};
  CK_RV rv = CNK_PIV_CREATE(session, cnk_piv_attest_new, &operation, &error, pivSlot);
  if (rv != CKR_OK)
    return rv;
  SCARDHANDLE card = 0;
  rv = cnk_begin_piv_transaction(session->slotId, &card);
  if (rv == CKR_OK)
    rv = cnk_run_piv_operation(card, operation, CKR_KEY_HANDLE_INVALID, NULL);
  if (rv == CKR_OK) {
    size_t length = 0;
    uint32_t status = CNK_EXTERNAL_CALL(cnk_operation_result_copy_bytes, operation, NULL, &length);
    if (status == CNK_OK) {
      CK_ULONG capacity = *certificateLen;
      *certificateLen = (CK_ULONG)length;
      if (certificate && capacity < length)
        rv = CKR_BUFFER_TOO_SMALL;
      else if (certificate)
        status = CNK_EXTERNAL_CALL(cnk_operation_result_copy_bytes, operation, certificate, &length);
    }
    if (rv == CKR_OK)
      rv = cnk_piv_operation_status(status, NULL, CKR_DEVICE_ERROR);
  }
  CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  if (card)
    cnk_disconnect_card(card);
  return rv;
}

CK_RV C_CNK_MoveKey(CK_SESSION_HANDLE hSession, CK_BYTE source, CK_BYTE target) {
  CNK_ENSURE_INITIALIZED();
  if (!regularPivSlot(source) || (target != 0xff && !regularPivSlot(target)) || source == target)
    return CKR_ARGUMENTS_BAD;
  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (!(session->flags & CKF_RW_SESSION))
    return CKR_SESSION_READ_ONLY;
  CNK_ENSURE_OK(cnk_token_begin_management_operation(session));
  cnk_operation_t *operation = NULL;
  cnk_error_v1 error = {.struct_size = sizeof(error)};
  SCARDHANDLE card = 0;
  CK_BBOOL attempted = CK_FALSE;
  CK_RV rv = cnk_ensure_libcanokey_profile(session);
  if (rv == CKR_OK)
    rv = target == 0xff ? CNK_PIV_CREATE(session, cnk_piv_delete_key_new, &operation, &error, source, NULL)
                        : CNK_PIV_CREATE(session, cnk_piv_move_key_new, &operation, &error, source, target, NULL);
  if (rv == CKR_OK)
    rv = cnk_authenticate_admin_for_write(session->slotId, session, &card);
  if (rv == CKR_OK) {
    cnk_piv_public_cache_invalidate(session);
    rv = cnk_run_piv_operation(card, operation, CKR_KEY_HANDLE_INVALID, &attempted);
    cnk_piv_public_cache_invalidate(session);
  }
  if (operation)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  if (card)
    cnk_disconnect_card(card);
  if (attempted) {
    CK_RV revokeRv = cnk_token_revoke_private_operations(session->token);
    if (revokeRv != CKR_OK) {
      // Do not release stale initialized operations after a failed callback.
      cnk_token_forget_credentials(session);
      if (rv == CKR_OK)
        rv = revokeRv;
    }
  }
  cnk_token_end_management_operation(session);
  return rv;
}

// Shared lifetime for credential mutations: authorization and optional PIN stay
// in this transaction; local credentials are revoked after any attempted command.
static CK_RV changeManagementCredential(CNK_PKCS11_SESSION *session, cnk_operation_t *operation, const CK_BYTE *pin,
                                        CK_ULONG pinLen, CK_BBOOL resetting) {
  SCARDHANDLE card = 0;
  CK_BBOOL attempted = CK_FALSE;
  CK_RV rv = cnk_authenticate_admin_for_write(session->slotId, session, &card);
  if (rv != CKR_OK)
    return rv;
  if (pinLen)
    rv = cnk_piv_credential_on_card(session, card, CNK_PIV_CREDENTIAL_VERIFY_PIN, pin, pinLen, NULL, 0, NULL);
  if (rv == CKR_OK && resetting) {
    CK_BYTE admin[CNK_ADMIN_DATA_MAX_LEN];
    cnk_operation_t *read = NULL;
    cnk_error_v1 error = {.struct_size = sizeof(error)};
    rv = CNK_PIV_CREATE(session, cnk_piv_read_object_container_new, &read, &error, CNK_ADMIN_DATA_TAG,
                        sizeof(CNK_ADMIN_DATA_TAG));
    if (rv == CKR_OK)
      rv = cnk_run_piv_operation(card, read, CKR_DATA_INVALID, NULL);
    if (rv == CKR_OK) {
      size_t length = sizeof(admin);
      rv = cnk_piv_operation_status(CNK_EXTERNAL_CALL(cnk_operation_result_copy_bytes, read, admin, &length), NULL,
                                    CKR_DEVICE_ERROR);
      uint32_t flags = 0;
      if (rv == CKR_OK)
        rv = readAdminProtectionFlags(admin, (CK_ULONG)length, &flags);
      if (rv == CKR_OK && (flags & CNK_ADMIN_PIN_PROTECTED_BIT))
        rv = CKR_ACTION_PROHIBITED;
    }
    if (read)
      CNK_EXTERNAL_VOID(cnk_operation_free, read);
    mbedtls_platform_zeroize(admin, sizeof(admin));
  }
  if (rv == CKR_OK) {
    cnk_piv_public_cache_invalidate(session);
    rv = cnk_run_piv_operation(card, operation, CKR_DEVICE_ERROR, &attempted);
  }
  if (attempted)
    atomic_store(&session->token->logoutPending, CK_TRUE);
  cnk_disconnect_card(card);
  if (attempted) {
    CK_RV revokeRv = cnk_token_forget_credentials(session);
    if (rv == CKR_OK)
      rv = revokeRv;
  }
  return rv;
}

CK_RV C_CNK_SetManagementKey(CK_SESSION_HANDLE hSession, CK_ULONG algorithm, CK_BYTE_PTR key, CK_ULONG keyLen,
                             CK_BBOOL touch) {
  CNK_ENSURE_INITIALIZED();
  if (!key || keyLen != 24 || (algorithm != 1 && algorithm != 2) || touch > CK_TRUE)
    return CKR_ARGUMENTS_BAD;
  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (!(session->flags & CKF_RW_SESSION))
    return CKR_SESSION_READ_ONLY;
  CNK_ENSURE_OK(cnk_token_begin_management_operation(session));
  cnk_operation_t *operation = NULL;
  cnk_error_v1 error = {.struct_size = sizeof(error)};
  CK_BYTE pin[8] = {0};
  CK_ULONG pinLen = 0;
  CK_RV rv = cnk_ensure_libcanokey_profile(session);
  if (rv == CKR_OK) {
    rv = cnk_token_copy_pin(session, pin, &pinLen);
    if (rv == CKR_USER_NOT_LOGGED_IN)
      rv = CKR_OK;
  }
  if (rv == CKR_OK)
    rv = CNK_PIV_CREATE(session, cnk_piv_set_management_key_new, &operation, &error, algorithm, key, keyLen, touch, 1,
                        NULL);
  if (rv == CKR_OK)
    rv = changeManagementCredential(session, operation, pin, pinLen, CK_FALSE);
  if (operation)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  mbedtls_platform_zeroize(pin, sizeof(pin));
  cnk_token_end_management_operation(session);
  return rv;
}

CK_RV C_CNK_SetPinRetries(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pin, CK_ULONG pinLen, CK_BYTE pinRetries,
                          CK_BYTE pukRetries) {
  CNK_ENSURE_INITIALIZED();
  if (!pin || pinLen < 1 || pinLen > 8 || pinRetries < 1 || pinRetries > 15 || pukRetries < 1 || pukRetries > 15)
    return CKR_ARGUMENTS_BAD;
  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (!(session->flags & CKF_RW_SESSION))
    return CKR_SESSION_READ_ONLY;
  CNK_ENSURE_OK(cnk_token_begin_management_operation(session));
  cnk_operation_t *operation = NULL;
  cnk_error_v1 error = {.struct_size = sizeof(error)};
  CK_RV rv = cnk_ensure_libcanokey_profile(session);
  if (rv == CKR_OK)
    rv = CNK_PIV_CREATE(session, cnk_piv_reset_pin_puk_retries_new, &operation, &error, pinRetries, pukRetries, NULL);
  if (rv == CKR_OK)
    rv = changeManagementCredential(session, operation, pin, pinLen, CK_TRUE);
  if (operation)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  cnk_token_end_management_operation(session);
  return rv;
}
