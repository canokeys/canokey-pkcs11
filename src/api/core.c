#include "api/session.h"
#include "backend/pcsc.h"
#include "internal/lifecycle.h"
#include "internal/logging.h"
#include "internal/macros.h"
#include "internal/mutex.h"
#include "internal/util.h"
#include "pkcs11.h"
#include "pkcs11_canokey.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sched.h>
#endif

#include <mbedtls/platform.h>
#include <nsync_malloc.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>

// Forward declaration of the function list
static CK_FUNCTION_LIST ck_function_list;
static CK_FUNCTION_LIST_3_2 ck_function_list_3_2;
static CK_UTF8CHAR ck_interface_name[] = "PKCS 11";
static CK_INTERFACE ck_interface_3_2 = {ck_interface_name, &ck_function_list_3_2, 0};

// Global variables
static atomic_int g_ref_count = 0;
static CK_BBOOL g_initialization_cleanup_pending = CK_FALSE;
static CK_BBOOL g_backend_cleanup_pending = CK_FALSE;
static atomic_flag g_lifecycle_lock = ATOMIC_FLAG_INIT;

void cnk_lifecycle_lock(void) {
  while (atomic_flag_test_and_set(&g_lifecycle_lock)) {
#ifdef _WIN32
    Sleep(0);
#else
    sched_yield();
#endif
  }
}

void cnk_lifecycle_unlock(void) { atomic_flag_clear(&g_lifecycle_lock); }

static void release_lifecycle_lock(atomic_flag **lock) {
  if (lock != NULL && *lock != NULL)
    atomic_flag_clear(*lock);
}

#if defined(__clang__) || defined(__GNUC__)
#define CNK_LIFECYCLE_GUARD __attribute__((cleanup(release_lifecycle_lock)))
#else
#error "CanoKey lifecycle serialization requires compiler cleanup support"
#endif

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
  if (!g_cnk_is_managed_mode)
    cnk_config_logging_from_env();

  CNK_LOG_FUNC(": pInitArgs: %p", pInitArgs);
  atomic_flag *lifecycleLock CNK_LIFECYCLE_GUARD = &g_lifecycle_lock;
  cnk_lifecycle_lock();

  // A failed callback during rollback can leave the PC/SC/backend objects
  // alive while Cryptoki remains uninitialized. Finish that rollback before
  // accepting a new initialization attempt.
  if (g_initialization_cleanup_pending || g_backend_cleanup_pending) {
    CK_RV cleanupRv = g_initialization_cleanup_pending ? cnk_cleanup_pcsc() : CKR_OK;
    if (cleanupRv != CKR_OK)
      return cleanupRv;
    cleanupRv = g_backend_cleanup_pending ? cnk_cleanup_backend() : CKR_OK;
    if (cleanupRv != CKR_OK)
      return cleanupRv;
    mbedtls_psa_crypto_free();
    cnk_mutex_system_cleanup();
    g_initialization_cleanup_pending = CK_FALSE;
    g_backend_cleanup_pending = CK_FALSE;
  }

  // Check if the library is already initialized
  if (g_cnk_is_initialized) {
    // Managed mode allows multiple initializations, we increment the reference count
    if (g_cnk_is_managed_mode) {
      if (atomic_fetch_add(&g_ref_count, 1) == 0) {
        CNK_RETURN(CKR_MUTEX_BAD, "g_ref_count is 0. Invalid state");
      }
      CNK_RET_OK;
    }
    CNK_RETURN(CKR_CRYPTOKI_ALREADY_INITIALIZED, "already initialized");
  }

  // Process the initialization arguments
  CK_RV mutex_rv;

  if (pInitArgs == NULL_PTR) {
    // NULL argument is treated as a pointer to a CK_C_INITIALIZE_ARGS structure
    // with all fields set to NULL (single-threaded mode)
    mutex_rv = CNK_ENSURE_OK(cnk_mutex_system_init(NULL));
  } else {
    CK_C_INITIALIZE_ARGS_PTR args = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;

    // Check for reserved field - must be NULL according to PKCS#11
    CNK_ENSURE_NULL(args->pReserved);

    // Check for invalid combinations of flags and function pointers
    CK_BBOOL can_use_os_locking = (args->flags & CKF_OS_LOCKING_OK);

    // Check if all or none of the mutex function pointers are supplied
    CK_BBOOL all_supplied = (args->CreateMutex != NULL_PTR) && (args->DestroyMutex != NULL_PTR) &&
                            (args->LockMutex != NULL_PTR) && (args->UnlockMutex != NULL_PTR);

    CK_BBOOL none_supplied = (args->CreateMutex == NULL_PTR) && (args->DestroyMutex == NULL_PTR) &&
                             (args->LockMutex == NULL_PTR) && (args->UnlockMutex == NULL_PTR);

    // check consistency
    if (!all_supplied && !none_supplied) {
      CNK_RETURN(CKR_ARGUMENTS_BAD, "invalid mutex function pointers");
    }

    // Handle the four cases as per PKCS#11 specification

    // Initialize mutex system based on the provided arguments
    if (none_supplied) {
      if (can_use_os_locking) {
        // Case 2:
        // the application will be performing multi-threaded Cryptoki access,
        // and the library needs to use the native operating system primitives
        // to ensure safe multi-threaded access
        mutex_rv = cnk_mutex_system_init(NULL); // only nsync available
      } else {
        // Case 1:
        // the application won't be accessing the Cryptoki library from multiple
        // threads simultaneously
        // Internal synchronization objects are still required for state
        // ownership and cleanup, even when the caller promises serialization.
        mutex_rv = cnk_mutex_system_init(NULL);
      }
    } else { // all_supplied
      if (can_use_os_locking) {
        // Case 4:
        // the application will be performing multi-threaded Cryptoki access,
        // and the library needs to use either the native operating system primitives
        // or the supplied function pointers for mutex-handling to ensure safe
        // multi-threaded access
        mutex_rv = cnk_mutex_system_init(NULL); // use nsync first
      } else {
        // Case 3:
        // the application will be performing multi-threaded Cryptoki access,
        // and the library needs to use the supplied function pointers for
        // mutex-handling to ensure safe multi-threaded access
        mutex_rv = cnk_mutex_system_init(args); // only UDF available
      }
    }

    if (mutex_rv != CKR_OK) {
      CNK_RETURN(CKR_CANT_LOCK, "cannot init mutex");
    }
  }

  if (psa_crypto_init() != PSA_SUCCESS) {
    cnk_mutex_system_cleanup();
    CNK_RETURN(CKR_FUNCTION_FAILED, "cannot initialize TF-PSA-Crypto");
  }

  CK_RV rv = cnk_initialize_backend();
  if (rv != CKR_OK)
    goto initialization_failed;

  if (!g_cnk_is_managed_mode) {
    // Standalone mode: Initialize the PC/SC subsystem.
    rv = cnk_initialize_pcsc();
    if (rv != CKR_OK)
      goto initialization_failed;
  }

  rv = cnk_session_manager_init();
  if (rv != CKR_OK)
    goto initialization_failed;

  // Mark the library as initialized
  g_cnk_is_initialized = CK_TRUE;

  int last_ref_count = atomic_fetch_add(&g_ref_count, 1);
  CNK_ENSURE_EQUAL_REASON(last_ref_count, 0, "library has been initialized. Invalid state");

  CNK_RET_OK;

initialization_failed:
  if (!g_cnk_is_managed_mode) {
    CK_RV pcscRv = cnk_cleanup_pcsc();
    if (pcscRv != CKR_OK) {
      g_initialization_cleanup_pending = CK_TRUE;
      return rv;
    }
  }
  CK_RV backendRv = cnk_cleanup_backend();
  if (backendRv != CKR_OK) {
    g_backend_cleanup_pending = CK_TRUE;
    mbedtls_psa_crypto_free();
    return rv;
  }
  mbedtls_psa_crypto_free();
  cnk_mutex_system_cleanup();
  return rv;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
  CNK_LOG_FUNC(": pReserved: %p", pReserved);
  atomic_flag *lifecycleLock CNK_LIFECYCLE_GUARD = &g_lifecycle_lock;
  cnk_lifecycle_lock();

  CNK_ENSURE_INITIALIZED();

  // Invalid calls must not consume a managed-mode reference.
  CNK_ENSURE_NULL(pReserved);

  if (!g_cnk_is_managed_mode && atomic_load(&g_ref_count) > 1) {
    CNK_RETURN(CKR_MUTEX_BAD, "g_ref_count > 1 in standalone mode");
  }
  if (atomic_fetch_sub(&g_ref_count, 1) > 1) {
    CNK_RETURN(CKR_OK, "library still in use");
  }

  // Stop admitting new API calls while the final session/backend teardown is
  // in progress. Calls that already hold references or card transactions are
  // drained before the PC/SC context is released.
  g_cnk_is_initialized = CK_FALSE;

  // Wake a blocking C_WaitForSlotEvent before waiting for the operation
  // counter. cnk_cleanup_pcsc performs the same cancellation later, but the
  // lifetime barrier must cancel first to avoid waiting forever.
  if (!g_cnk_is_managed_mode)
    cnk_cancel_pcsc_operations();

  CK_RV activeRv = cnk_session_wait_for_active_calls();
  if (activeRv != CKR_OK) {
    g_cnk_is_initialized = CK_TRUE;
    atomic_fetch_add(&g_ref_count, 1);
    return activeRv;
  }
  activeRv = cnk_wait_for_pcsc_operations();
  if (activeRv != CKR_OK) {
    g_cnk_is_initialized = CK_TRUE;
    atomic_fetch_add(&g_ref_count, 1);
    return activeRv;
  }

  // PC/SC cleanup must complete before backend mutexes are destroyed. A
  // failed callback leaves the initialized state intact for a later retry.
  CK_RV pcscCleanupRv = g_cnk_is_managed_mode ? CKR_OK : cnk_cleanup_pcsc();
  if (pcscCleanupRv != CKR_OK) {
    g_cnk_is_initialized = CK_TRUE;
    atomic_fetch_add(&g_ref_count, 1);
    return pcscCleanupRv;
  }

  CK_RV rv = cnk_session_manager_cleanup();
  if (rv != CKR_OK) {
    // PC/SC was already released. Re-establish the standalone context so the
    // still-initialized module remains internally coherent for a retry.
    if (!g_cnk_is_managed_mode) {
      CK_RV restoreRv = cnk_initialize_pcsc();
      if (restoreRv != CKR_OK) {
        atomic_fetch_add(&g_ref_count, 1);
        g_cnk_is_initialized = CK_TRUE;
        return restoreRv;
      }
    }
    atomic_fetch_add(&g_ref_count, 1);
    g_cnk_is_initialized = CK_TRUE;
    return rv;
  }

  // Managed mode owns no PC/SC context, but it still owns the backend mutexes.
  CK_RV backendCleanupRv = cnk_cleanup_backend();

  if (backendCleanupRv != CKR_OK) {
    // Session state is already gone, but retain the backend descriptors and
    // allocator/mode binding so C_Initialize can retry cnk_cleanup_backend.
    g_backend_cleanup_pending = CK_TRUE;
    g_cnk_is_initialized = CK_FALSE;
    return backendCleanupRv;
  }

  if (g_cnk_is_managed_mode)
    g_cnk_is_managed_mode = CK_FALSE;
  g_cnk_pcsc_context = 0;
  g_cnk_scard = 0;
  g_cnk_malloc_func = malloc;
  g_cnk_free_func = free;
  mbedtls_platform_set_calloc_free(calloc, free);
  nsync_malloc_ptr_ = malloc;
  nsync_free_ptr_ = free;
  g_cnk_is_initialized = CK_FALSE;

  mbedtls_psa_crypto_free();
  cnk_mutex_system_cleanup();

  if (pcscCleanupRv != CKR_OK)
    return pcscCleanupRv;
  return backendCleanupRv;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
  CNK_LOG_FUNC(": pInfo: %p", pInfo);

  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pInfo);

  // Fill in the CK_INFO structure
  pInfo->cryptokiVersion.major = 3;
  pInfo->cryptokiVersion.minor = 2;

  // Manufacturer ID (padded with spaces)
  memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
  const char *manufacturer = "canokeys.org";
  size_t manufacturer_len = strlen(manufacturer);
  if (manufacturer_len > sizeof(pInfo->manufacturerID)) {
    manufacturer_len = sizeof(pInfo->manufacturerID);
  }
  memcpy(pInfo->manufacturerID, manufacturer, manufacturer_len);

  // No flags
  pInfo->flags = 0;

  // Library description (padded with spaces)
  memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
  const char *description = "CanoKey PKCS#11 Library";
  size_t description_len = strlen(description);
  if (description_len > sizeof(pInfo->libraryDescription)) {
    description_len = sizeof(pInfo->libraryDescription);
  }
  memcpy(pInfo->libraryDescription, description, description_len);

  // Library version
  pInfo->libraryVersion.major = 1;
  pInfo->libraryVersion.minor = 0;

  CNK_RET_OK;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
  CNK_LOG_FUNC(": ppFunctionList: %p", ppFunctionList);
  CNK_ENSURE_NONNULL(ppFunctionList);

  *ppFunctionList = &ck_function_list;

  CNK_RET_OK;
}

CK_RV C_GetInterfaceList(CK_INTERFACE_PTR interfaces, CK_ULONG_PTR count) {
  CNK_ENSURE_NONNULL(count);
  if (interfaces == NULL) {
    *count = 1;
    return CKR_OK;
  }
  if (*count < 1) {
    *count = 1;
    return CKR_BUFFER_TOO_SMALL;
  }
  interfaces[0] = ck_interface_3_2;
  *count = 1;
  return CKR_OK;
}

CK_RV C_GetInterface(CK_UTF8CHAR_PTR interfaceName, CK_VERSION_PTR version, CK_INTERFACE_PTR_PTR ppInterface,
                     CK_FLAGS flags) {
  CNK_ENSURE_NONNULL(ppInterface);
  if (flags != 0)
    return CKR_ARGUMENTS_BAD;
  if (interfaceName != NULL && strcmp((const char *)interfaceName, (const char *)ck_interface_name) != 0)
    return CKR_ARGUMENTS_BAD;
  if (version != NULL && (version->major != 3 || version->minor != 2))
    return CKR_ARGUMENTS_BAD;
  *ppInterface = &ck_interface_3_2;
  return CKR_OK;
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession) {
  CNK_UNUSED(hSession);

  CNK_RETURN(CKR_FUNCTION_NOT_PARALLEL, "function not parallel");
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession) {
  CNK_UNUSED(hSession);

  CNK_RETURN(CKR_FUNCTION_NOT_PARALLEL, "function not parallel");
}

// Define the function list structure
static CK_FUNCTION_LIST ck_function_list = {{2, 40}, // PKCS #11 version 2.40

                                            // Function pointers
                                            C_Initialize,
                                            C_Finalize,
                                            C_GetInfo,
                                            C_GetFunctionList,
                                            C_GetSlotList,
                                            C_GetSlotInfo,
                                            C_GetTokenInfo,
                                            C_GetMechanismList,
                                            C_GetMechanismInfo,
                                            C_InitToken,
                                            C_InitPIN,
                                            C_SetPIN,
                                            C_OpenSession,
                                            C_CloseSession,
                                            C_CloseAllSessions,
                                            C_GetSessionInfo,
                                            C_GetOperationState,
                                            C_SetOperationState,
                                            C_Login,
                                            C_Logout,
                                            C_CreateObject,
                                            C_CopyObject,
                                            C_DestroyObject,
                                            C_GetObjectSize,
                                            C_GetAttributeValue,
                                            C_SetAttributeValue,
                                            C_FindObjectsInit,
                                            C_FindObjects,
                                            C_FindObjectsFinal,
                                            C_EncryptInit,
                                            C_Encrypt,
                                            C_EncryptUpdate,
                                            C_EncryptFinal,
                                            C_DecryptInit,
                                            C_Decrypt,
                                            C_DecryptUpdate,
                                            C_DecryptFinal,
                                            C_DigestInit,
                                            C_Digest,
                                            C_DigestUpdate,
                                            C_DigestKey,
                                            C_DigestFinal,
                                            C_SignInit,
                                            C_Sign,
                                            C_SignUpdate,
                                            C_SignFinal,
                                            C_SignRecoverInit,
                                            C_SignRecover,
                                            C_VerifyInit,
                                            C_Verify,
                                            C_VerifyUpdate,
                                            C_VerifyFinal,
                                            C_VerifyRecoverInit,
                                            C_VerifyRecover,
                                            C_DigestEncryptUpdate,
                                            C_DecryptDigestUpdate,
                                            C_SignEncryptUpdate,
                                            C_DecryptVerifyUpdate,
                                            C_GenerateKey,
                                            C_GenerateKeyPair,
                                            C_WrapKey,
                                            C_UnwrapKey,
                                            C_DeriveKey,
                                            C_SeedRandom,
                                            C_GenerateRandom,
                                            C_GetFunctionStatus,
                                            C_CancelFunction,
                                            C_WaitForSlotEvent};

// Generate the 3.2 table from the canonical declaration list. Unsupported
// entries still point at type-correct stubs, so clients never dereference NULL.
#define CK_PKCS11_FUNCTION_INFO(name) name,
static CK_FUNCTION_LIST_3_2 ck_function_list_3_2 = {
    {3, 2},
#include "pkcs11f.h"
};
#undef CK_PKCS11_FUNCTION_INFO
