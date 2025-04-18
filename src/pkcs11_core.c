#if defined(_WIN32)
#define CRYPTOKI_EXPORTS
#endif

#include "logging.h"
#include "pcsc_backend.h"
#include "pkcs11.h"
#include "pkcs11_canokey.h"
#include "pkcs11_macros.h"
#include "pkcs11_mutex.h"
#include "pkcs11_session.h"
#include "utils.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

// Forward declaration of the function list
static CK_FUNCTION_LIST ck_function_list;

// Global variables
static atomic_int g_ref_count = 0;

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
#ifdef CNK_VERBOSE
  // forcibly enable debug logging, can be overridden by C_CNK_ConfigLogging later
  C_CNK_ConfigLogging(CNK_LOG_LEVEL_DEBUG, NULL);
#endif

  CNK_LOG_FUNC(": pInitArgs: %p", pInitArgs);

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
        mutex_rv = CKR_OK; // no need to do anything
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

  if (!g_cnk_is_managed_mode) {
    // Standalone mode: Initialize the PC/SC subsystem
    CNK_ENSURE_OK(cnk_initialize_pcsc());
  }

  cnk_initialize_backend();

  // Initialize the session manager
  CNK_ENSURE_OK(cnk_session_manager_init());

  // Mark the library as initialized
  g_cnk_is_initialized = CK_TRUE;

  int last_ref_count = atomic_fetch_add(&g_ref_count, 1);
  CNK_ENSURE_EQUAL_REASON(last_ref_count, 0, "library has been initialized. Invalid state");

  CNK_RET_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
  CNK_LOG_FUNC(": pReserved: %p", pReserved);

  if (!g_cnk_is_managed_mode && atomic_load(&g_ref_count) > 1) {
    CNK_RETURN(CKR_MUTEX_BAD, "g_ref_count > 1 in standalone mode");
  }
  if (atomic_fetch_sub(&g_ref_count, 1) > 1) {
    CNK_RETURN(CKR_OK, "library still in use");
  }

  // According to PKCS#11, pReserved must be NULL_PTR
  CNK_ENSURE_NULL(pReserved);

  // Clean up session manager
  cnk_session_manager_cleanup();

  // Clean up mutex system
  cnk_mutex_system_cleanup();

  // In managed mode, we don't clean up PC/SC resources
  if (g_cnk_is_managed_mode) {
    // Reset managed mode variables
    g_cnk_is_managed_mode = CK_FALSE;
    g_cnk_scard = 0;
    g_cnk_is_initialized = CK_FALSE;
    CNK_RET_OK;
  }

  // Clean up PC/SC resources in standalone mode
  cnk_cleanup_pcsc();
  g_cnk_is_initialized = CK_FALSE;

  CNK_RET_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
  CNK_LOG_FUNC(": pInfo: %p", pInfo);

  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pInfo);

  // Fill in the CK_INFO structure
  // Cryptoki version (PKCS#11 v2.40)
  pInfo->cryptokiVersion.major = 2;
  pInfo->cryptokiVersion.minor = 40;

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
