#define CRYPTOKI_EXPORTS

#include "logging.h"
#include "pcsc_backend.h"
#include "pkcs11.h"
#include "pkcs11_canokey.h"
#include "pkcs11_macros.h"
#include "pkcs11_mutex.h"
#include "pkcs11_obj.h"
#include "pkcs11_session.h"
#include "rsa_utils.h"

#include <stdio.h>
#include <string.h>

#include <nsync_mu.h>

// Forward declaration of the function list
static CK_FUNCTION_LIST ck_function_list;

// Global variables
static int g_ref_count = 0;
static nsync_mu g_ref_lock = NSYNC_MU_INIT;

// Helper function to check basic library and session state
static CK_RV validate_session(CK_SESSION_HANDLE hSession, CNK_PKCS11_SESSION **session) {
  // Check if the library is initialized
  if (!g_cnk_is_initialized)
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  // Find the session
  return cnk_session_find(hSession, session);
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
#ifdef CNK_VERBOSE
  // forcibly enable debug logging, can be overridden by C_CNK_ConfigLogging later
  C_CNK_ConfigLogging(CNK_LOG_LEVEL_DEBUG, NULL);
#endif

  CNK_LOG_FUNC(C_Initialize, ", pInitArgs: %p", pInitArgs);

  // Check if the library is already initialized
  if (g_cnk_is_initialized) {
    // Managed mode allows multiple initializations, we increment the reference count
    if (g_cnk_is_managed_mode) {
      nsync_mu_lock(&g_ref_lock);
      if (g_ref_count == 0) {
        nsync_mu_unlock(&g_ref_lock);
        CNK_RETURN(CKR_MUTEX_BAD, "g_ref_count is 0. Invalid state");
      }
      ++g_ref_count;
      nsync_mu_unlock(&g_ref_lock);
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
    CHK_ENSURE_NULL(args->pReserved);

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
    } else if (all_supplied) {
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
    } else {
      __builtin_unreachable(); // checked above
    }

    if (mutex_rv != CKR_OK) {
      CNK_RETURN(CKR_CANT_LOCK, "cannot init mutex");
    }
  }

  if (!g_cnk_is_managed_mode) {
    // Standalone mode: Initialize the PC/SC subsystem
    CNK_ENSURE_OK(cnk_initialize_pcsc());
  }

  // Initialize the session manager
  CK_RV rv = cnk_session_manager_init();
  if (rv == CKR_OK) {
    // Mark the library as initialized
    g_cnk_is_initialized = CK_TRUE;
  }

  nsync_mu_lock(&g_ref_lock);
  ++g_ref_count;
  CNK_ENSURE_EQUAL_REASON(g_ref_count, 1, "g_ref_count is not 1. Invalid state");
  nsync_mu_unlock(&g_ref_lock);

  CNK_RETURN(rv, "session manager init");
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
  CNK_LOG_FUNC(C_Finalize, ", pReserved: %p", pReserved);

  nsync_mu_lock(&g_ref_lock);
  if (!g_cnk_is_managed_mode && g_ref_count > 1) {
    nsync_mu_unlock(&g_ref_lock);
    CNK_RETURN(CKR_MUTEX_BAD, "g_ref_count > 1 in standalone mode");
  }
  if (--g_ref_count > 0) {
    nsync_mu_unlock(&g_ref_lock);
    CNK_RETURN(CKR_OK, "library still in use");
  }
  nsync_mu_unlock(&g_ref_lock);

  // According to PKCS#11, pReserved must be NULL_PTR
  CHK_ENSURE_NULL(pReserved);

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
  CNK_LOG_FUNC(C_GetInfo, ", pInfo: %p", pInfo);

  // Check if the library is initialized
  if (!g_cnk_is_initialized) {
    CNK_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED, "not initialized");
  }

  // Validate arguments
  CNK_ENSURE_NONNULL(pInfo);

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
  CNK_LOG_FUNC(C_GetFunctionList, ", ppFunctionList: %p", ppFunctionList);

  CNK_ENSURE_NONNULL(ppFunctionList);

  *ppFunctionList = &ck_function_list;
  CNK_RET_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
  CNK_LOG_FUNC(C_GetSlotList, ", tokenPresent: %d, pSlotList: %p, pulCount: %p", tokenPresent, pSlotList, pulCount);

  // Parameter validation
  CNK_ENSURE_NONNULL(pulCount);

  // Initialize PC/SC if not already initialized
  CNK_ENSURE_OK(cnk_initialize_pcsc());

  // List readers
  CNK_ENSURE_OK(cnk_list_readers());

  // If pSlotList is NULL, just return the number of slots
  if (!pSlotList) {
    *pulCount = g_cnk_num_readers;
    CNK_RET_OK;
  }

  // Check if the provided buffer is large enough
  if (*pulCount < g_cnk_num_readers) {
    *pulCount = g_cnk_num_readers;
    CNK_RETURN(CKR_BUFFER_TOO_SMALL, "pulCount too small");
  }

  // Fill the slot list with the stored slot IDs
  for (CK_ULONG i = 0; i < g_cnk_num_readers; i++) {
    pSlotList[i] = g_cnk_readers[i].slot_id;
  }

  *pulCount = g_cnk_num_readers;
  CNK_RET_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
  CNK_LOG_FUNC(C_GetSlotInfo, ", slotID: %lu, pInfo: %p", slotID, pInfo);

  CNK_ENSURE_NONNULL(pInfo);

  // Get firmware version and hardware name
  CK_BYTE fw_major, fw_minor;
  char hw_name[64] = {0}; // Buffer for hardware name
  CNK_ENSURE_OK(cnk_get_version(slotID, &fw_major, &fw_minor, hw_name, sizeof(hw_name)));

  // Fill in the slot info structure
  memset(pInfo, 0, sizeof(CK_SLOT_INFO));

  // Set the slot description to hardware name
  memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
  size_t name_len = strlen(hw_name);
  if (name_len > sizeof(pInfo->slotDescription)) {
    name_len = sizeof(pInfo->slotDescription);
  }
  memcpy(pInfo->slotDescription, hw_name, name_len);

  // Set the manufacturer ID
  memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
  const char *manufacturer = "canokeys.org";
  memcpy(pInfo->manufacturerID, manufacturer,
         strlen(manufacturer) > sizeof(pInfo->manufacturerID) ? sizeof(pInfo->manufacturerID) : strlen(manufacturer));

  // Set flags
  pInfo->flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT | CKF_TOKEN_PRESENT;

  // Always set hardware version to 1.0
  pInfo->hardwareVersion.major = 1;
  pInfo->hardwareVersion.minor = 0;

  // Set firmware version
  pInfo->firmwareVersion.major = fw_major;
  pInfo->firmwareVersion.minor = fw_minor;

  CNK_DEBUG("C_GetSlotInfo: Hardware name: %s, FW version: %d.%d", hw_name, fw_major, fw_minor);
  CNK_RET_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
  CNK_LOG_FUNC(C_GetTokenInfo, ", slotID: %lu", slotID);

  // Check parameters
  if (!g_cnk_is_initialized) {
    CNK_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED, "not initialized");
  }

  CNK_ENSURE_NONNULL(pInfo);

  // Check if the slot ID is valid
  if (slotID >= g_cnk_num_readers) {
    CNK_RETURN(CKR_SLOT_ID_INVALID, "invalid slot");
  }

  // Get the serial number
  CK_ULONG serial_number;
  CNK_ENSURE_OK(cnk_get_serial_number(slotID, &serial_number));

  // Clear the structure
  memset(pInfo, 0, sizeof(CK_TOKEN_INFO));

  // Create the token label with serial number
  char label[32];
  snprintf(label, sizeof(label), "CanoKey PIV #%lu", serial_number);

  // Set the token label (padded with spaces)
  memset(pInfo->label, ' ', sizeof(pInfo->label));
  size_t label_len = strlen(label);
  if (label_len > sizeof(pInfo->label)) {
    label_len = sizeof(pInfo->label);
  }
  memcpy(pInfo->label, label, label_len);

  // Set the manufacturer ID (padded with spaces)
  memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
  const char *manufacturer = "canokeys.org";
  size_t manufacturer_len = strlen(manufacturer);
  if (manufacturer_len > sizeof(pInfo->manufacturerID)) {
    manufacturer_len = sizeof(pInfo->manufacturerID);
  }
  memcpy(pInfo->manufacturerID, manufacturer, manufacturer_len);

  // Set the serial number (padded with spaces)
  memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
  char serial_str[16];
  snprintf(serial_str, sizeof(serial_str), "%lu", serial_number);
  size_t serial_len = strlen(serial_str);
  if (serial_len > sizeof(pInfo->serialNumber)) {
    serial_len = sizeof(pInfo->serialNumber);
  }
  memcpy(pInfo->serialNumber, serial_str, serial_len);

  // Set the flags as requested
  pInfo->flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;

  // Set session counts
  pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
  pInfo->ulSessionCount = 0; // Will be updated if we implement session tracking
  pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
  pInfo->ulRwSessionCount = 0; // Will be updated if we implement session tracking

  // Set PIN constraints
  pInfo->ulMaxPinLen = 8; // PIV PIN is 8 digits max
  pInfo->ulMinPinLen = 6; // PIV PIN is 6 digits min

  // Memory info - not applicable for a smart card, set to effectively infinite
  pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;

  // Get firmware version
  CK_BYTE fw_major, fw_minor;
  CK_RV rv = cnk_get_version(slotID, &fw_major, &fw_minor, (char *)pInfo->model, sizeof(pInfo->model));
  if (rv != CKR_OK) {
    // If we can't get the version, default to 1.0
    CNK_WARN("Failed to get firmware version, defaulting to 1.0");
    fw_major = 1;
    fw_minor = 0;
  }

  // Set hardware and firmware versions
  pInfo->hardwareVersion.major = 1;
  pInfo->hardwareVersion.minor = 0;
  pInfo->firmwareVersion.major = fw_major;
  pInfo->firmwareVersion.minor = fw_minor;

  // UTC time - not supported
  memset(pInfo->utcTime, 0, sizeof(pInfo->utcTime));

  CNK_DEBUG("Serial number: %lu, Label: %s", serial_number, label);
  CNK_RET_OK;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount) {
  CNK_LOG_FUNC(C_GetMechanismList, ", slotID: %lu", slotID);

  // Validate common parameters
  PKCS11_VALIDATE(pulCount, slotID);

  // Define the supported mechanisms
  static const CK_MECHANISM_TYPE supported_mechanisms[] = {
      CKM_RSA_PKCS_KEY_PAIR_GEN, // RSA key pair generation
      CKM_RSA_PKCS,              // RSA PKCS #1 v1.5
      CKM_RSA_X_509,             // Raw RSA
      CKM_RSA_PKCS_OAEP,         // RSA OAEP
      CKM_RSA_PKCS_PSS,          // RSA PSS
      CKM_SHA1_RSA_PKCS,         // RSA PKCS #1 v1.5 with SHA-1
      CKM_SHA1_RSA_PKCS_PSS,     // RSA PKCS #1 v1.5 with SHA-1 and PSS
      CKM_SHA256_RSA_PKCS,       // RSA PKCS #1 v1.5 with SHA-256
      CKM_SHA256_RSA_PKCS_PSS,   // RSA PKCS #1 v1.5 with SHA-256 and PSS
      CKM_SHA384_RSA_PKCS,       // RSA PKCS #1 v1.5 with SHA-384
      CKM_SHA384_RSA_PKCS_PSS,   // RSA PKCS #1 v1.5 with SHA-384 and PSS
      CKM_SHA512_RSA_PKCS,       // RSA PKCS #1 v1.5 with SHA-512
      CKM_SHA512_RSA_PKCS_PSS,   // RSA PKCS #1 v1.5 with SHA-512 and PSS
      CKM_SHA224_RSA_PKCS,       // RSA PKCS #1 v1.5 with SHA-224
      CKM_SHA224_RSA_PKCS_PSS,   // RSA PKCS #1 v1.5 with SHA-224 and PSS
      CKM_SHA3_256_RSA_PKCS,     // RSA PKCS #1 v1.5 with SHA3-256
      CKM_SHA3_384_RSA_PKCS,     // RSA PKCS #1 v1.5 with SHA3-384
      CKM_SHA3_512_RSA_PKCS,     // RSA PKCS #1 v1.5 with SHA3-512

      CKM_ECDSA_KEY_PAIR_GEN, // ECDSA key pair generation
      CKM_ECDSA               // ECDSA
  };

  const CK_ULONG num_mechanisms = sizeof(supported_mechanisms) / sizeof(supported_mechanisms[0]);

  // If pMechanismList is NULL, just return the number of mechanisms
  if (pMechanismList == NULL) {
    *pulCount = num_mechanisms;
    CNK_RET_OK;
  }

  // Check if the provided buffer is large enough
  if (*pulCount < num_mechanisms) {
    *pulCount = num_mechanisms;
    CNK_RETURN(CKR_BUFFER_TOO_SMALL, "pulCount too small");
  }

  // Copy the mechanism list to the provided buffer
  memcpy(pMechanismList, supported_mechanisms, sizeof(supported_mechanisms));
  *pulCount = num_mechanisms;

  CNK_DEBUG("Returned %lu mechanisms", num_mechanisms);
  CNK_RET_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
  CNK_LOG_FUNC(C_GetMechanismInfo, ", slotID: %lu, type: %lu, pInfo: %p", slotID, type, pInfo);

  // Validate common parameters
  PKCS11_VALIDATE(pInfo, slotID);

  // Clear the mechanism info structure
  memset(pInfo, 0, sizeof(CK_MECHANISM_INFO));

  // Set mechanism info based on type
  switch (type) {
  case CKM_RSA_PKCS_KEY_PAIR_GEN:
    pInfo->flags = CKF_GENERATE_KEY_PAIR;
    pInfo->ulMinKeySize = 2048;
    pInfo->ulMaxKeySize = 4096;
    break;

  case CKM_RSA_X_509:
  case CKM_RSA_PKCS:
    pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY;
    pInfo->ulMinKeySize = 2048;
    pInfo->ulMaxKeySize = 4096;
    break;

  case CKM_RSA_PKCS_OAEP:
    pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
    pInfo->ulMinKeySize = 2048;
    pInfo->ulMaxKeySize = 4096;
    break;

  case CKM_RSA_PKCS_PSS:
  case CKM_SHA1_RSA_PKCS:
  case CKM_SHA1_RSA_PKCS_PSS:
  case CKM_SHA256_RSA_PKCS:
  case CKM_SHA256_RSA_PKCS_PSS:
  case CKM_SHA384_RSA_PKCS:
  case CKM_SHA384_RSA_PKCS_PSS:
  case CKM_SHA512_RSA_PKCS:
  case CKM_SHA512_RSA_PKCS_PSS:
  case CKM_SHA224_RSA_PKCS:
  case CKM_SHA224_RSA_PKCS_PSS:
  case CKM_SHA3_256_RSA_PKCS:
  case CKM_SHA3_384_RSA_PKCS:
  case CKM_SHA3_512_RSA_PKCS:
    pInfo->flags = CKF_SIGN | CKF_VERIFY;
    pInfo->ulMinKeySize = 2048;
    pInfo->ulMaxKeySize = 4096;
    break;

    // TODO: add ECDSA

  default:
    CNK_RETURN(CKR_MECHANISM_INVALID, "invalid mechanism");
  }

  CNK_DEBUG("C_GetMechanismInfo: Mechanism %lu, flags = 0x%lx, min key size = %lu, max key size = %lu", type,
            pInfo->flags, pInfo->ulMinKeySize, pInfo->ulMaxKeySize);
  CNK_RET_OK;
}

CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel) {
  CNK_LOG_FUNC(C_InitToken, ", slotID: %lu", slotID);
  CNK_RET_UNIMPL;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  CNK_LOG_FUNC(C_InitPIN, ", hSession: %lu", hSession);
  CNK_RET_UNIMPL;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin,
               CK_ULONG ulNewLen) {
  CNK_RET_UNIMPL;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify,
                    CK_SESSION_HANDLE_PTR phSession) {
  if (!g_cnk_is_initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  CNK_ENSURE_NONNULL(phSession);

  return cnk_session_open(slotID, flags, pApplication, Notify, phSession);
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
  if (!g_cnk_is_initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  return cnk_session_close(hSession);
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
  if (!g_cnk_is_initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  return cnk_session_close_all(slotID);
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
  CNK_LOG_FUNC(C_GetSessionInfo, ", hSession: %lu", hSession);

  // Check if the cryptoki library is initialized
  if (!g_cnk_is_initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  // Validate arguments
  CNK_ENSURE_NONNULL(pInfo);

  // Find the session
  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  // Fill in the session info structure
  pInfo->slotID = session->slot_id;

  // Set the session flags (only support read-only for now)
  pInfo->flags = CKF_SERIAL_SESSION; // Always set for PKCS#11 v2.x
  // We don't support read-write sessions for now
  // if (session->flags & CKF_RW_SESSION) {
  //   pInfo->flags |= CKF_RW_SESSION;
  // }

  // Determine the state based on PIN cache status
  if (session->piv_pin_len > 0) {
    // User is logged in
    pInfo->state = CKS_RO_USER_FUNCTIONS;
  } else {
    // User is not logged in
    pInfo->state = CKS_RO_PUBLIC_SESSION;
  }

  // No device errors
  pInfo->ulDeviceError = 0;

  CNK_DEBUG("C_GetSessionInfo: slotID = %lu, state = %lu, flags = 0x%lx", pInfo->slotID, pInfo->state, pInfo->flags);
  CNK_RET_OK;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen) {
  CNK_RET_UNIMPL;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen,
                          CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey) {
  CNK_RET_UNIMPL;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  CNK_LOG_FUNC(C_Login, ", hSession: %lu, userType: %lu, ulPinLen: %lu", hSession, userType, ulPinLen);

  // Check if the cryptoki library is initialized
  if (!g_cnk_is_initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  // Validate arguments
  if (pPin == NULL && ulPinLen > 0) {
    return CKR_ARGUMENTS_BAD;
  }

  // Only CKU_USER is supported for PIV
  if (userType != CKU_USER) {
    return CKR_USER_TYPE_INVALID;
  }

  // Find the session
  CNK_PKCS11_SESSION *session;
  CK_RV rv = CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  // Check if already logged in (PIN is already cached)
  if (session->piv_pin_len > 0) {
    return CKR_USER_ALREADY_LOGGED_IN;
  }

  // Verify the PIN and cache it in the session
  rv = cnk_verify_piv_pin_with_session(session->slot_id, session, pPin, ulPinLen);

  // If PIN verification was successful, update the session state
  if (rv == CKR_OK) {
    // Update session state based on session type
    if (session->flags & CKF_RW_SESSION) {
      session->state = SESSION_STATE_RW_USER;
    } else {
      session->state = SESSION_STATE_RO_USER;
    }
  }

  return rv;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
  CNK_LOG_FUNC(C_Logout, ", hSession: %lu", hSession);

  // Check if the cryptoki library is initialized
  if (!g_cnk_is_initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  // Find the session
  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  ;

  // Check if logged in (PIN is cached)
  if (session->piv_pin_len == 0) {
    return CKR_USER_NOT_LOGGED_IN;
  }

  // Send the logout APDU to the card
  CNK_ENSURE_OK(cnk_logout_piv_pin_with_session(session->slot_id));

  // Clear the cached PIN
  memset(session->piv_pin, 0xFF, sizeof(session->piv_pin));
  session->piv_pin_len = 0;

  // Reset session state based on session type
  if (session->flags & CKF_RW_SESSION) {
    session->state = SESSION_STATE_RW_PUBLIC;
  } else {
    session->state = SESSION_STATE_RO_PUBLIC;
  }

  CNK_RET_OK;
}

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                     CK_OBJECT_HANDLE_PTR phObject) {
  CNK_LOG_FUNC(C_CreateObject, ", hSession: %lu, ulCount: %lu", hSession, ulCount);
  return cnk_create_object(hSession, pTemplate, ulCount, phObject);
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                   CK_OBJECT_HANDLE_PTR phNewObject) {
  CNK_LOG_FUNC(C_CopyObject, ", hSession: %lu, hObject: %lu, ulCount: %lu", hSession, hObject, ulCount);
  return cnk_copy_object(hSession, hObject, pTemplate, ulCount, phNewObject);
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
  CNK_LOG_FUNC(C_DestroyObject, ", hSession: %lu, hObject: %lu", hSession, hObject);
  return cnk_destroy_object(hSession, hObject);
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) {
  CNK_LOG_FUNC(C_GetObjectSize, ", hSession: %lu, hObject: %lu", hSession, hObject);
  return cnk_get_object_size(hSession, hObject, pulSize);
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                          CK_ULONG ulCount) {
  CNK_LOG_FUNC(C_GetAttributeValue, ", hSession: %lu, hObject: %lu, ulCount: %lu", hSession, hObject, ulCount);
  return cnk_get_attribute_value(hSession, hObject, pTemplate, ulCount);
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                          CK_ULONG ulCount) {
  CNK_LOG_FUNC(C_SetAttributeValue, ", hSession: %lu, hObject: %lu, ulCount: %lu", hSession, hObject, ulCount);
  return cnk_set_attribute_value(hSession, hObject, pTemplate, ulCount);
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  CNK_LOG_FUNC(C_FindObjectsInit, ", hSession: %lu, ulCount: %lu", hSession, ulCount);
  return cnk_find_objects_init(hSession, pTemplate, ulCount);
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
                    CK_ULONG_PTR pulObjectCount) {
  CNK_LOG_FUNC(C_FindObjects, ", hSession: %lu, ulMaxObjectCount: %lu", hSession, ulMaxObjectCount);
  return cnk_find_objects(hSession, phObject, ulMaxObjectCount, pulObjectCount);
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
  CNK_LOG_FUNC(C_FindObjectsFinal, ", hSession: %lu", hSession);
  return cnk_find_objects_final(hSession);
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) { CNK_RET_UNIMPL; }

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
                CK_ULONG_PTR pulEncryptedDataLen) {
  CNK_RET_UNIMPL;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                      CK_ULONG_PTR pulEncryptedPartLen) {
  CNK_RET_UNIMPL;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen) {
  CNK_RET_UNIMPL;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) { CNK_RET_UNIMPL; }

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
                CK_ULONG_PTR pulDataLen) {
  CNK_RET_UNIMPL;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
                      CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
  CNK_RET_UNIMPL;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen) { CNK_RET_UNIMPL; }

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) { CNK_RET_UNIMPL; }

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
               CK_ULONG_PTR pulDigestLen) {
  CNK_RET_UNIMPL;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) { CNK_RET_UNIMPL; }

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) { CNK_RET_UNIMPL; }

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) { CNK_RET_UNIMPL; }

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  CNK_LOG_FUNC(C_SignInit, ", hSession: %lu, pMechanism: %p, hKey: %lu", hSession, pMechanism, hKey);

  // Validate mechanism
  CNK_ENSURE_NONNULL(pMechanism);

  // Validate session
  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(validate_session(hSession, &session));

  // Validate the key object
  CK_BYTE obj_id;
  CNK_ENSURE_OK(cnk_validate_object(hKey, session, CKO_PRIVATE_KEY, &obj_id));

  // Map object ID to PIV tag
  CK_BYTE piv_tag;
  CNK_ENSURE_OK(cnk_obj_id_to_piv_tag(obj_id, &piv_tag));

  // Verify that the key matches the mechanism and retrieve modulus if available
  CK_BYTE algorithm_type;

  // Reset modulus length to the maximum buffer size
  session->active_key_modulus_len = sizeof(session->active_key_modulus);

  // Get metadata including the modulus
  CNK_ENSURE_OK(cnk_get_metadata(session->slot_id, piv_tag, &algorithm_type, session->active_key_modulus,
                                 &session->active_key_modulus_len));

  CNK_DEBUG("Modulus length: %lu", session->active_key_modulus_len);

  // Check if the mechanism is supported
  switch (pMechanism->mechanism) {
  case CKM_RSA_X_509:
  case CKM_RSA_PKCS:
    if (algorithm_type != PIV_ALG_RSA_2048 && algorithm_type != PIV_ALG_RSA_3072 && algorithm_type != PIV_ALG_RSA_4096)
      CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "key is not RSA");
    break;

  case CKM_RSA_PKCS_PSS:
  case CKM_SHA1_RSA_PKCS_PSS:
  case CKM_SHA224_RSA_PKCS_PSS:
  case CKM_SHA256_RSA_PKCS_PSS:
  case CKM_SHA384_RSA_PKCS_PSS:
  case CKM_SHA512_RSA_PKCS_PSS:
    // For PSS mechanisms, validate the parameter
    if (algorithm_type != PIV_ALG_RSA_2048 && algorithm_type != PIV_ALG_RSA_3072 && algorithm_type != PIV_ALG_RSA_4096)
      CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "key is not RSA");

    // Check if parameters are provided
    if (pMechanism->pParameter == NULL || pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS))
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "PSS mechanism requires valid parameters");

    // Validate the PSS parameters
    CK_RSA_PKCS_PSS_PARAMS *pss_params = pMechanism->pParameter;

    // Validate hash algorithm
    switch (pss_params->hashAlg) {
    case CKM_SHA_1:
    case CKM_SHA224:
    case CKM_SHA256:
    case CKM_SHA384:
    case CKM_SHA512:
      break;
    default:
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "unsupported hash algorithm in PSS parameters");
    }

    // Validate MGF
    switch (pss_params->mgf) {
    case CKG_MGF1_SHA1:
    case CKG_MGF1_SHA224:
    case CKG_MGF1_SHA256:
    case CKG_MGF1_SHA384:
    case CKG_MGF1_SHA512:
      break;
    default:
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "unsupported MGF function in PSS parameters");
    }

    break;

  case CKM_SHA1_RSA_PKCS:
  case CKM_SHA256_RSA_PKCS:
  case CKM_SHA384_RSA_PKCS:
  case CKM_SHA512_RSA_PKCS:
  case CKM_SHA224_RSA_PKCS:
  case CKM_SHA3_256_RSA_PKCS:
  case CKM_SHA3_384_RSA_PKCS:
  case CKM_SHA3_512_RSA_PKCS:
    if (algorithm_type != PIV_ALG_RSA_2048 && algorithm_type != PIV_ALG_RSA_3072 && algorithm_type != PIV_ALG_RSA_4096)
      CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "key is not RSA");
    break;

  default:
    CNK_RETURN(CKR_MECHANISM_INVALID, "unsupported mechanism");
  }

  // Store the key handle, mechanism, and validated info in the session for C_Sign
  session->active_key = hKey;
  session->active_mechanism_ptr = pMechanism;
  session->active_key_piv_tag = piv_tag;
  session->active_key_algorithm_type = algorithm_type;

  CNK_DEBUG("Setting active_mechanism to %lu, PIV tag %u, algorithm type %u", pMechanism->mechanism, piv_tag,
            algorithm_type);

  CNK_RET_OK;
}

// Main C_Sign function
CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
             CK_ULONG_PTR pulSignatureLen) {
  CNK_LOG_FUNC(C_Sign, ", hSession: %lu, ulDataLen: %lu, pSignature: %p, pulSignatureLen: %p", hSession, ulDataLen,
               pSignature, pulSignatureLen);

  // Parameter validation
  if (!pData && ulDataLen > 0)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "pData is NULL but ulDataLen > 0");

  CNK_ENSURE_NONNULL(pulSignatureLen);

  // Validate the session
  CNK_PKCS11_SESSION *session;
  CK_RV rv = CNK_ENSURE_OK(validate_session(hSession, &session));

  // Verify that we have an active key and mechanism
  if (session->active_key == 0)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_SignInit not called - no active key");

  if (session->active_mechanism_ptr == NULL)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_SignInit not called - no active mechanism");

  // All key validation was already done in C_SignInit, so we use the cached values
  CK_BYTE piv_tag = session->active_key_piv_tag;
  CK_BYTE algorithm_type = session->active_key_algorithm_type;
  CK_MECHANISM_PTR mechanism_ptr = session->active_mechanism_ptr;

  CNK_DEBUG("Signing with active key, PIV tag %u, algorithm type %u", piv_tag, algorithm_type);

  // For signature-only call to get the signature length
  if (pSignature == NULL) {
    switch (algorithm_type) {
    case PIV_ALG_RSA_2048:
      *pulSignatureLen = 256; // 2048 bits = 256 bytes
      break;
    case PIV_ALG_RSA_3072:
      *pulSignatureLen = 384; // 3072 bits = 384 bytes
      break;
    case PIV_ALG_RSA_4096:
      *pulSignatureLen = 512; // 4096 bits = 512 bytes
      break;
    default:
      CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "unsupported key algorithm");
    }

    // We don't need to reset the session state here since we're just querying the length
    CNK_RET_OK;
  }

  // Prepare data for RSA signing (add padding, etc.)
  CK_BYTE prepared_data[512]; // Max RSA key size (4096 bits = 512 bytes)
  CK_ULONG prepared_data_len = sizeof(prepared_data);

  rv = cnk_prepare_rsa_sign_data(mechanism_ptr, pData, ulDataLen, session->active_key_modulus,
                                 session->active_key_modulus_len, algorithm_type, prepared_data, &prepared_data_len);
  if (rv != CKR_OK) {
    // Reset the session state
    session->active_mechanism_ptr = NULL;
    session->active_key = 0;
    session->active_key_piv_tag = 0;
    session->active_key_algorithm_type = 0;
    return rv;
  }

  // Now pass the prepared data to the PIV sign function
  rv = cnk_piv_sign(session->slot_id, session, piv_tag, prepared_data, prepared_data_len, pSignature, pulSignatureLen);

  // Reset the active mechanism and related fields to indicate operation is complete
  session->active_mechanism_ptr = NULL;
  session->active_key = 0;
  session->active_key_piv_tag = 0;
  session->active_key_algorithm_type = 0;

  return rv;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) { CNK_RET_UNIMPL; }

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) { CNK_RET_UNIMPL; }

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  CNK_RET_UNIMPL;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                    CK_ULONG_PTR pulSignatureLen) {
  CNK_RET_UNIMPL;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) { CNK_RET_UNIMPL; }

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
               CK_ULONG ulSignatureLen) {
  CNK_RET_UNIMPL;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) { CNK_RET_UNIMPL; }

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) { CNK_RET_UNIMPL; }

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  CNK_RET_UNIMPL;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData,
                      CK_ULONG_PTR pulDataLen) {
  CNK_RET_UNIMPL;
}

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                            CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
  CNK_RET_UNIMPL;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
                            CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
  CNK_RET_UNIMPL;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                          CK_ULONG_PTR pulEncryptedPartLen) {
  CNK_RET_UNIMPL;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
                            CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
  CNK_RET_UNIMPL;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate,
                    CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
  CNK_RET_UNIMPL;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                        CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                        CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey,
                        CK_OBJECT_HANDLE_PTR phPrivateKey) {
  CNK_RET_UNIMPL;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey,
                CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
  CNK_RET_UNIMPL;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey,
                  CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
  CNK_RET_UNIMPL;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey,
                  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
  CNK_RET_UNIMPL;
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) { CNK_RET_UNIMPL; }

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) { CNK_RET_UNIMPL; }

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession) { CNK_RET_UNIMPL; }

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession) { CNK_RET_UNIMPL; }

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved) { CNK_RET_UNIMPL; }

#pragma clang diagnostic pop

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
