#define CRYPTOKI_EXPORTS

#include "logging.h"
#include "pcsc_backend.h"
#include "pkcs11.h"
#include "pkcs11_canokey.h"
#include "pkcs11_macros.h"
#include "pkcs11_mutex.h"
#include "pkcs11_session.h"
#include "rsa_utils.h"

#include <stdio.h>
#include <string.h>

// Forward declaration of the function list
static CK_FUNCTION_LIST ck_function_list;

// Forward declarations for attribute handler functions
static CK_RV handle_certificate_attribute(CK_ATTRIBUTE attribute, CK_BYTE piv_tag, CK_BYTE_PTR data, CK_ULONG data_len);
static CK_RV handle_public_key_attribute(CK_ATTRIBUTE attribute, CK_BYTE piv_tag, CK_BYTE algorithm_type,
                                         CK_SLOT_ID slot_id);
static CK_RV handle_private_key_attribute(CK_ATTRIBUTE attribute, CK_BYTE piv_tag, CK_BYTE algorithm_type,
                                          CK_SLOT_ID slot_id);

// Helper function to extract object information from a handle
// Object handle format: slot_id (16 bits) | object_class (8 bits) | object_id (8 bits)
static void extract_object_info(CK_OBJECT_HANDLE hObject, CK_SLOT_ID *slot_id, CK_OBJECT_CLASS *obj_class,
                                CK_BYTE *obj_id) {
  if (slot_id) {
    *slot_id = (hObject >> 16) & 0xFFFF;
  }
  if (obj_class) {
    *obj_class = (hObject >> 8) & 0xFF;
  }
  if (obj_id) {
    *obj_id = hObject & 0xFF;
  }
}

// Helper function to map object ID to PIV tag
static CK_RV obj_id_to_piv_tag(CK_BYTE obj_id, CK_BYTE *piv_tag) {
  switch (obj_id) {
  case PIV_SLOT_9A:
    *piv_tag = 0x9A;
    break;
  case PIV_SLOT_9C:
    *piv_tag = 0x9C;
    break;
  case PIV_SLOT_9D:
    *piv_tag = 0x9D;
    break;
  case PIV_SLOT_9E:
    *piv_tag = 0x9E;
    break;
  case PIV_SLOT_82:
    *piv_tag = 0x82;
    break;
  case PIV_SLOT_83:
    *piv_tag = 0x83;
    break;
  default:
    return CKR_OBJECT_HANDLE_INVALID;
  }
  CNK_RET_OK;
}

// Helper function to set attribute values with proper buffer checking
static CK_RV set_attribute_value(CK_ATTRIBUTE_PTR attribute, const void *value, CK_ULONG value_size) {
  attribute->ulValueLen = value_size;

  if (attribute->pValue) {
    if (attribute->ulValueLen >= value_size) {
      memcpy(attribute->pValue, value, value_size);
    } else {
      return CKR_BUFFER_TOO_SMALL;
    }
  }

  CNK_RET_OK;
}

// Helper function to check basic library and session state
static CK_RV validate_session(CK_SESSION_HANDLE hSession, CNK_PKCS11_SESSION **session) {
  // Check if the library is initialized
  if (!g_cnk_is_initialized)
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  // Find the session
  return cnk_session_find(hSession, session);
}

// Helper function to validate an object handle against a session and expected class
static CK_RV validate_object(CK_OBJECT_HANDLE hObject, CNK_PKCS11_SESSION *session, CK_OBJECT_CLASS expected_class,
                             CK_BYTE *obj_id) {
  // Extract object information from the handle
  CK_SLOT_ID slot_id;
  CK_OBJECT_CLASS obj_class;

  extract_object_info(hObject, &slot_id, &obj_class, obj_id);

  // Verify the slot ID matches the session's slot ID
  if (slot_id != session->slot_id) {
    CNK_RETURN(CKR_OBJECT_HANDLE_INVALID, "slot ID mismatch");
  }

  // Verify the object class if expected_class is not 0
  if (expected_class != 0 && obj_class != expected_class) {
    CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "object class mismatch");
  }

  CNK_RET_OK;
}

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
#ifdef CNK_VERBOSE
  // forcibly enable debug logging, can be overridden by C_CNK_ConfigLogging later
  C_CNK_ConfigLogging(CNK_LOG_LEVEL_DEBUG, NULL);
#endif

  CNK_LOG_FUNC(C_Initialize, ", pInitArgs: %p\n", pInitArgs);

  // Check if the library is already initialized
  if (g_cnk_is_initialized)
    CNK_RETURN(CKR_CRYPTOKI_ALREADY_INITIALIZED, "already initialized");

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
  CNK_RETURN(rv, "session manager init");
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
  CNK_LOG_FUNC(C_Finalize, ", pReserved: %p\n", pReserved);

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
  CNK_LOG_FUNC(C_GetInfo, ", pInfo: %p\n", pInfo);

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
  CNK_LOG_FUNC(C_GetFunctionList, ", ppFunctionList: %p\n", ppFunctionList);

  CNK_ENSURE_NONNULL(ppFunctionList);

  *ppFunctionList = &ck_function_list;
  CNK_RET_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
  CNK_LOG_FUNC(C_GetSlotList, ", tokenPresent: %d, pSlotList: %p, pulCount: %p\n", tokenPresent, pSlotList, pulCount);

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
  CNK_LOG_FUNC(C_GetSlotInfo, ", slotID: %lu, pInfo: %p\n", slotID, pInfo);

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

  CNK_DEBUG("C_GetSlotInfo: Hardware name: %s, FW version: %d.%d\n", hw_name, fw_major, fw_minor);
  CNK_RET_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
  CNK_LOG_FUNC(C_GetTokenInfo, ", slotID: %lu\n", slotID);

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
    CNK_WARN("Failed to get firmware version, defaulting to 1.0\n");
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

  CNK_DEBUG("Serial number: %lu, Label: %s\n", serial_number, label);
  CNK_RET_OK;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount) {
  CNK_LOG_FUNC(C_GetMechanismList, ", slotID: %lu\n", slotID);

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

  CNK_DEBUG("Returned %lu mechanisms\n", num_mechanisms);
  CNK_RET_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
  CNK_LOG_FUNC(C_GetMechanismInfo, ", slotID: %lu, type: %lu, pInfo: %p\n", slotID, type, pInfo);

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

  CNK_DEBUG("C_GetMechanismInfo: Mechanism %lu, flags = 0x%lx, min key size = %lu, max key size = %lu\n", type,
            pInfo->flags, pInfo->ulMinKeySize, pInfo->ulMaxKeySize);
  CNK_RET_OK;
}

CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel) {
  CNK_LOG_FUNC(C_InitToken, ", slotID: %lu\n", slotID);
  CNK_RET_UNIMPL;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  CNK_LOG_FUNC(C_InitPIN, ", hSession: %lu\n", hSession);
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
  CNK_LOG_FUNC(C_GetSessionInfo, ", hSession: %lu\n", hSession);

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

  CNK_DEBUG("C_GetSessionInfo: slotID = %lu, state = %lu, flags = 0x%lx\n", pInfo->slotID, pInfo->state, pInfo->flags);
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
  CNK_LOG_FUNC(C_Login, ", hSession: %lu, userType: %lu, ulPinLen: %lu\n", hSession, userType, ulPinLen);

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
  CNK_LOG_FUNC(C_Logout, ", hSession: %lu\n", hSession);

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
  CNK_RET_UNIMPL;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                   CK_OBJECT_HANDLE_PTR phNewObject) {
  CNK_RET_UNIMPL;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) { CNK_RET_UNIMPL; }

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) { CNK_RET_UNIMPL; }

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                          CK_ULONG ulCount) {
  CNK_LOG_FUNC(C_GetAttributeValue, ", hSession: %lu, hObject: %lu, ulCount: %lu\n", hSession, hObject, ulCount);

  // Validate parameters
  if (!pTemplate && ulCount > 0)
    return CKR_ARGUMENTS_BAD;

  // Validate session
  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(validate_session(hSession, &session));

  // Extract and validate object information
  CK_OBJECT_CLASS obj_class;
  CK_BYTE obj_id;
  CNK_ENSURE_OK(validate_object(hObject, session, 0, &obj_id));

  // Get object class from handle
  extract_object_info(hObject, NULL, &obj_class, NULL);
  CNK_DEBUG("Object handle: slot %lu, class %lu, id %lu\n", session->slot_id, obj_class, obj_id);

  // Map object ID to PIV tag
  CK_BYTE piv_tag;
  CNK_ENSURE_OK(obj_id_to_piv_tag(obj_id, &piv_tag));

  // Fetch the PIV data for this object
  CK_ULONG data_len = 0;
  CK_BYTE_PTR data = NULL;

  CNK_ENSURE_OK(cnk_get_piv_data(session->slot_id, piv_tag, &data, &data_len, CK_FALSE));

  // If no data was found, the object doesn't exist
  if (data_len == 0) {
    return CKR_OBJECT_HANDLE_INVALID;
  }

  // Get key metadata if this is a key object
  CK_BYTE algorithm_type;

  if (obj_class == CKO_PUBLIC_KEY || obj_class == CKO_PRIVATE_KEY) {
    CK_RV rv = cnk_get_metadata(session->slot_id, piv_tag, &algorithm_type);
    if (rv != CKR_OK) {
      CNK_DEBUG("Failed to get metadata for PIV tag 0x%02X: %lu\n", piv_tag, rv);
      // Continue anyway, we'll use default values
    } else {
      CNK_DEBUG("Retrieved algorithm type %u for PIV tag 0x%02X\n", algorithm_type, piv_tag);
    }
  }

  // Process each attribute in the template
  CK_RV return_rv = CKR_OK; // Final return value

  for (CK_ULONG i = 0; i < ulCount; i++) {
    // Set default values for attributes that are not found
    pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
    CK_RV rv = CKR_ATTRIBUTE_TYPE_INVALID; // Default to attribute not found

    // Common attributes for all object types
    switch (pTemplate[i].type) {
    case CKA_CLASS:
      if (pTemplate[i].pValue) {
        if (pTemplate[i].ulValueLen >= sizeof(CK_OBJECT_CLASS)) {
          *((CK_OBJECT_CLASS *)pTemplate[i].pValue) = obj_class;
        } else {
          rv = CKR_BUFFER_TOO_SMALL;
        }
      }
      pTemplate[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
      rv = CKR_OK;
      break;

    case CKA_TOKEN:
      if (pTemplate[i].pValue) {
        if (pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
          *((CK_BBOOL *)pTemplate[i].pValue) = CK_TRUE;
        } else {
          rv = CKR_BUFFER_TOO_SMALL;
        }
      }
      pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
      rv = CKR_OK;
      break;

    case CKA_PRIVATE:
      if (pTemplate[i].pValue) {
        if (pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
          // Only private keys are private objects
          *((CK_BBOOL *)pTemplate[i].pValue) = (obj_class == CKO_PRIVATE_KEY) ? CK_TRUE : CK_FALSE;
        } else {
          rv = CKR_BUFFER_TOO_SMALL;
        }
      }
      pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
      rv = CKR_OK;
      break;

    case CKA_ID:
      if (pTemplate[i].pValue) {
        if (pTemplate[i].ulValueLen >= sizeof(CK_BYTE)) {
          *((CK_BYTE *)pTemplate[i].pValue) = obj_id;
        } else {
          rv = CKR_BUFFER_TOO_SMALL;
        }
      }
      pTemplate[i].ulValueLen = sizeof(CK_BYTE);
      rv = CKR_OK;
      break;

    case CKA_LABEL: {
      // Create a label based on the object type and ID
      char label[32];
      const char *type_str = "Unknown";

      switch (obj_class) {
      case CKO_CERTIFICATE:
        type_str = "Certificate";
        break;
      case CKO_PUBLIC_KEY:
        type_str = "Public Key";
        break;
      case CKO_PRIVATE_KEY:
        type_str = "Private Key";
        break;
      case CKO_DATA:
        type_str = "Data";
        break;
      }

      snprintf(label, sizeof(label), "PIV %s %02X", type_str, piv_tag);
      CK_ULONG label_len = (CK_ULONG)strlen(label);

      if (pTemplate[i].pValue) {
        if (pTemplate[i].ulValueLen >= label_len) {
          memcpy(pTemplate[i].pValue, label, label_len);
        } else {
          rv = CKR_BUFFER_TOO_SMALL;
        }
      }
      pTemplate[i].ulValueLen = label_len;
      rv = CKR_OK;
      break;
    }

    default:
      // Not a common attribute, handle based on object class
      break;
    }

    // If we've already handled this attribute, continue to the next one
    if (rv != CKR_ATTRIBUTE_TYPE_INVALID) {
      if (rv != CKR_OK && return_rv == CKR_OK) {
        return_rv = rv; // Update return value if we had an error
      }
      continue;
    }

    // Object class specific attributes
    switch (obj_class) {
    case CKO_CERTIFICATE:
      rv = handle_certificate_attribute(pTemplate[i], piv_tag, data, data_len);
      break;

    case CKO_PUBLIC_KEY:
      rv = handle_public_key_attribute(pTemplate[i], piv_tag, algorithm_type, session->slot_id);
      break;

    case CKO_PRIVATE_KEY:
      rv = handle_private_key_attribute(pTemplate[i], piv_tag, algorithm_type, session->slot_id);
      break;

    default:
      // Unsupported object class
      rv = CKR_ATTRIBUTE_TYPE_INVALID;
      break;
    }

    // Update the return value if needed
    if (rv != CKR_OK && return_rv == CKR_OK) {
      return_rv = rv;
    }
  }

  // Free the PIV data if it was allocated
  if (data != NULL) {
    ck_free(data);
  }

  return return_rv;
}

static CK_KEY_TYPE algo_type_to_key_type(CK_BYTE algorithm_type) {
  switch (algorithm_type) {
  case PIV_ALG_RSA_2048:
  case PIV_ALG_RSA_3072:
  case PIV_ALG_RSA_4096:
    return CKK_RSA;

  case PIV_ALG_ECC_256:
  case PIV_ALG_ECC_384:
  case PIV_ALG_SECP256K1:
  case PIV_ALG_SM2:
    return CKK_EC;

  case PIV_ALG_ED25519:
  case PIV_ALG_X25519:
    return CKK_EC_EDWARDS;

  default:
    return CKK_VENDOR_DEFINED;
  }
}

// Handle certificate-specific attributes
static CK_RV handle_certificate_attribute(CK_ATTRIBUTE attribute, CK_BYTE piv_tag, CK_BYTE_PTR data,
                                          CK_ULONG data_len) {
  CK_RV rv = CKR_ATTRIBUTE_TYPE_INVALID;

  switch (attribute.type) {
  case CKA_CERTIFICATE_TYPE: {
    CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
    rv = set_attribute_value(&attribute, &cert_type, sizeof(cert_type));
    break;
  }

  case CKA_VALUE:
    // For certificates, return the raw certificate data
    rv = set_attribute_value(&attribute, data, data_len);
    break;

    // Add other certificate attributes as needed
    // CKA_SUBJECT, CKA_ISSUER, CKA_SERIAL_NUMBER would require parsing the certificate

  default:
    rv = CKR_ATTRIBUTE_TYPE_INVALID;
    break;
  }

  return rv;
}

// Handle public key specific attributes
static CK_RV handle_public_key_attribute(CK_ATTRIBUTE attribute, CK_BYTE piv_tag, CK_BYTE algorithm_type,
                                         CK_SLOT_ID slot_id) {
  CK_RV rv = CKR_ATTRIBUTE_TYPE_INVALID;
  CK_KEY_TYPE key_type = algo_type_to_key_type(algorithm_type);

  switch (attribute.type) {
  case CKA_KEY_TYPE:
    rv = set_attribute_value(&attribute, &key_type, sizeof(key_type));
    break;

  case CKA_VERIFY: {
    // Public keys can be used for verification
    CK_BBOOL value = CK_TRUE;
    rv = set_attribute_value(&attribute, &value, sizeof(value));
    break;
  }

  case CKA_ENCRYPT: {
    // Only RSA public keys can encrypt
    CK_BBOOL value = (key_type == CKK_RSA) ? CK_TRUE : CK_FALSE;
    rv = set_attribute_value(&attribute, &value, sizeof(value));
    break;
  }

  case CKA_MODULUS_BITS:
    if (key_type == CKK_RSA) {
      // For RSA keys, we can determine the modulus bits
      CK_ULONG modulus_bits = 2048; // Default for PIV
      if (algorithm_type == PIV_ALG_RSA_3072) {
        modulus_bits = 3072;
      } else if (algorithm_type == PIV_ALG_RSA_4096) {
        modulus_bits = 4096;
      }
      rv = set_attribute_value(&attribute, &modulus_bits, sizeof(modulus_bits));
    } else {
      // Not applicable for non-RSA keys
      rv = CKR_ATTRIBUTE_TYPE_INVALID;
    }
    break;

    // Add other public key attributes as needed
    // For a complete implementation, you would need to handle attributes like
    // CKA_MODULUS, CKA_PUBLIC_EXPONENT for RSA or CKA_EC_PARAMS, CKA_EC_POINT for EC

  default:
    rv = CKR_ATTRIBUTE_TYPE_INVALID;
    break;
  }

  return rv;
}

// Handle private key specific attributes
static CK_RV handle_private_key_attribute(CK_ATTRIBUTE attribute, CK_BYTE piv_tag, CK_BYTE algorithm_type,
                                          CK_SLOT_ID slot_id) {
  CK_RV rv = CKR_ATTRIBUTE_TYPE_INVALID;
  CK_KEY_TYPE key_type = algo_type_to_key_type(algorithm_type);

  switch (attribute.type) {
  case CKA_KEY_TYPE:
    rv = set_attribute_value(&attribute, &key_type, sizeof(key_type));
    break;

  case CKA_SIGN: {
    // Private keys can be used for signing
    CK_BBOOL value = CK_TRUE;
    rv = set_attribute_value(&attribute, &value, sizeof(value));
    break;
  }

  case CKA_DECRYPT: {
    // Only RSA private keys can decrypt
    CK_BBOOL value = (key_type == CKK_RSA) ? CK_TRUE : CK_FALSE;
    rv = set_attribute_value(&attribute, &value, sizeof(value));
    break;
  }

  case CKA_SENSITIVE:
  case CKA_ALWAYS_SENSITIVE: {
    // Private keys are always sensitive
    CK_BBOOL value = CK_TRUE;
    rv = set_attribute_value(&attribute, &value, sizeof(value));
    break;
  }

  case CKA_EXTRACTABLE: {
    // Private keys on PIV are never extractable
    CK_BBOOL value = CK_FALSE;
    rv = set_attribute_value(&attribute, &value, sizeof(value));
    break;
  }

    // Add other private key attributes as needed

  default:
    rv = CKR_ATTRIBUTE_TYPE_INVALID;
    break;
  }

  return rv;
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                          CK_ULONG ulCount) {
  CNK_RET_UNIMPL;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  CNK_LOG_FUNC(C_FindObjectsInit, ", hSession: %lu, ulCount: %lu\n", hSession, ulCount);

  // Validate the session
  CNK_PKCS11_SESSION *session;
  CK_RV rv = CNK_ENSURE_OK(validate_session(hSession, &session));

  // Lock the session
  cnk_mutex_lock(&session->lock);

  // Check if a find operation is already active
  if (session->find_active) {
    cnk_mutex_unlock(&session->lock);
    return CKR_OPERATION_ACTIVE;
  }

  // Reset find operation state
  session->find_active = CK_TRUE;
  session->find_objects_count = 0;
  session->find_objects_position = 0;
  session->find_id_specified = CK_FALSE;
  session->find_class_specified = CK_FALSE;

  // Parse the template
  for (CK_ULONG i = 0; i < ulCount; i++) {
    if (pTemplate[i].type == CKA_CLASS && pTemplate[i].pValue != NULL &&
        pTemplate[i].ulValueLen == sizeof(CK_OBJECT_CLASS)) {
      session->find_object_class = *((CK_OBJECT_CLASS *)pTemplate[i].pValue);
      session->find_class_specified = CK_TRUE;
    } else if (pTemplate[i].type == CKA_ID && pTemplate[i].pValue != NULL &&
               pTemplate[i].ulValueLen == sizeof(CK_BYTE)) {
      session->find_object_id = *((CK_BYTE *)pTemplate[i].pValue);
      session->find_id_specified = CK_TRUE;
    }
  }

  // If no class is specified, we can't search
  if (!session->find_class_specified) {
    session->find_active = CK_FALSE;
    cnk_mutex_unlock(&session->lock);
    CNK_RET_OK; // Return OK but with no results
  }

  // Check if the specified class is supported
  if (session->find_class_specified && session->find_object_class != CKO_CERTIFICATE &&
      session->find_object_class != CKO_PUBLIC_KEY && session->find_object_class != CKO_PRIVATE_KEY &&
      session->find_object_class != CKO_DATA) {
    session->find_active = CK_FALSE;
    cnk_mutex_unlock(&session->lock);
    CNK_RET_OK; // Return OK but with no results
  }

  // If an ID is specified, we only need to check that specific ID
  if (session->find_id_specified) {
    // Check if the ID is valid (1-6)
    if (session->find_object_id < 1 || session->find_object_id > 6) {
      session->find_active = CK_FALSE;
      cnk_mutex_unlock(&session->lock);
      CNK_RET_OK; // Return OK but with no results
    }

    // Map CKA_ID to PIV tag
    CK_BYTE piv_tag;
    rv = obj_id_to_piv_tag(session->find_object_id, &piv_tag);
    if (rv != CKR_OK) {
      session->find_active = CK_FALSE;
      cnk_mutex_unlock(&session->lock);
      CNK_RET_OK; // Return OK but with no results
    }

    // Try to get the data for this tag
    CK_BYTE_PTR data = NULL;
    CK_ULONG data_len = 0;
    rv = cnk_get_piv_data(session->slot_id, piv_tag, &data, &data_len, CK_FALSE); // Just check existence

    if (rv != CKR_OK) {
      session->find_active = CK_FALSE;
      cnk_mutex_unlock(&session->lock);
      return rv;
    }

    // If data exists, add this object to the results
    if (data_len > 0) {
      // Create a handle for this object: slot_id | object_class | object_id
      // This will allow us to identify the object in future operations
      CK_OBJECT_HANDLE handle =
          (session->slot_id << 16) | ((CK_ULONG)session->find_object_class << 8) | session->find_object_id;
      session->find_objects[session->find_objects_count++] = handle;
      ck_free(data);
    }
  } else {
    // No ID specified, check all possible IDs (1-6)
    for (CK_BYTE id = 1; id <= 6; id++) {
      // Map ID to PIV tag
      CK_BYTE piv_tag;
      if (obj_id_to_piv_tag(id, &piv_tag) != CKR_OK) {
        continue;
      }

      // Try to get the data for this tag
      CK_BYTE_PTR data = NULL;
      CK_ULONG data_len = 0;
      rv = cnk_get_piv_data(session->slot_id, piv_tag, &data, &data_len, CK_FALSE); // Just check existence

      if (rv != CKR_OK) {
        session->find_active = CK_FALSE;
        cnk_mutex_unlock(&session->lock);
        return rv;
      }

      // If data exists, add this object to the results
      if (data_len > 0) {
        // Create a handle for this object: slot_id | object_class | object_id
        CK_OBJECT_HANDLE handle = (session->slot_id << 16) | ((CK_ULONG)session->find_object_class << 8) | id;
        session->find_objects[session->find_objects_count++] = handle;
        ck_free(data);
      }
    }
  }

  cnk_mutex_unlock(&session->lock);
  CNK_RET_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
                    CK_ULONG_PTR pulObjectCount) {
  CNK_LOG_FUNC(C_FindObjects, ", hSession: %lu, ulMaxObjectCount: %lu\n", hSession, ulMaxObjectCount);

  // Check if the library is initialized
  if (!g_cnk_is_initialized)
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  // Validate parameters
  if (!phObject || !pulObjectCount)
    return CKR_ARGUMENTS_BAD;

  // Find the session
  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  // Lock the session
  cnk_mutex_lock(&session->lock);

  // Check if a find operation is active
  if (!session->find_active) {
    cnk_mutex_unlock(&session->lock);
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  // Calculate how many objects to return
  CK_ULONG remaining = session->find_objects_count - session->find_objects_position;
  CK_ULONG count = (remaining < ulMaxObjectCount) ? remaining : ulMaxObjectCount;

  // Copy the object handles
  for (CK_ULONG i = 0; i < count; i++) {
    phObject[i] = session->find_objects[session->find_objects_position + i];
  }

  // Update the position
  session->find_objects_position += count;

  // Return the number of objects copied
  *pulObjectCount = count;

  cnk_mutex_unlock(&session->lock);
  CNK_RET_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
  CNK_LOG_FUNC(C_FindObjectsFinal, ", hSession: %lu\n", hSession);

  // Check if the library is initialized
  if (!g_cnk_is_initialized)
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  // Find the session
  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  // Lock the session
  cnk_mutex_lock(&session->lock);

  // Check if a find operation is active
  if (!session->find_active) {
    cnk_mutex_unlock(&session->lock);
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  // End the find operation
  session->find_active = CK_FALSE;
  session->find_objects_count = 0;
  session->find_objects_position = 0;

  cnk_mutex_unlock(&session->lock);
  CNK_RET_OK;
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
  CNK_LOG_FUNC(C_SignInit, ", hSession: %lu, pMechanism: %lu, hKey: %lu\n", hSession,
               pMechanism ? pMechanism->mechanism : 0, hKey);

  // Validate mechanism
  CNK_ENSURE_NONNULL(pMechanism);

  // Validate session
  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(validate_session(hSession, &session));

  // Validate the key object
  CK_BYTE obj_id;
  CNK_ENSURE_OK(validate_object(hKey, session, CKO_PRIVATE_KEY, &obj_id));

  // Map object ID to PIV tag
  CK_BYTE piv_tag;
  CNK_ENSURE_OK(obj_id_to_piv_tag(obj_id, &piv_tag));

  // Verify that the key matches the mechanism
  CK_BYTE algorithm_type;
  CNK_ENSURE_OK(cnk_get_metadata(session->slot_id, piv_tag, &algorithm_type));

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

  CNK_DEBUG("Setting active_mechanism to %lu, PIV tag %u, algorithm type %u\n", pMechanism->mechanism, piv_tag,
            algorithm_type);

  CNK_RET_OK;
}

// Main C_Sign function
CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
             CK_ULONG_PTR pulSignatureLen) {
  CNK_LOG_FUNC(C_Sign, ", hSession: %lu, ulDataLen: %lu, pSignature: %p, pulSignatureLen: %p\n", hSession, ulDataLen,
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

  CNK_DEBUG("Signing with active key, PIV tag %u, algorithm type %u\n", piv_tag, algorithm_type);

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

  rv = cnk_prepare_rsa_sign_data(mechanism_ptr, pData, ulDataLen, algorithm_type, prepared_data, &prepared_data_len);
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
