#define CRYPTOKI_EXPORTS

#include "logging.h"
#include "pcsc_backend.h"
#include "pkcs11.h"
#include "pkcs11_canokey.h"
#include "pkcs11_mutex.h"
#include "pkcs11_session.h"

#include <stdio.h>
#include <string.h>

// Forward declaration of the function list
static CK_FUNCTION_LIST ck_function_list;

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
#ifdef CNK_VERBOSE
  // forcibly enable debug logging, can be overridden by C_CNK_ConfigLogging later
  C_CNK_ConfigLogging(CNK_LOG_LEVEL_DEBUG, NULL);
#endif

  CNK_DEBUG("C_Initialize called with pInitArgs: %p", pInitArgs);

  // Check if the library is already initialized
  if (g_cnk_is_initialized)
    return CKR_CRYPTOKI_ALREADY_INITIALIZED;

  // Process the initialization arguments
  CK_RV mutex_rv;

  if (pInitArgs == NULL_PTR) {
    // NULL argument is treated as a pointer to a CK_C_INITIALIZE_ARGS structure
    // with all fields set to NULL (single-threaded mode)
    mutex_rv = cnk_mutex_system_init(NULL);
    if (mutex_rv != CKR_OK) {
      CNK_RETURN(CKR_CANT_LOCK, "cannot init mutex");
    }
  } else {
    CK_C_INITIALIZE_ARGS_PTR args = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;

    // Check for reserved field - must be NULL according to PKCS#11
    if (args->pReserved != NULL_PTR)
      CNK_RETURN(CKR_ARGUMENTS_BAD, "pReserved not NULL");

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
        // the application won’t be accessing the Cryptoki library from multiple
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
    CK_RV rv = cnk_initialize_pcsc();
    if (rv != CKR_OK) {
      CNK_RETURN(rv, "cannot initialize PC/SC");
    }
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
  // According to PKCS#11, pReserved must be NULL_PTR
  if (pReserved != NULL_PTR)
    return CKR_ARGUMENTS_BAD;

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
    return CKR_OK;
  }

  // Clean up PC/SC resources in standalone mode
  cnk_cleanup_pcsc();
  g_cnk_is_initialized = CK_FALSE;
  return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo) { return CKR_FUNCTION_NOT_SUPPORTED; }

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
  if (ppFunctionList == NULL_PTR)
    return CKR_ARGUMENTS_BAD;
  *ppFunctionList = &ck_function_list;
  return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
  // Parameter validation
  if (!pulCount)
    return CKR_ARGUMENTS_BAD;

  // Initialize PC/SC if not already initialized
  CK_RV rv = cnk_initialize_pcsc();
  if (rv != CKR_OK)
    return rv;

  // List readers
  rv = cnk_list_readers();
  if (rv != CKR_OK)
    return rv;

  // If pSlotList is NULL, just return the number of slots
  if (!pSlotList) {
    *pulCount = g_cnk_num_readers;
    return CKR_OK;
  }

  // Check if the provided buffer is large enough
  if (*pulCount < g_cnk_num_readers) {
    *pulCount = g_cnk_num_readers;
    return CKR_BUFFER_TOO_SMALL;
  }

  // Fill the slot list with the stored slot IDs
  for (CK_ULONG i = 0; i < g_cnk_num_readers; i++) {
    pSlotList[i] = g_cnk_readers[i].slot_id;
  }

  *pulCount = g_cnk_num_readers;
  return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
  if (!pInfo)
    return CKR_ARGUMENTS_BAD;

  // Get firmware version directly (it will handle its own connection)
  CK_BYTE fw_major, fw_minor;
  CK_RV rv = cnk_get_version(slotID, 0x00, &fw_major, &fw_minor);
  if (rv != CKR_OK) {
    return rv;
  }

  // Get hardware version
  CK_BYTE hw_major, hw_minor;
  rv = cnk_get_version(slotID, 0x01, &hw_major, &hw_minor);
  if (rv != CKR_OK) {
    return rv;
  }

  // Fill in the slot info structure
  memset(pInfo, 0, sizeof(CK_SLOT_INFO));

  // Set the slot description
  char desc[64];
  snprintf(desc, sizeof(desc), "CanoKey (FW: %d.%d, HW: %d.%d)", fw_major, fw_minor, hw_major, hw_minor);
  memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
  memcpy(pInfo->slotDescription, desc,
         strlen(desc) > sizeof(pInfo->slotDescription) ? sizeof(pInfo->slotDescription) : strlen(desc));

  // Set the manufacturer ID
  memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
  const char *manufacturer = "canokeys.org";
  memcpy(pInfo->manufacturerID, manufacturer,
         strlen(manufacturer) > sizeof(pInfo->manufacturerID) ? sizeof(pInfo->manufacturerID) : strlen(manufacturer));

  // Set flags
  pInfo->flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT | CKF_TOKEN_PRESENT;

  // Set hardware version
  pInfo->hardwareVersion.major = hw_major;
  pInfo->hardwareVersion.minor = hw_minor;

  // Set firmware version
  pInfo->firmwareVersion.major = fw_major;
  pInfo->firmwareVersion.minor = fw_minor;

  return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) { return CKR_FUNCTION_NOT_SUPPORTED; }

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin,
               CK_ULONG ulNewLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify,
                    CK_SESSION_HANDLE_PTR phSession) {
  if (!g_cnk_is_initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (phSession == NULL) {
    return CKR_ARGUMENTS_BAD;
  }

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

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) { return CKR_FUNCTION_NOT_SUPPORTED; }

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen,
                          CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
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
  CK_RV rv = cnk_session_find(hSession, &session);
  if (rv != CKR_OK) {
    return rv;
  }

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
  // Check if the cryptoki library is initialized
  if (!g_cnk_is_initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  // Find the session
  CNK_PKCS11_SESSION *session;
  CK_RV rv = cnk_session_find(hSession, &session);
  if (rv != CKR_OK) {
    return rv;
  }

  // Check if logged in (PIN is cached)
  if (session->piv_pin_len == 0) {
    return CKR_USER_NOT_LOGGED_IN;
  }

  // Send the logout APDU to the card
  rv = cnk_logout_piv_pin_with_session(session->slot_id);
  if (rv != CKR_OK) {
    // Even if the card logout fails, we still clear the cached PIN
    // to maintain consistent state in the session
  }

  // Clear the cached PIN
  memset(session->piv_pin, 0xFF, sizeof(session->piv_pin));
  session->piv_pin_len = 0;

  // Reset session state based on session type
  if (session->flags & CKF_RW_SESSION) {
    session->state = SESSION_STATE_RW_PUBLIC;
  } else {
    session->state = SESSION_STATE_RO_PUBLIC;
  }

  return CKR_OK;
}

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                     CK_OBJECT_HANDLE_PTR phObject) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                   CK_OBJECT_HANDLE_PTR phNewObject) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) { return CKR_FUNCTION_NOT_SUPPORTED; }

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                          CK_ULONG ulCount) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                          CK_ULONG ulCount) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  // Check if the library is initialized
  if (!g_cnk_is_initialized)
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  // Find the session
  CNK_PKCS11_SESSION *session;
  CK_RV rv = cnk_session_find(hSession, &session);
  if (rv != CKR_OK)
    return rv;

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
    return CKR_OK; // Return OK but with no results
  }

  // Check if the specified class is supported
  if (session->find_class_specified && session->find_object_class != CKO_CERTIFICATE &&
      session->find_object_class != CKO_PUBLIC_KEY && session->find_object_class != CKO_PRIVATE_KEY &&
      session->find_object_class != CKO_DATA) {
    session->find_active = CK_FALSE;
    cnk_mutex_unlock(&session->lock);
    return CKR_OK; // Return OK but with no results
  }

  // If an ID is specified, we only need to check that specific ID
  if (session->find_id_specified) {
    // Check if the ID is valid (1-6)
    if (session->find_object_id < 1 || session->find_object_id > 6) {
      session->find_active = CK_FALSE;
      cnk_mutex_unlock(&session->lock);
      return CKR_OK; // Return OK but with no results
    }

    // Map CKA_ID to PIV tag
    CK_BYTE piv_tag;
    switch (session->find_object_id) {
    case PIV_SLOT_9A:
      piv_tag = 0x9A;
      break;
    case PIV_SLOT_9C:
      piv_tag = 0x9C;
      break;
    case PIV_SLOT_9D:
      piv_tag = 0x9D;
      break;
    case PIV_SLOT_9E:
      piv_tag = 0x9E;
      break;
    case PIV_SLOT_82:
      piv_tag = 0x82;
      break;
    case PIV_SLOT_83:
      piv_tag = 0x83;
      break;
    default:
      session->find_active = CK_FALSE;
      cnk_mutex_unlock(&session->lock);
      return CKR_OK; // Return OK but with no results
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
      switch (id) {
      case PIV_SLOT_9A:
        piv_tag = 0x9A;
        break;
      case PIV_SLOT_9C:
        piv_tag = 0x9C;
        break;
      case PIV_SLOT_9D:
        piv_tag = 0x9D;
        break;
      case PIV_SLOT_9E:
        piv_tag = 0x9E;
        break;
      case PIV_SLOT_82:
        piv_tag = 0x82;
        break;
      case PIV_SLOT_83:
        piv_tag = 0x83;
        break;
      default:
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
  return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
                    CK_ULONG_PTR pulObjectCount) {
  // Check if the library is initialized
  if (!g_cnk_is_initialized)
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  // Validate parameters
  if (!phObject || !pulObjectCount)
    return CKR_ARGUMENTS_BAD;

  // Find the session
  CNK_PKCS11_SESSION *session;
  CK_RV rv = cnk_session_find(hSession, &session);
  if (rv != CKR_OK)
    return rv;

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
  return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
  // Check if the library is initialized
  if (!g_cnk_is_initialized)
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  // Find the session
  CNK_PKCS11_SESSION *session;
  CK_RV rv = cnk_session_find(hSession, &session);
  if (rv != CKR_OK)
    return rv;

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
  return CKR_OK;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
                CK_ULONG_PTR pulEncryptedDataLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                      CK_ULONG_PTR pulEncryptedPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
                CK_ULONG_PTR pulDataLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
                      CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) { return CKR_FUNCTION_NOT_SUPPORTED; }

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
               CK_ULONG_PTR pulDigestLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) { return CKR_FUNCTION_NOT_SUPPORTED; }

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
             CK_ULONG_PTR pulSignatureLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                    CK_ULONG_PTR pulSignatureLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
               CK_ULONG ulSignatureLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData,
                      CK_ULONG_PTR pulDataLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                            CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
                            CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                          CK_ULONG_PTR pulEncryptedPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
                            CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate,
                    CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                        CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                        CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey,
                        CK_OBJECT_HANDLE_PTR phPrivateKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey,
                CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey,
                  CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey,
                  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession) { return CKR_FUNCTION_NOT_SUPPORTED; }

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession) { return CKR_FUNCTION_NOT_SUPPORTED; }

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved) {
  return CKR_FUNCTION_NOT_SUPPORTED;
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
