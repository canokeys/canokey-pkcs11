#include "pkcs11.h"
#include "canokey.h"
#include "pkcs11_session.h"
#include <stdio.h>
#include <string.h>

// Forward declaration of the function list
static CK_FUNCTION_LIST ck_function_list;

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
  // Check if initialization arguments are provided
  if (pInitArgs != NULL_PTR) {
    // Cast to our custom initialization arguments structure
    CK_INIT_ARGS *args = (CK_INIT_ARGS *)pInitArgs;

    // Set custom memory allocation functions if provided
    if (args->malloc_func != NULL && args->free_func != NULL) {
      g_malloc_func = args->malloc_func;
      g_free_func = args->free_func;
    }

    // Check if we should enter managed mode
    if (args->hSCardCtx != 0 && args->hScard != 0) {
      // Enter managed mode
      g_is_managed_mode = CK_TRUE;
      g_pcsc_context = args->hSCardCtx;
      g_scard = args->hScard;
      g_is_initialized = CK_TRUE;

      // In managed mode, we don't need to initialize PC/SC
      // Initialize the session manager
      return session_manager_init();
    }
  }

  // Standalone mode: Initialize the PC/SC subsystem (just establish context, don't list readers yet)
  CK_RV rv = initialize_pcsc();
  if (rv != CKR_OK) {
    return rv;
  }

  // Initialize the session manager
  return session_manager_init();
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
  // According to PKCS#11, pReserved must be NULL_PTR
  if (pReserved != NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  // Clean up session manager
  session_manager_cleanup();

  // In managed mode, we don't clean up PC/SC resources
  if (g_is_managed_mode) {
    // Reset managed mode variables
    g_is_managed_mode = CK_FALSE;
    g_scard = 0;
    g_is_initialized = CK_FALSE;
    return CKR_OK;
  }

  // Clean up PC/SC resources in standalone mode
  cleanup_pcsc();
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
  CK_RV rv = initialize_pcsc();
  if (rv != CKR_OK)
    return rv;

  // List readers
  rv = list_readers();
  if (rv != CKR_OK)
    return rv;

  // If pSlotList is NULL, just return the number of slots
  if (!pSlotList) {
    *pulCount = g_num_readers;
    return CKR_OK;
  }

  // Check if the provided buffer is large enough
  if (*pulCount < g_num_readers) {
    *pulCount = g_num_readers;
    return CKR_BUFFER_TOO_SMALL;
  }

  // Fill the slot list with the stored slot IDs
  for (CK_ULONG i = 0; i < g_num_readers; i++) {
    pSlotList[i] = g_readers[i].slot_id;
  }

  *pulCount = g_num_readers;
  return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
  if (!pInfo)
    return CKR_ARGUMENTS_BAD;

  // Get firmware version directly (it will handle its own connection)
  CK_BYTE fw_major, fw_minor;
  CK_RV rv = get_version(slotID, 0x00, &fw_major, &fw_minor);
  if (rv != CKR_OK) {
    return rv;
  }

  // Get hardware version
  CK_BYTE hw_major, hw_minor;
  rv = get_version(slotID, 0x01, &hw_major, &hw_minor);
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
  if (!g_is_initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (phSession == NULL) {
    return CKR_ARGUMENTS_BAD;
  }

  return session_open(slotID, flags, pApplication, Notify, phSession);
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
  if (!g_is_initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  return session_close(hSession);
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
  if (!g_is_initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  return session_close_all(slotID);
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
  if (!g_is_initialized) {
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
  PKCS11_SESSION *session;
  CK_RV rv = session_find(hSession, &session);
  if (rv != CKR_OK) {
    return rv;
  }

  // Check if already logged in (PIN is already cached)
  if (session->piv_pin_len > 0) {
    return CKR_USER_ALREADY_LOGGED_IN;
  }

  // Verify the PIN and cache it in the session
  rv = verify_piv_pin_with_session(session->slot_id, session, pPin, ulPinLen);

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
  if (!g_is_initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  // Find the session
  PKCS11_SESSION *session;
  CK_RV rv = session_find(hSession, &session);
  if (rv != CKR_OK) {
    return rv;
  }

  // Check if logged in (PIN is cached)
  if (session->piv_pin_len == 0) {
    return CKR_USER_NOT_LOGGED_IN;
  }
  
  // Send the logout APDU to the card
  rv = logout_piv_pin_with_session(session->slot_id);
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
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
                    CK_ULONG_PTR pulObjectCount) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) { return CKR_FUNCTION_NOT_SUPPORTED; }

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
