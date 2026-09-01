#include "api/session.h"
#include "backend/pcsc.h"
#include "internal/macros.h"
#include "internal/util.h"
#include "pkcs11.h"

CK_RV C_LoginUser(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
                  CK_UTF8CHAR_PTR pUsername, CK_ULONG ulUsernameLen) {
  if (pUsername != NULL || ulUsernameLen != 0)
    return CKR_ARGUMENTS_BAD;
  return C_Login(hSession, userType, pPin, ulPinLen);
}

CK_RV C_SessionCancel(CK_SESSION_HANDLE hSession, CK_FLAGS flags) {
  CNK_ENSURE_INITIALIZED();
  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  return cnk_session_cancel_operations(session, flags);
}

#define CNK_V3_UNSUPPORTED()                                                                                           \
  do {                                                                                                                 \
    CNK_RET_UNSUPPORTED;                                                                                               \
  } while (0)

CK_RV C_MessageEncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  (void)hSession;
  (void)pMechanism;
  (void)hKey;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_EncryptMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
                       CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pPlaintext,
                       CK_ULONG ulPlaintextLen, CK_BYTE_PTR pCiphertext, CK_ULONG_PTR pulCiphertextLen) {
  (void)hSession;
  (void)pParameter;
  (void)ulParameterLen;
  (void)pAssociatedData;
  (void)ulAssociatedDataLen;
  (void)pPlaintext;
  (void)ulPlaintextLen;
  (void)pCiphertext;
  (void)pulCiphertextLen;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_EncryptMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
                            CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen) {
  (void)hSession;
  (void)pParameter;
  (void)ulParameterLen;
  (void)pAssociatedData;
  (void)ulAssociatedDataLen;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_EncryptMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
                           CK_BYTE_PTR pPlaintextPart, CK_ULONG ulPlaintextPartLen, CK_BYTE_PTR pCiphertextPart,
                           CK_ULONG_PTR pulCiphertextPartLen, CK_FLAGS flags) {
  (void)hSession;
  (void)pParameter;
  (void)ulParameterLen;
  (void)pPlaintextPart;
  (void)ulPlaintextPartLen;
  (void)pCiphertextPart;
  (void)pulCiphertextPartLen;
  (void)flags;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_MessageEncryptFinal(CK_SESSION_HANDLE hSession) {
  (void)hSession;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_MessageDecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  (void)hSession;
  (void)pMechanism;
  (void)hKey;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_DecryptMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
                       CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pCiphertext,
                       CK_ULONG ulCiphertextLen, CK_BYTE_PTR pPlaintext, CK_ULONG_PTR pulPlaintextLen) {
  (void)hSession;
  (void)pParameter;
  (void)ulParameterLen;
  (void)pAssociatedData;
  (void)ulAssociatedDataLen;
  (void)pCiphertext;
  (void)ulCiphertextLen;
  (void)pPlaintext;
  (void)pulPlaintextLen;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_DecryptMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
                            CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen) {
  (void)hSession;
  (void)pParameter;
  (void)ulParameterLen;
  (void)pAssociatedData;
  (void)ulAssociatedDataLen;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_DecryptMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
                           CK_BYTE_PTR pCiphertextPart, CK_ULONG ulCiphertextPartLen, CK_BYTE_PTR pPlaintextPart,
                           CK_ULONG_PTR pulPlaintextPartLen, CK_FLAGS flags) {
  (void)hSession;
  (void)pParameter;
  (void)ulParameterLen;
  (void)pCiphertextPart;
  (void)ulCiphertextPartLen;
  (void)pPlaintextPart;
  (void)pulPlaintextPartLen;
  (void)flags;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_MessageDecryptFinal(CK_SESSION_HANDLE hSession) {
  (void)hSession;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_MessageSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  (void)hSession;
  (void)pMechanism;
  (void)hKey;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_SignMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData,
                    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
  (void)hSession;
  (void)pParameter;
  (void)ulParameterLen;
  (void)pData;
  (void)ulDataLen;
  (void)pSignature;
  (void)pulSignatureLen;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_SignMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen) {
  (void)hSession;
  (void)pParameter;
  (void)ulParameterLen;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_SignMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData,
                        CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
  (void)hSession;
  (void)pParameter;
  (void)ulParameterLen;
  (void)pData;
  (void)ulDataLen;
  (void)pSignature;
  (void)pulSignatureLen;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_MessageSignFinal(CK_SESSION_HANDLE hSession) {
  (void)hSession;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_MessageVerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  (void)hSession;
  (void)pMechanism;
  (void)hKey;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_VerifyMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData,
                      CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
  (void)hSession;
  (void)pParameter;
  (void)ulParameterLen;
  (void)pData;
  (void)ulDataLen;
  (void)pSignature;
  (void)ulSignatureLen;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_VerifyMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen) {
  (void)hSession;
  (void)pParameter;
  (void)ulParameterLen;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_VerifyMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
                          CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
  (void)hSession;
  (void)pParameter;
  (void)ulParameterLen;
  (void)pData;
  (void)ulDataLen;
  (void)pSignature;
  (void)ulSignatureLen;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_MessageVerifyFinal(CK_SESSION_HANDLE hSession) {
  (void)hSession;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_VerifySignatureInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey,
                            CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
  (void)hSession;
  (void)pMechanism;
  (void)hKey;
  (void)pSignature;
  (void)ulSignatureLen;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_VerifySignature(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen) {
  (void)hSession;
  (void)pData;
  (void)ulDataLen;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_VerifySignatureUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  (void)hSession;
  (void)pPart;
  (void)ulPartLen;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_VerifySignatureFinal(CK_SESSION_HANDLE hSession) {
  (void)hSession;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_GetSessionValidationFlags(CK_SESSION_HANDLE hSession, CK_SESSION_VALIDATION_FLAGS_TYPE type,
                                  CK_FLAGS_PTR pFlags) {
  (void)hSession;
  (void)type;
  (void)pFlags;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_AsyncComplete(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName, CK_ASYNC_DATA_PTR pResult) {
  (void)hSession;
  (void)pFunctionName;
  (void)pResult;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_AsyncGetID(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName, CK_ULONG_PTR pulID) {
  (void)hSession;
  (void)pFunctionName;
  (void)pulID;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_AsyncJoin(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName, CK_ULONG ulID, CK_BYTE_PTR pData,
                  CK_ULONG ulData) {
  (void)hSession;
  (void)pFunctionName;
  (void)ulID;
  (void)pData;
  (void)ulData;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_WrapKeyAuthenticated(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey,
                             CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen,
                             CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
  (void)hSession;
  (void)pMechanism;
  (void)hWrappingKey;
  (void)hKey;
  (void)pAssociatedData;
  (void)ulAssociatedDataLen;
  (void)pWrappedKey;
  (void)pulWrappedKeyLen;
  CNK_V3_UNSUPPORTED();
}

CK_RV C_UnwrapKeyAuthenticated(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey,
                               CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
                               CK_ULONG ulAttributeCount, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen,
                               CK_OBJECT_HANDLE_PTR phKey) {
  (void)hSession;
  (void)pMechanism;
  (void)hUnwrappingKey;
  (void)pWrappedKey;
  (void)ulWrappedKeyLen;
  (void)pTemplate;
  (void)ulAttributeCount;
  (void)pAssociatedData;
  (void)ulAssociatedDataLen;
  (void)phKey;
  CNK_V3_UNSUPPORTED();
}

#undef CNK_V3_UNSUPPORTED
