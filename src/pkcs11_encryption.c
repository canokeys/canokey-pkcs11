#include "logging.h"
#include "pcsc_backend.h"
#include "pkcs11.h"
#include "utils.h"

#include <string.h>

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, hKey: %lu", hSession, pMechanism, hKey);
  CNK_RET_UNIMPL;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
                CK_ULONG_PTR pulEncryptedDataLen) {
  CNK_LOG_FUNC(": hSession: %lu, pData: %p, ulDataLen: %lu, pEncryptedData: %p, pulEncryptedDataLen: %p", hSession,
               pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);
  CNK_RET_UNIMPL;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                      CK_ULONG_PTR pulEncryptedPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pPart: %p, ulPartLen: %lu, pEncryptedPart: %p, pulEncryptedPartLen: %p", hSession,
               pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
  CNK_RET_UNIMPL;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pLastEncryptedPart: %p, pulLastEncryptedPartLen: %p", hSession, pLastEncryptedPart,
               pulLastEncryptedPartLen);
  CNK_RET_UNIMPL;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, hKey: %lu", hSession, pMechanism, hKey);
  CNK_RET_UNIMPL;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
                CK_ULONG_PTR pulDataLen) {
  CNK_LOG_FUNC(": hSession: %lu, pEncryptedData: %p, ulEncryptedDataLen: %lu, pData: %p, pulDataLen: %p", hSession,
               pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);
  CNK_RET_UNIMPL;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
                      CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pEncryptedPart: %p, ulEncryptedPartLen: %lu, pPart: %p, pulPartLen: %p", hSession,
               pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
  CNK_RET_UNIMPL;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pLastPart: %p, pulLastPartLen: %p", hSession, pLastPart, pulLastPartLen);
  CNK_RET_UNIMPL;
}
