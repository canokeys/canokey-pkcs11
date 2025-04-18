#include "logging.h"
#include "pcsc_backend.h"
#include "pkcs11.h"
#include "utils.h"

#include <string.h>

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p", hSession, pMechanism);
  CNK_RET_UNIMPL;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
               CK_ULONG_PTR pulDigestLen) {
  CNK_LOG_FUNC(": hSession: %lu, pData: %p, ulDataLen: %lu, pDigest: %p, pulDigestLen: %p", hSession, pData, ulDataLen,
               pDigest, pulDigestLen);
  CNK_RET_UNIMPL;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pPart: %p, ulPartLen: %lu", hSession, pPart, ulPartLen);
  CNK_RET_UNIMPL;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
  CNK_LOG_FUNC(": hSession: %lu, hKey: %lu", hSession, hKey);
  CNK_RET_UNIMPL;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
  CNK_LOG_FUNC(": hSession: %lu, pDigest: %p, pulDigestLen: %p", hSession, pDigest, pulDigestLen);
  CNK_RET_UNIMPL;
}
