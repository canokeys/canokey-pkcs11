#include "logging.h"
#include "pcsc_backend.h"
#include "pkcs11.h"
#include "utils.h"

#include <string.h>

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                            CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pPart: %p, ulPartLen: %lu, pEncryptedPart: %p, pulEncryptedPartLen: %p", hSession,
               pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
  CNK_RET_UNIMPL;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
                            CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pEncryptedPart: %p, ulEncryptedPartLen: %lu, pPart: %p, pulPartLen: %p", hSession,
               pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
  CNK_RET_UNIMPL;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                          CK_ULONG_PTR pulEncryptedPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pPart: %p, ulPartLen: %lu, pEncryptedPart: %p, pulEncryptedPartLen: %p", hSession,
               pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
  CNK_RET_UNIMPL;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
                            CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pEncryptedPart: %p, ulEncryptedPartLen: %lu, pPart: %p, pulPartLen: %p", hSession,
               pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
  CNK_RET_UNIMPL;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate,
                    CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, pTemplate: %p, ulCount: %lu, phKey: %p", hSession, pMechanism,
               pTemplate, ulCount, phKey);
  CNK_RET_UNIMPL;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                        CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                        CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey,
                        CK_OBJECT_HANDLE_PTR phPrivateKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, pPublicKeyTemplate: %p, ulPublicKeyAttributeCount: %lu, "
               "pPrivateKeyTemplate: %p, ulPrivateKeyAttributeCount: %lu, phPublicKey: %p, phPrivateKey: %p",
               hSession, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate,
               ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey);
  CNK_RET_UNIMPL;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey,
                CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, hWrappingKey: %lu, hKey: %lu, pWrappedKey: %p, pulWrappedKeyLen: %p",
               hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen);
  CNK_RET_UNIMPL;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey,
                  CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, hUnwrappingKey: %lu, pWrappedKey: %p, ulWrappedKeyLen: %lu, "
               "pTemplate: %p, ulAttributeCount: %lu, phKey: %p",
               hSession, pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen, pTemplate, ulAttributeCount, phKey);
  CNK_RET_UNIMPL;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey,
                  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, hBaseKey: %lu, pTemplate: %p, ulAttributeCount: %lu, phKey: %p",
               hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey);
  CNK_RET_UNIMPL;
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
  CNK_LOG_FUNC(": hSession: %lu, pSeed: %p, ulSeedLen: %lu", hSession, pSeed, ulSeedLen);
  CNK_RET_UNIMPL;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {
  CNK_LOG_FUNC(": hSession: %lu, pRandomData: %p, ulRandomLen: %lu", hSession, pRandomData, ulRandomLen);
  CNK_RET_UNIMPL;
}
