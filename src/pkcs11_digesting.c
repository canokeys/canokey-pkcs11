#include "logging.h"
#include "pcsc_backend.h"
#include "pkcs11.h"
#include "pkcs11_macros.h"
#include "pkcs11_session.h"
#include "utils.h"
#include <mbedtls/md.h>
#include <string.h>

static size_t get_md_size(CK_MECHANISM_TYPE mechanism) {
  switch (mechanism) {
  case CKM_SHA_1:
    return 20;
  case CKM_SHA224:
    return 28;
  case CKM_SHA256:
    return 32;
  case CKM_SHA384:
    return 48;
  case CKM_SHA512:
    return 64;
  case CKM_SHA3_224:
    return 28;
  case CKM_SHA3_256:
    return 32;
  case CKM_SHA3_384:
    return 48;
  case CKM_SHA3_512:
    return 64;
  default:
    return 0;
  }
}

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p", hSession, pMechanism);

  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pMechanism);

  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  mbedtls_md_type_t md_type;
  switch (pMechanism->mechanism) {
  case CKM_SHA_1:
    md_type = MBEDTLS_MD_SHA1;
    break;
  case CKM_SHA224:
    md_type = MBEDTLS_MD_SHA224;
    break;
  case CKM_SHA256:
    md_type = MBEDTLS_MD_SHA256;
    break;
  case CKM_SHA384:
    md_type = MBEDTLS_MD_SHA384;
    break;
  case CKM_SHA512:
    md_type = MBEDTLS_MD_SHA512;
    break;
  case CKM_SHA3_224:
    md_type = MBEDTLS_MD_SHA3_224;
    break;
  case CKM_SHA3_256:
    md_type = MBEDTLS_MD_SHA3_256;
    break;
  case CKM_SHA3_384:
    md_type = MBEDTLS_MD_SHA3_384;
    break;
  case CKM_SHA3_512:
    md_type = MBEDTLS_MD_SHA3_512;
    break;
  default:
    CNK_RETURN(CKR_MECHANISM_INVALID, "unsupported mechanism");
  }

  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
  if (!md_info)
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "invalid md_info");

  mbedtls_md_init(&session->digest_ctx);
  if (mbedtls_md_setup(&session->digest_ctx, md_info, 0) != 0)
    CNK_RETURN(CKR_HOST_MEMORY, "md setup failed");
  if (mbedtls_md_starts(&session->digest_ctx) != 0)
    CNK_RETURN(CKR_FUNCTION_FAILED, "md start failed");
  session->digest_mech = pMechanism->mechanism;
  session->digest_active = CK_TRUE;

  CNK_RET_OK;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
               CK_ULONG_PTR pulDigestLen) {
  CNK_LOG_FUNC(": hSession: %lu, ulDataLen: %lu, pDigest: %p, pulDigestLen: %p", hSession, ulDataLen, pDigest,
               pulDigestLen);
  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pulDigestLen);

  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  if (pDigest == NULL) {
    size_t length = get_md_size(session->digest_mech);
    if (length == 0)
      CNK_RETURN(CKR_MECHANISM_INVALID, "unsupported mechanism");
    *pulDigestLen = length;
    CNK_RET_OK;
  }

  if (ulDataLen > 0) {
    CK_RV rv = C_DigestUpdate(hSession, pData, ulDataLen);
    if (rv != CKR_OK)
      return rv;
  }

  return C_DigestFinal(hSession, pDigest, pulDigestLen);
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pPart: %p, ulPartLen: %lu", hSession, pPart, ulPartLen);
  CNK_ENSURE_INITIALIZED();

  if (!pPart && ulPartLen > 0)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "pPart is NULL but ulPartLen > 0");

  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  if (!session->digest_active)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_DigestInit not called");

  if (mbedtls_md_update(&session->digest_ctx, pPart, ulPartLen) != 0)
    CNK_RETURN(CKR_FUNCTION_FAILED, "md update failed");

  CNK_RET_OK;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
  CNK_LOG_FUNC(": hSession: %lu, hKey: %lu", hSession, hKey);
  CNK_RET_UNIMPL;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
  CNK_LOG_FUNC(": hSession: %lu, pDigest: %p, pulDigestLen: %p", hSession, pDigest, pulDigestLen);
  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pulDigestLen);

  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  if (!session->digest_active)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_DigestInit not called");

  size_t hash_len = get_md_size(session->digest_mech);
  if (pDigest == NULL) {
    *pulDigestLen = hash_len;
    CNK_RET_OK;
  }
  if (*pulDigestLen < hash_len) {
    *pulDigestLen = hash_len;
    CNK_RETURN(CKR_BUFFER_TOO_SMALL, "buffer too small");
  }
  if (mbedtls_md_finish(&session->digest_ctx, pDigest) != 0)
    CNK_RETURN(CKR_FUNCTION_FAILED, "md finish failed");
  *pulDigestLen = hash_len;
  mbedtls_md_free(&session->digest_ctx);
  session->digest_active = CK_FALSE;

  CNK_RET_OK;
}
