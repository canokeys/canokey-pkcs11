#include "api/object.h"
#include "api/session.h"
#include "backend/pcsc.h"
#include "internal/crypto.h"
#include "internal/logging.h"
#include "internal/macros.h"
#include "internal/util.h"
#include "pkcs11.h"
#include <mbedtls/md.h>
#include <string.h>

static size_t get_md_size(CK_MECHANISM_TYPE mechanism) {
  mbedtls_md_type_t md_type;
  if (cnk_hash_mech_to_md(mechanism, &md_type) != CKR_OK)
    return 0;

  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
  if (md_info == NULL)
    return 0;

  return mbedtls_md_get_size(md_info);
}

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p", hSession, pMechanism);

  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pMechanism);

  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (session->digestingContext.mechanismType != 0)
    CNK_RETURN(CKR_OPERATION_ACTIVE, "digest operation is already active");

  mbedtls_md_type_t md_type;
  CNK_ENSURE_OK(cnk_hash_mech_to_md(pMechanism->mechanism, &md_type));

  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
  if (!md_info)
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "invalid md_info");

  mbedtls_md_init(&session->digestingContext.context);
  if (mbedtls_md_setup(&session->digestingContext.context, md_info, 0) != 0) {
    mbedtls_md_free(&session->digestingContext.context);
    CNK_RETURN(CKR_HOST_MEMORY, "md setup failed");
  }
  if (mbedtls_md_starts(&session->digestingContext.context) != 0) {
    mbedtls_md_free(&session->digestingContext.context);
    CNK_RETURN(CKR_FUNCTION_FAILED, "md start failed");
  }
  session->digestingContext.mechanismType = pMechanism->mechanism;

  CNK_RET_OK;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
               CK_ULONG_PTR pulDigestLen) {
  CNK_LOG_FUNC(": hSession: %lu, ulDataLen: %lu, pDigest: %p, pulDigestLen: %p", hSession, ulDataLen, pDigest,
               pulDigestLen);
  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pulDigestLen);

  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (session->digestingContext.mechanismType == 0)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_DigestInit not called");
  if (pData == NULL && ulDataLen > 0) {
    mbedtls_md_free(&session->digestingContext.context);
    memset(&session->digestingContext, 0, sizeof(session->digestingContext));
    CNK_RETURN(CKR_ARGUMENTS_BAD, "pData is NULL but ulDataLen > 0");
  }

  if (pDigest == NULL) {
    size_t length = get_md_size(session->digestingContext.mechanismType);
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

  if (session->digestingContext.mechanismType == 0)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_DigestInit not called");

  if (mbedtls_md_update(&session->digestingContext.context, pPart, ulPartLen) != 0)
    CNK_RETURN(CKR_FUNCTION_FAILED, "md update failed");

  CNK_RET_OK;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
  CNK_LOG_FUNC(": hSession: %lu, hKey: %lu", hSession, hKey);
  CNK_ENSURE_INITIALIZED();

  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (session->digestingContext.mechanismType == 0)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_DigestInit not called");

  CNK_PKCS11_SECRET_KEY_OBJECT *secret;
  CNK_ENSURE_OK(CNK_GetSessionSecretKey(session, hKey, &secret));
  if (secret->sensitive)
    CNK_RETURN(CKR_KEY_INDIGESTIBLE, "Sensitive session key cannot be digested");
  if (secret->private && !cnk_token_pin_is_cached(session))
    CNK_RETURN(CKR_USER_NOT_LOGGED_IN, "Private session key requires USER login");

  if (mbedtls_md_update(&session->digestingContext.context, secret->value, secret->valueLen) != 0)
    CNK_RETURN(CKR_FUNCTION_FAILED, "md update failed");
  CNK_RET_OK;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
  CNK_LOG_FUNC(": hSession: %lu, pDigest: %p, pulDigestLen: %p", hSession, pDigest, pulDigestLen);
  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pulDigestLen);

  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  if (session->digestingContext.mechanismType == 0)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_DigestInit not called");

  size_t hash_len = get_md_size(session->digestingContext.mechanismType);
  if (pDigest == NULL) {
    *pulDigestLen = hash_len;
    CNK_RET_OK;
  }
  if (*pulDigestLen < hash_len) {
    *pulDigestLen = hash_len;
    CNK_RETURN(CKR_BUFFER_TOO_SMALL, "buffer too small");
  }
  if (mbedtls_md_finish(&session->digestingContext.context, pDigest) != 0) {
    mbedtls_md_free(&session->digestingContext.context);
    memset(&session->digestingContext, 0, sizeof(session->digestingContext));
    CNK_RETURN(CKR_FUNCTION_FAILED, "md finish failed");
  }
  *pulDigestLen = hash_len;
  mbedtls_md_free(&session->digestingContext.context);
  session->digestingContext.mechanismType = 0;

  CNK_RET_OK;
}
