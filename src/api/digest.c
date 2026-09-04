#include "api/object.h"
#include "api/operation.h"
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

static CK_RV digestUpdate(CNK_PKCS11_SESSION *session, CK_BYTE_PTR part, CK_ULONG partLen) {
  if (session->digestingContext.mechanismType == 0)
    return CKR_OPERATION_NOT_INITIALIZED;
  if (mbedtls_md_update(&session->digestingContext.context, part, partLen) != 0) {
    cnk_reset_digesting_context(session);
    return CKR_FUNCTION_FAILED;
  }
  session->digestingContext.mode = CNK_DIGEST_MODE_MULTI_PART;
  return CKR_OK;
}

static CK_RV digestFinal(CNK_PKCS11_SESSION *session, CK_BYTE_PTR digest, CK_ULONG_PTR digestLen) {
  if (session->digestingContext.mechanismType == 0)
    return CKR_OPERATION_NOT_INITIALIZED;
  size_t hashLen = get_md_size(session->digestingContext.mechanismType);
  if (digest == NULL) {
    *digestLen = hashLen;
    return CKR_OK;
  }
  if (*digestLen < hashLen) {
    *digestLen = hashLen;
    return CKR_BUFFER_TOO_SMALL;
  }
  if (mbedtls_md_finish(&session->digestingContext.context, digest) != 0) {
    cnk_reset_digesting_context(session);
    return CKR_FUNCTION_FAILED;
  }
  *digestLen = hashLen;
  cnk_reset_digesting_context(session);
  return CKR_OK;
}

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p", hSession, pMechanism);

  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pMechanism);

  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  CNK_PKCS11_MUTEX_GUARD sessionLock CNK_MUTEX_GUARD = {.mutex = &session->lock};
  CNK_ENSURE_OK(cnk_mutex_lock_guard(&sessionLock));
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
  CNK_ENSURE_INITIALIZED();

  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  CNK_PKCS11_MUTEX_GUARD sessionLock CNK_MUTEX_GUARD = {.mutex = &session->lock};
  CNK_ENSURE_OK(cnk_mutex_lock_guard(&sessionLock));
  if (session->digestingContext.mechanismType == 0)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_DigestInit not called");
  if (pulDigestLen == NULL) {
    cnk_reset_digesting_context(session);
    CNK_RETURN(CKR_ARGUMENTS_BAD, "pulDigestLen is NULL");
  }
  if (session->digestingContext.mode == CNK_DIGEST_MODE_MULTI_PART) {
    cnk_reset_digesting_context(session);
    CNK_RETURN(CKR_OPERATION_ACTIVE, "C_Digest cannot terminate a multi-part digest");
  }
  if (pData == NULL && ulDataLen > 0) {
    cnk_reset_digesting_context(session);
    CNK_RETURN(CKR_ARGUMENTS_BAD, "pData is NULL but ulDataLen > 0");
  }

  session->digestingContext.mode = CNK_DIGEST_MODE_SINGLE_PART;

  // Check the destination before consuming input so CKR_BUFFER_TOO_SMALL
  // preserves the exact digest state for a retry.
  if (pDigest != NULL) {
    size_t hashLen = get_md_size(session->digestingContext.mechanismType);
    if (hashLen == 0)
      CNK_RETURN(CKR_MECHANISM_INVALID, "unsupported mechanism");
    if (*pulDigestLen < hashLen) {
      *pulDigestLen = hashLen;
      return CKR_BUFFER_TOO_SMALL;
    }
  }

  if (pDigest == NULL) {
    size_t length = get_md_size(session->digestingContext.mechanismType);
    if (length == 0)
      CNK_RETURN(CKR_MECHANISM_INVALID, "unsupported mechanism");
    *pulDigestLen = length;
    CNK_RET_OK;
  }

  if (ulDataLen > 0) {
    CK_RV rv = digestUpdate(session, pData, ulDataLen);
    if (rv != CKR_OK)
      return rv;
  }

  return digestFinal(session, pDigest, pulDigestLen);
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pPart: %p, ulPartLen: %lu", hSession, pPart, ulPartLen);
  CNK_ENSURE_INITIALIZED();

  if (!pPart && ulPartLen > 0)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "pPart is NULL but ulPartLen > 0");

  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  CNK_PKCS11_MUTEX_GUARD sessionLock CNK_MUTEX_GUARD = {.mutex = &session->lock};
  CNK_ENSURE_OK(cnk_mutex_lock_guard(&sessionLock));

  return digestUpdate(session, pPart, ulPartLen);
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
  CNK_LOG_FUNC(": hSession: %lu, hKey: %lu", hSession, hKey);
  CNK_ENSURE_INITIALIZED();

  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  CNK_PKCS11_MUTEX_GUARD sessionLock CNK_MUTEX_GUARD = {.mutex = &session->lock};
  CNK_ENSURE_OK(cnk_mutex_lock_guard(&sessionLock));
  if (session->digestingContext.mechanismType == 0)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_DigestInit not called");

  CNK_PKCS11_SECRET_KEY_OBJECT *secret;
  CNK_ENSURE_OK(CNK_GetSessionSecretKey(session, hKey, &secret));
  // Digesting a sensitive key would expose a stable value-derived identifier;
  // treat it as indigestible even though the bytes are resident on the host.
  if (secret->sensitive || !secret->extractable)
    CNK_RETURN(CKR_KEY_INDIGESTIBLE, "Sensitive or non-extractable session key cannot be digested");
  CK_BBOOL userReservationHeld = CK_FALSE;
  if (secret->private) {
    CNK_ENSURE_OK(cnk_token_begin_user_operation(session));
    userReservationHeld = CK_TRUE;
  }

  if (mbedtls_md_update(&session->digestingContext.context, secret->value, secret->valueLen) != 0) {
    cnk_reset_digesting_context(session);
    if (userReservationHeld)
      cnk_token_end_management_operation(session);
    CNK_RETURN(CKR_FUNCTION_FAILED, "md update failed");
  }
  session->digestingContext.mode = CNK_DIGEST_MODE_MULTI_PART;
  if (userReservationHeld)
    cnk_token_end_management_operation(session);
  CNK_RET_OK;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
  CNK_LOG_FUNC(": hSession: %lu, pDigest: %p, pulDigestLen: %p", hSession, pDigest, pulDigestLen);
  CNK_ENSURE_INITIALIZED();

  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  CNK_PKCS11_MUTEX_GUARD sessionLock CNK_MUTEX_GUARD = {.mutex = &session->lock};
  CNK_ENSURE_OK(cnk_mutex_lock_guard(&sessionLock));
  if (session->digestingContext.mechanismType == 0)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_DigestInit not called");
  if (pulDigestLen == NULL) {
    cnk_reset_digesting_context(session);
    CNK_RETURN(CKR_ARGUMENTS_BAD, "pulDigestLen is NULL");
  }
  if (session->digestingContext.mode == CNK_DIGEST_MODE_SINGLE_PART) {
    cnk_reset_digesting_context(session);
    CNK_RETURN(CKR_OPERATION_ACTIVE, "C_DigestFinal cannot terminate a single-part digest");
  }
  session->digestingContext.mode = CNK_DIGEST_MODE_MULTI_PART;
  return digestFinal(session, pDigest, pulDigestLen);
}
