#include "api/object.h"
#include "api/session.h"
#include "backend/pcsc.h"
#include "internal/crypto.h"
#include "internal/logging.h"
#include "internal/macros.h"
#include "internal/mldsa.h"
#include "internal/rsa.h"
#include "internal/util.h"
#include "pkcs11.h"

#include <mbedtls/private/bignum.h>
#include <mbedtls/private/ecdsa.h>
#include <mbedtls/private/ecp.h>
#include <string.h>

static const CK_MECHANISM_TYPE rsaMechs[] = {
    CKM_RSA_PKCS,
    CKM_RSA_X_509,
    CKM_RSA_PKCS_PSS,
    CKM_SHA1_RSA_PKCS,
    CKM_SHA1_RSA_PKCS_PSS,
    CKM_SHA224_RSA_PKCS,
    CKM_SHA224_RSA_PKCS_PSS,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA384_RSA_PKCS_PSS,
    CKM_SHA512_RSA_PKCS,
    CKM_SHA512_RSA_PKCS_PSS,
    CKM_SHA3_224_RSA_PKCS,
    CKM_SHA3_224_RSA_PKCS_PSS,
    CKM_SHA3_256_RSA_PKCS,
    CKM_SHA3_256_RSA_PKCS_PSS,
    CKM_SHA3_384_RSA_PKCS,
    CKM_SHA3_384_RSA_PKCS_PSS,
    CKM_SHA3_512_RSA_PKCS,
    CKM_SHA3_512_RSA_PKCS_PSS,
};

static const CK_MECHANISM_TYPE rsaPkcsV15Mechs[] = {
    CKM_RSA_PKCS,        CKM_SHA1_RSA_PKCS,     CKM_SHA224_RSA_PKCS,   CKM_SHA256_RSA_PKCS,   CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS, CKM_SHA3_224_RSA_PKCS, CKM_SHA3_256_RSA_PKCS, CKM_SHA3_384_RSA_PKCS, CKM_SHA3_512_RSA_PKCS,
};

static const CK_MECHANISM_TYPE rsaPssMechs[] = {
    CKM_RSA_PKCS_PSS,          CKM_SHA1_RSA_PKCS_PSS,     CKM_SHA224_RSA_PKCS_PSS,   CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA384_RSA_PKCS_PSS,   CKM_SHA512_RSA_PKCS_PSS,   CKM_SHA3_224_RSA_PKCS_PSS, CKM_SHA3_256_RSA_PKCS_PSS,
    CKM_SHA3_384_RSA_PKCS_PSS, CKM_SHA3_512_RSA_PKCS_PSS,
};

static const CK_MECHANISM_TYPE ecMechs[] = {
    CKM_ECDSA,        CKM_ECDSA_SHA1,     CKM_ECDSA_SHA224,   CKM_ECDSA_SHA256,   CKM_ECDSA_SHA384,
    CKM_ECDSA_SHA512, CKM_ECDSA_SHA3_224, CKM_ECDSA_SHA3_256, CKM_ECDSA_SHA3_384, CKM_ECDSA_SHA3_512,
};

static const CK_MECHANISM_TYPE requireDigesting[] = {
    CKM_SHA1_RSA_PKCS,     CKM_SHA1_RSA_PKCS_PSS,     CKM_SHA224_RSA_PKCS,   CKM_SHA224_RSA_PKCS_PSS,
    CKM_SHA256_RSA_PKCS,   CKM_SHA256_RSA_PKCS_PSS,   CKM_SHA384_RSA_PKCS,   CKM_SHA384_RSA_PKCS_PSS,
    CKM_SHA512_RSA_PKCS,   CKM_SHA512_RSA_PKCS_PSS,   CKM_SHA3_224_RSA_PKCS, CKM_SHA3_224_RSA_PKCS_PSS,
    CKM_SHA3_256_RSA_PKCS, CKM_SHA3_256_RSA_PKCS_PSS, CKM_SHA3_384_RSA_PKCS, CKM_SHA3_384_RSA_PKCS_PSS,
    CKM_SHA3_512_RSA_PKCS, CKM_SHA3_512_RSA_PKCS_PSS, CKM_ECDSA_SHA1,        CKM_ECDSA_SHA224,
    CKM_ECDSA_SHA256,      CKM_ECDSA_SHA384,          CKM_ECDSA_SHA512,      CKM_ECDSA_SHA3_224,
    CKM_ECDSA_SHA3_256,    CKM_ECDSA_SHA3_384,        CKM_ECDSA_SHA3_512,
};

static CK_BBOOL mechInList(CK_MECHANISM_TYPE m, const CK_MECHANISM_TYPE *list, CK_ULONG len) {
  for (CK_ULONG i = 0; i < len; ++i)
    if (list[i] == m)
      return CK_TRUE;
  return CK_FALSE;
}

static inline CK_BBOOL isMechRSA(CK_MECHANISM_TYPE m) {
  return mechInList(m, rsaMechs, sizeof(rsaMechs) / sizeof(CK_MECHANISM_TYPE));
}

static inline CK_BBOOL isMechRsaPss(CK_MECHANISM_TYPE m) {
  return mechInList(m, rsaPssMechs, sizeof(rsaPssMechs) / sizeof(CK_MECHANISM_TYPE));
}

static inline CK_BBOOL isMechRsaPkcsV15(CK_MECHANISM_TYPE m) {
  return mechInList(m, rsaPkcsV15Mechs, sizeof(rsaPkcsV15Mechs) / sizeof(CK_MECHANISM_TYPE));
}

static inline CK_BBOOL isMechEC(CK_MECHANISM_TYPE m) {
  return mechInList(m, ecMechs, sizeof(ecMechs) / sizeof(CK_MECHANISM_TYPE));
}

static inline CK_BBOOL isMechRequireDigesting(CK_MECHANISM_TYPE m) {
  return mechInList(m, requireDigesting, sizeof(requireDigesting) / sizeof(CK_MECHANISM_TYPE));
}

static CK_RV validateRsaPssParams(const CK_MECHANISM *m) {
  // Check if parameters are provided
  if (m->pParameter == NULL || m->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS))
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad PSS param pointer/len");

  const CK_RSA_PKCS_PSS_PARAMS *p = (const CK_RSA_PKCS_PSS_PARAMS *)m->pParameter;

  mbedtls_md_type_t hashType, mgfType;
  if (cnk_hash_mech_to_md(p->hashAlg, &hashType) != CKR_OK || cnk_mgf_to_md(p->mgf, &mgfType) != CKR_OK ||
      hashType != mgfType)
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "unsupported PSS hash or MGF");
  const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(hashType);
  if (mdInfo == NULL || p->sLen > mbedtls_md_get_size(mdInfo))
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad PSS salt length");

  if (m->mechanism != CKM_RSA_PKCS_PSS) {
    CK_MECHANISM_TYPE expectedHashAlg;
    CK_RSA_PKCS_MGF_TYPE expectedMgf;
    CNK_ENSURE_OK(cnk_rsa_pkcs_pss_mech_to_hash_mgf(m->mechanism, &expectedHashAlg, &expectedMgf));
    if (p->hashAlg != expectedHashAlg || p->mgf != expectedMgf)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad PSS param: hashAlg or mgf");
  }

  return CKR_OK;
}

static CK_RV validateRsaMech(CNK_PKCS11_SESSION *session, const CK_MECHANISM *m, CK_BYTE algorithmType,
                             const CK_BYTE *abPublicKey, CK_ULONG cbPublicKey) {
  if (algorithmType != PIV_ALG_RSA_2048 && algorithmType != PIV_ALG_RSA_3072 && algorithmType != PIV_ALG_RSA_4096)
    CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "key is not RSA");

  if (isMechRsaPss(m->mechanism))
    CNK_ENSURE_OK(validateRsaPssParams(m));
  else if (m->pParameter != NULL || m->ulParameterLen != 0)
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "unexpected RSA mechanism parameters");

  session->signingContext.cbSignature = 0;

  // Get modulus
  CK_ULONG vpos = 0;
  while (vpos < cbPublicKey) {
    CK_BYTE itag = abPublicKey[vpos++];
    if (vpos >= cbPublicKey)
      break;
    CK_LONG fail;
    CK_ULONG lengthSize;
    CK_ULONG ilen = tlvGetLengthSafe(&abPublicKey[vpos], cbPublicKey - vpos, &fail, &lengthSize);
    if (fail)
      CNK_RETURN(CKR_DEVICE_ERROR, "Bad length in public-key TLV");
    vpos += lengthSize;

    // RSA modulus lives in tag 0x81
    if (itag == 0x81) {
      memcpy(session->signingContext.abModulus, abPublicKey + vpos, ilen);
      session->signingContext.cbSignature = ilen;
      break;
    }

    vpos += ilen;
  }

  CNK_DEBUG("Modulus and signature length: %lu", session->signingContext.cbSignature);

  if (session->signingContext.cbSignature == 0)
    CNK_RETURN(CKR_DEVICE_ERROR, "Modulus not found in public key");

  return CKR_OK;
}

static CK_ULONG getEcSignatureLength(CK_BYTE algorithmType) {
  switch (algorithmType) {
  case PIV_ALG_ECC_256:
  case PIV_ALG_SECP256K1:
    return 64;
  case PIV_ALG_ECC_384:
    return 96;
  default:
    return 0;
  }
}

static CK_RV validateEcMech(CNK_PKCS11_SESSION *session, CK_BYTE algorithmType) {
  CK_ULONG signatureLength = getEcSignatureLength(algorithmType);
  if (signatureLength == 0)
    CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "key is not a supported EC signing key");

  session->signingContext.cbSignature = signatureLength;
  return CKR_OK;
}

CK_RV initDigestingContext(CNK_PKCS11_SESSION *session, CK_MECHANISM_TYPE mechanism) {
  if (session->digestingContext.mechanismType != 0)
    CNK_RETURN(CKR_OPERATION_ACTIVE, "digest context is already active");
  mbedtls_md_type_t mdType;
  CNK_ENSURE_OK(cnk_sign_mech_to_md(mechanism, &mdType));

  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(mdType);
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
  session->digestingContext.mechanismType = mechanism;
  session->digestingContext.type = mdType;

  CNK_RET_OK;
}

/**
 * @brief Reset signing context after operation completion
 * @param session Active PKCS11 session
 */
static void resetSigningContext(CNK_PKCS11_SESSION *session) {
  session->signingContext.hKey = 0;
  session->signingContext.pivSlot = 0;
  session->signingContext.algorithmType = 0;
  session->signingContext.pinPolicy = 0;
  session->signingContext.mdType = MBEDTLS_MD_NONE;
  session->signingContext.mechanism.mechanism = 0;
  session->signingContext.mechanism.ulParameterLen = 0;
  ck_free(session->signingContext.mechanism.pParameter);
  session->signingContext.mechanism.pParameter = NULL;
  if (session->signingContext.message != NULL) {
    mbedtls_platform_zeroize(session->signingContext.message, session->signingContext.messageCapacity);
    ck_free(session->signingContext.message);
  }
  session->signingContext.message = NULL;
  session->signingContext.messageLen = 0;
  session->signingContext.messageCapacity = 0;
  mbedtls_platform_zeroize(session->signingContext.contextPin, sizeof(session->signingContext.contextPin));
  session->signingContext.contextPinLen = 0;
  session->signingContext.contextAuthenticated = CK_FALSE;
}

static CK_RV appendSigningMessage(CNK_PKCS11_SESSION *session, const CK_BYTE *part, CK_ULONG partLen) {
  if (partLen == 0)
    return CKR_OK;
  CNK_ENSURE_NONNULL(part);
  if (partLen > 65520 - session->signingContext.messageLen)
    CNK_RETURN(CKR_DATA_LEN_RANGE, "ML-DSA message exceeds firmware limit");

  CK_ULONG required = session->signingContext.messageLen + partLen;
  if (required > session->signingContext.messageCapacity) {
    CK_ULONG capacity = session->signingContext.messageCapacity == 0 ? 1024 : session->signingContext.messageCapacity;
    while (capacity < required)
      capacity = capacity > 32760 ? 65520 : capacity * 2;
    CK_BYTE_PTR replacement = ck_malloc(capacity);
    if (replacement == NULL)
      CNK_RETURN(CKR_HOST_MEMORY, "failed to grow ML-DSA message buffer");
    if (session->signingContext.messageLen > 0)
      memcpy(replacement, session->signingContext.message, session->signingContext.messageLen);
    if (session->signingContext.message != NULL) {
      mbedtls_platform_zeroize(session->signingContext.message, session->signingContext.messageCapacity);
      ck_free(session->signingContext.message);
    }
    session->signingContext.message = replacement;
    session->signingContext.messageCapacity = capacity;
  }
  memcpy(session->signingContext.message + session->signingContext.messageLen, part, partLen);
  session->signingContext.messageLen += partLen;
  return CKR_OK;
}

/**
 * @brief Prepare data and execute PIV sign operation
 * @param session Active PKCS11 session
 * @param inputData The data to sign (plaintext or digest)
 * @param inputDataLen Length of data to sign
 * @param pSignature Buffer to receive signature
 * @param pulSignatureLen Pointer to receive signature length
 * @return CK_RV
 */
static CK_RV prepareAndSign(CNK_PKCS11_SESSION *pSession, CK_BYTE_PTR pInputData, CK_ULONG cbInputData,
                            CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
  if (pSession->signingContext.pinPolicy == CNK_PIV_PIN_POLICY_ALWAYS && !pSession->signingContext.contextAuthenticated)
    CNK_RETURN(CKR_USER_NOT_LOGGED_IN, "PIN-always key requires context-specific login");
  CK_RV rv = CKR_OK;
  CK_BYTE pivSlot = pSession->signingContext.pivSlot;
  CNK_DEBUG("Signing with active key, PIV slot 0x%x", pivSlot);

  CK_BYTE_PTR pbSignRawData = NULL_PTR;
  CK_ULONG cbSignRawData;

  if (pSession->signingContext.mechanism.mechanism == CKM_ML_DSA) {
    return cnk_piv_sign(pSession->slotId, pSession, pInputData, cbInputData, pSignature, pulSignatureLen);
  } else if (isMechRSA(pSession->signingContext.mechanism.mechanism)) {
    pbSignRawData = ck_malloc(pSession->signingContext.cbSignature);
    if (!pbSignRawData)
      CNK_RETURN(CKR_HOST_MEMORY, "failed to allocate RSA sign buffer");
    cbSignRawData = pSession->signingContext.cbSignature;
    if (isMechRsaPkcsV15(pSession->signingContext.mechanism.mechanism)) {
      rv = pkcs1_v1_5_pad(pInputData, cbInputData, pbSignRawData, cbSignRawData, pSession->signingContext.mdType);
      if (rv != CKR_OK)
        goto cleanup;
    } else if (isMechRsaPss(pSession->signingContext.mechanism.mechanism)) {
      const CK_RSA_PKCS_PSS_PARAMS *pss_params =
          (CK_RSA_PKCS_PSS_PARAMS *)pSession->signingContext.mechanism.pParameter;
      CK_ULONG cbModulus = pSession->signingContext.cbSignature;
      CK_ULONG cbSalt = pss_params->sLen;
      rv = pss_encode(pInputData, cbInputData, pSession->signingContext.abModulus, cbModulus, cbSalt,
                      pSession->signingContext.mdType, pbSignRawData);
      if (rv != CKR_OK)
        goto cleanup;
    } else if (pSession->signingContext.mechanism.mechanism == CKM_RSA_X_509) {
      if (cbSignRawData != cbInputData) {
        rv = CKR_ARGUMENTS_BAD;
        goto cleanup;
      }
      memcpy(pbSignRawData, pInputData, cbInputData);
    } else {
      CNK_ERROR("Unexpected code path");
      rv = CKR_FUNCTION_FAILED;
      goto cleanup;
    }
  } else if (isMechEC(pSession->signingContext.mechanism.mechanism)) {
    cbSignRawData = pSession->signingContext.cbSignature / 2;
    if (cbSignRawData == 0) {
      rv = CKR_KEY_TYPE_INCONSISTENT;
      goto cleanup;
    }
    if (cbInputData > cbSignRawData)
      cbInputData = cbSignRawData;
    pbSignRawData = ck_malloc(cbSignRawData);
    if (!pbSignRawData) {
      rv = CKR_HOST_MEMORY;
      goto cleanup;
    }
    memset(pbSignRawData, 0, cbSignRawData);
    memcpy(pbSignRawData + cbSignRawData - cbInputData, pInputData, cbInputData);
  } else {
    CNK_ERROR("Unexpected code path");
    rv = CKR_FUNCTION_FAILED;
    goto cleanup;
  }

  // Sign the data
  rv = cnk_piv_sign(pSession->slotId, pSession, pbSignRawData, cbSignRawData, pSignature, pulSignatureLen);
  if (rv != CKR_BUFFER_TOO_SMALL) {
    pSession->signingContext.contextAuthenticated = CK_FALSE;
    mbedtls_platform_zeroize(pSession->signingContext.contextPin, sizeof(pSession->signingContext.contextPin));
    pSession->signingContext.contextPinLen = 0;
  }
  if (rv != CKR_OK) {
    CNK_ERROR("Failed to sign data: ret = %lu", rv);
  }

cleanup:
  ck_free(pbSignRawData);
  return rv;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, hKey: %lu", hSession, pMechanism, hKey);

  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pMechanism);

  // Find the session, validate the key object, and map object ID to PIV tag
  CNK_PKCS11_SESSION *session;
  CK_BYTE objId;
  CK_BYTE pivTag;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (session->signingContext.hKey != 0)
    CNK_RETURN(CKR_OPERATION_ACTIVE, "sign operation is already active");
  CNK_ENSURE_OK(CNK_ValidateObject(hKey, session, CKO_PRIVATE_KEY, &objId));
  CNK_ENSURE_OK(C_CNK_ObjIdToPivTag(objId, &pivTag));

  // Get metadata
  CK_BYTE algorithmType;
  CK_BYTE pinPolicy = CNK_DefaultPinPolicyForPivObjectId(objId);
  CK_BYTE abPublicKey[2048];
  CK_ULONG cbPublicKey = sizeof(abPublicKey);
  CNK_ENSURE_OK(cnk_get_metadata(session->slotId, pivTag, &algorithmType, abPublicKey, &cbPublicKey, &pinPolicy, NULL));

  if (!CNK_PivPrivateKeyCanSign(algorithmType) && algorithmType != session->mldsa65Algorithm)
    CNK_RETURN(CKR_KEY_FUNCTION_NOT_PERMITTED, "key is not usable for signing");

  if (pMechanism->mechanism == CKM_ML_DSA) {
    if (algorithmType != session->mldsa65Algorithm)
      CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "key is not ML-DSA-65");
    if (pMechanism->pParameter != NULL || pMechanism->ulParameterLen != 0)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "ML-DSA context is not supported by PIV");
    session->signingContext.cbSignature = 3309;
  } else if (isMechRSA(pMechanism->mechanism)) {
    CNK_ENSURE_OK(validateRsaMech(session, pMechanism, algorithmType, abPublicKey, cbPublicKey));
  } else if (isMechEC(pMechanism->mechanism)) {
    CNK_ENSURE_OK(validateEcMech(session, algorithmType));
  } else {
    CNK_RETURN(CKR_MECHANISM_INVALID, "Invalid mechanism");
  }

  if (pMechanism->ulParameterLen > 0)
    CNK_ENSURE_NONNULL(pMechanism->pParameter);

  // Store active key and mechanism in the session
  session->signingContext.hKey = hKey;
  session->signingContext.pivSlot = pivTag;
  session->signingContext.algorithmType = algorithmType;
  session->signingContext.pinPolicy = pinPolicy;
  session->signingContext.mechanism.mechanism = pMechanism->mechanism;
  session->signingContext.mechanism.pParameter = NULL_PTR;
  session->signingContext.mechanism.ulParameterLen = pMechanism->ulParameterLen;
  if (pMechanism->ulParameterLen > 0) {
    session->signingContext.mechanism.pParameter = ck_malloc(pMechanism->ulParameterLen);
    if (!session->signingContext.mechanism.pParameter) {
      resetSigningContext(session);
      CNK_RETURN(CKR_HOST_MEMORY, "failed to copy mechanism parameters");
    }
    memcpy(session->signingContext.mechanism.pParameter, pMechanism->pParameter, pMechanism->ulParameterLen);
  }

  if (isMechRequireDigesting(pMechanism->mechanism)) {
    CK_RV rv = initDigestingContext(session, pMechanism->mechanism);
    if (rv != CKR_OK) {
      resetSigningContext(session);
      CNK_RETURN(rv, "initDigestingContext failed");
    }
    session->signingContext.mdType = session->digestingContext.type;
  } else if (pMechanism->mechanism == CKM_RSA_PKCS_PSS) {
    // Raw PSS receives a caller-supplied digest, so remember its hash without
    // creating a streaming digest operation.
    const CK_RSA_PKCS_PSS_PARAMS *params = (const CK_RSA_PKCS_PSS_PARAMS *)pMechanism->pParameter;
    CNK_ENSURE_OK(cnk_hash_mech_to_md(params->hashAlg, &session->signingContext.mdType));
  }

  CNK_RET_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
             CK_ULONG_PTR pulSignatureLen) {
  CNK_LOG_FUNC(": hSession: %lu, ulDataLen: %lu, pSignature: %p, pulSignatureLen: %p", hSession, ulDataLen, pSignature,
               pulSignatureLen);

  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pulSignatureLen);

  // Validate the session, and check if we have an active key
  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (session->signingContext.hKey == 0)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_SignInit not called - no active key");
  if (pData == NULL && ulDataLen > 0) {
    resetSigningContext(session);
    CNK_RETURN(CKR_ARGUMENTS_BAD, "pData is NULL but ulDataLen > 0");
  }

  // For signature-only call to get the signature length
  if (pSignature == NULL_PTR) {
    *pulSignatureLen = session->signingContext.cbSignature;
    CNK_RET_OK;
  }
  if (*pulSignatureLen < session->signingContext.cbSignature) {
    *pulSignatureLen = session->signingContext.cbSignature;
    return CKR_BUFFER_TOO_SMALL;
  }

  CK_RV rv = CKR_OK;

  // If the mechanism requires digesting, do it using C_SignUpdate and C_SignFinal
  if (isMechRequireDigesting(session->signingContext.mechanism.mechanism)) {
    rv = C_SignUpdate(hSession, pData, ulDataLen);
    if (rv != CKR_OK)
      goto cleanup;
    rv = C_SignFinal(hSession, pSignature, pulSignatureLen);
    if (rv != CKR_OK)
      goto cleanup;
    goto cleanup;
  }

  // Otherwise, we compute the signature directly
  rv = prepareAndSign(session, pData, ulDataLen, pSignature, pulSignatureLen);

cleanup:
  if (rv != CKR_USER_NOT_LOGGED_IN && rv != CKR_BUFFER_TOO_SMALL)
    resetSigningContext(session);

  return rv;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pPart: %p, ulPartLen: %lu", hSession, pPart, ulPartLen);

  CNK_ENSURE_INITIALIZED();
  if (pPart == NULL && ulPartLen > 0)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "pPart is NULL but ulPartLen > 0");

  // Validate the session, check if we have an active key, and check if we have a mechanism
  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (session->signingContext.hKey == 0)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_SignInit not called");
  if (session->signingContext.pinPolicy == CNK_PIV_PIN_POLICY_ALWAYS && !session->signingContext.contextAuthenticated)
    CNK_RETURN(CKR_USER_NOT_LOGGED_IN, "PIN-always key requires context-specific login");
  if (!isMechRequireDigesting(session->signingContext.mechanism.mechanism) &&
      session->signingContext.mechanism.mechanism != CKM_ML_DSA)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "single-part mechanism");
  if (session->signingContext.mechanism.mechanism == CKM_ML_DSA)
    return appendSigningMessage(session, pPart, ulPartLen);
  if (session->digestingContext.mechanismType == 0)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_SignInit not called");

  if (mbedtls_md_update(&session->digestingContext.context, pPart, ulPartLen) != 0) {
    // Reset signing context
    resetSigningContext(session);

    // Reset digesting context
    mbedtls_md_free(&session->digestingContext.context);
    session->digestingContext.type = MBEDTLS_MD_NONE;

    CNK_RETURN(CKR_FUNCTION_FAILED, "md update failed");
  }

  CNK_RET_OK;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
  CNK_LOG_FUNC(": hSession: %lu, pSignature: %p, pulSignatureLen: %p", hSession, pSignature, pulSignatureLen);

  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pulSignatureLen);

  // Validate the session, check if we have an active key, and check if we have a mechanism
  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (session->signingContext.hKey == 0)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_SignInit not called");
  if (!isMechRequireDigesting(session->signingContext.mechanism.mechanism) &&
      session->signingContext.mechanism.mechanism != CKM_ML_DSA)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "single-part mechanism");
  if (session->signingContext.mechanism.mechanism == CKM_ML_DSA) {
    if (pSignature == NULL) {
      *pulSignatureLen = session->signingContext.cbSignature;
      return CKR_OK;
    }
    if (*pulSignatureLen < session->signingContext.cbSignature) {
      *pulSignatureLen = session->signingContext.cbSignature;
      return CKR_BUFFER_TOO_SMALL;
    }
    if (session->signingContext.pinPolicy == CNK_PIV_PIN_POLICY_ALWAYS && !session->signingContext.contextAuthenticated)
      CNK_RETURN(CKR_USER_NOT_LOGGED_IN, "PIN-always key requires context-specific login");
    CK_RV signRv = prepareAndSign(session, session->signingContext.message, session->signingContext.messageLen,
                                  pSignature, pulSignatureLen);
    if (signRv != CKR_USER_NOT_LOGGED_IN && signRv != CKR_BUFFER_TOO_SMALL)
      resetSigningContext(session);
    return signRv;
  }
  if (session->digestingContext.mechanismType == 0)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_SignInit not called");

  // For signature-only call to get the signature length
  if (pSignature == NULL) {
    *pulSignatureLen = session->signingContext.cbSignature;
    CNK_RET_OK;
  }
  if (*pulSignatureLen < session->signingContext.cbSignature) {
    *pulSignatureLen = session->signingContext.cbSignature;
    return CKR_BUFFER_TOO_SMALL;
  }
  if (session->signingContext.pinPolicy == CNK_PIV_PIN_POLICY_ALWAYS && !session->signingContext.contextAuthenticated)
    CNK_RETURN(CKR_USER_NOT_LOGGED_IN, "PIN-always key requires context-specific login");

  CK_RV rv = CKR_OK;

  // Get the digest
  const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(session->digestingContext.type);
  CNK_ENSURE_NONNULL(mdInfo);

  CK_ULONG cbMD = mbedtls_md_get_size(mdInfo);
  CK_BYTE_PTR pMD = ck_malloc(cbMD);
  CNK_ENSURE_NONNULL(pMD);

  if (mbedtls_md_finish(&session->digestingContext.context, pMD) != 0) {
    CNK_ERROR("Failed to finish digesting");
    rv = CKR_FUNCTION_FAILED;
    goto cleanup;
  }

  // Compute signature
  rv = prepareAndSign(session, pMD, cbMD, pSignature, pulSignatureLen);
  if (rv != CKR_OK) {
    goto cleanup;
  }

cleanup:
  ck_free(pMD);
  if (rv != CKR_USER_NOT_LOGGED_IN && rv != CKR_BUFFER_TOO_SMALL) {
    resetSigningContext(session);
    mbedtls_md_free(&session->digestingContext.context);
    session->digestingContext.type = MBEDTLS_MD_NONE;
    session->digestingContext.mechanismType = 0;
  }

  CNK_RETURN(rv, "C_SignFinal finished");
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, hKey: %lu", hSession, pMechanism, hKey);
  CNK_RET_UNSUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                    CK_ULONG_PTR pulSignatureLen) {
  CNK_LOG_FUNC(": hSession: %lu, pData: %p, ulDataLen: %lu, pSignature: %p, pulSignatureLen: %p", hSession, pData,
               ulDataLen, pSignature, pulSignatureLen);
  CNK_RET_UNSUPPORTED;
}

static CK_RV getPublicKeyComponent(const CK_BYTE *publicKey, CK_ULONG publicKeyLen, CK_BYTE tag, const CK_BYTE **value,
                                   CK_ULONG_PTR valueLen) {
  CNK_ENSURE_NONNULL(publicKey, value, valueLen);
  CK_ULONG offset = 0;
  while (offset < publicKeyLen) {
    CK_BYTE currentTag = publicKey[offset++];
    if (offset >= publicKeyLen)
      break;
    CK_LONG fail = 0;
    CK_ULONG lengthSize = 0;
    CK_ULONG length = tlvGetLengthSafe(publicKey + offset, publicKeyLen - offset, &fail, &lengthSize);
    if (fail)
      CNK_RETURN(CKR_DEVICE_ERROR, "Malformed public-key TLV");
    offset += lengthSize;
    if (currentTag == tag) {
      *value = publicKey + offset;
      *valueLen = length;
      CNK_RET_OK;
    }
    offset += length;
  }
  CNK_RETURN(CKR_DEVICE_ERROR, "Public-key component is missing");
}

static void resetVerifyingContext(CNK_PKCS11_SESSION *session) {
  if (session == NULL)
    return;
  ck_free(session->verifyingContext.mechanism.pParameter);
  if (session->verifyingContext.message != NULL) {
    mbedtls_platform_zeroize(session->verifyingContext.message, session->verifyingContext.messageCapacity);
    ck_free(session->verifyingContext.message);
  }
  // Only combined-hash Verify owns digestingContext. Raw Verify may coexist
  // with an independent C_Digest operation in the same session.
  CK_BBOOL ownsDigestContext = session->verifyingContext.ownsDigestContext;
  memset(&session->verifyingContext, 0, sizeof(session->verifyingContext));
  if (ownsDigestContext) {
    if (session->digestingContext.mechanismType != 0)
      mbedtls_md_free(&session->digestingContext.context);
    memset(&session->digestingContext, 0, sizeof(session->digestingContext));
  }
}

static CK_RV appendVerifyingMessage(CNK_PKCS11_SESSION *session, const CK_BYTE *part, CK_ULONG partLen) {
  if (partLen == 0)
    return CKR_OK;
  CNK_ENSURE_NONNULL(part);
  if (partLen > 65520 - session->verifyingContext.messageLen)
    CNK_RETURN(CKR_DATA_LEN_RANGE, "verification message is too large");
  // Raw RSA/ECDSA and ML-DSA have no incremental host primitive here, so keep
  // bounded input until VerifyFinal. Combined-hash mechanisms stream to MD.
  CK_ULONG required = session->verifyingContext.messageLen + partLen;
  if (required > session->verifyingContext.messageCapacity) {
    CK_ULONG capacity =
        session->verifyingContext.messageCapacity == 0 ? 1024 : session->verifyingContext.messageCapacity;
    while (capacity < required)
      capacity = capacity > 32760 ? 65520 : capacity * 2;
    CK_BYTE *replacement = ck_malloc(capacity);
    if (replacement == NULL)
      CNK_RETURN(CKR_HOST_MEMORY, "failed to grow verification message buffer");
    if (session->verifyingContext.messageLen > 0)
      memcpy(replacement, session->verifyingContext.message, session->verifyingContext.messageLen);
    if (session->verifyingContext.message != NULL) {
      mbedtls_platform_zeroize(session->verifyingContext.message, session->verifyingContext.messageCapacity);
      ck_free(session->verifyingContext.message);
    }
    session->verifyingContext.message = replacement;
    session->verifyingContext.messageCapacity = capacity;
  }
  memcpy(session->verifyingContext.message + session->verifyingContext.messageLen, part, partLen);
  session->verifyingContext.messageLen += partLen;
  return CKR_OK;
}

static CK_RV verifyRsaSignature(CNK_PKCS11_SESSION *session, const CK_BYTE *data, CK_ULONG dataLen,
                                const CK_BYTE *signature, CK_ULONG signatureLen) {
  const CK_BYTE *modulus, *exponent;
  CK_ULONG modulusLen, exponentLen;
  CNK_ENSURE_OK(getPublicKeyComponent(session->verifyingContext.publicKey, session->verifyingContext.publicKeyLen, 0x81,
                                      &modulus, &modulusLen));
  CNK_ENSURE_OK(getPublicKeyComponent(session->verifyingContext.publicKey, session->verifyingContext.publicKeyLen, 0x82,
                                      &exponent, &exponentLen));
  if (signatureLen != modulusLen)
    return CKR_SIGNATURE_LEN_RANGE;

  CK_BYTE encoded[512];
  CK_BYTE expected[512];
  if (modulusLen > sizeof(encoded))
    return CKR_KEY_SIZE_RANGE;
  // RSA verification first recovers EM = signature^e mod n, then validates the
  // mechanism-specific EMSA encoding without invoking the card.
  CK_RV rv = cnk_rsa_public(modulus, modulusLen, exponent, exponentLen, signature, signatureLen, encoded);
  if (rv != CKR_OK) {
    mbedtls_platform_zeroize(encoded, sizeof(encoded));
    return CKR_SIGNATURE_INVALID;
  }

  switch (session->verifyingContext.mechanism.mechanism) {
  case CKM_RSA_X_509:
    rv = dataLen == modulusLen && memcmp(encoded, data, dataLen) == 0 ? CKR_OK : CKR_SIGNATURE_INVALID;
    break;
  case CKM_RSA_PKCS:
  case CKM_SHA1_RSA_PKCS:
  case CKM_SHA224_RSA_PKCS:
  case CKM_SHA256_RSA_PKCS:
  case CKM_SHA384_RSA_PKCS:
  case CKM_SHA512_RSA_PKCS:
  case CKM_SHA3_224_RSA_PKCS:
  case CKM_SHA3_256_RSA_PKCS:
  case CKM_SHA3_384_RSA_PKCS:
  case CKM_SHA3_512_RSA_PKCS:
    rv = pkcs1_v1_5_pad((CK_BYTE_PTR)data, dataLen, expected, modulusLen, session->verifyingContext.mdType);
    if (rv == CKR_OK)
      rv = memcmp(encoded, expected, modulusLen) == 0 ? CKR_OK : CKR_SIGNATURE_INVALID;
    break;
  default: {
    const CK_RSA_PKCS_PSS_PARAMS *params =
        (const CK_RSA_PKCS_PSS_PARAMS *)session->verifyingContext.mechanism.pParameter;
    rv = pss_verify(data, dataLen, modulus, modulusLen, params->sLen, session->verifyingContext.mdType, encoded,
                    modulusLen);
    break;
  }
  }

  mbedtls_platform_zeroize(expected, sizeof(expected));
  mbedtls_platform_zeroize(encoded, sizeof(encoded));
  return rv;
}

static CK_RV verifyEcSignature(CNK_PKCS11_SESSION *session, const CK_BYTE *data, CK_ULONG dataLen,
                               const CK_BYTE *signature, CK_ULONG signatureLen) {
  mbedtls_ecp_group_id groupId;
  CK_ULONG coordinateLen;
  switch (session->verifyingContext.algorithmType) {
  case PIV_ALG_ECC_256:
    groupId = MBEDTLS_ECP_DP_SECP256R1;
    coordinateLen = 32;
    break;
  case PIV_ALG_ECC_384:
    groupId = MBEDTLS_ECP_DP_SECP384R1;
    coordinateLen = 48;
    break;
  case PIV_ALG_SECP256K1:
    groupId = MBEDTLS_ECP_DP_SECP256K1;
    coordinateLen = 32;
    break;
  default:
    return CKR_KEY_TYPE_INCONSISTENT;
  }
  // PKCS#11 represents ECDSA signatures as fixed-width r || s, not ASN.1 DER.
  if (signatureLen != 2 * coordinateLen)
    return CKR_SIGNATURE_LEN_RANGE;

  const CK_BYTE *point;
  CK_ULONG pointLen;
  CNK_ENSURE_OK(getPublicKeyComponent(session->verifyingContext.publicKey, session->verifyingContext.publicKeyLen, 0x86,
                                      &point, &pointLen));

  mbedtls_ecp_group group;
  mbedtls_ecp_point q;
  mbedtls_mpi r, s;
  mbedtls_ecp_group_init(&group);
  mbedtls_ecp_point_init(&q);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  CK_RV rv = CKR_SIGNATURE_INVALID;
  if (mbedtls_ecp_group_load(&group, groupId) != 0 || mbedtls_ecp_point_read_binary(&group, &q, point, pointLen) != 0 ||
      mbedtls_mpi_read_binary(&r, signature, coordinateLen) != 0 ||
      mbedtls_mpi_read_binary(&s, signature + coordinateLen, coordinateLen) != 0)
    goto cleanup;
  rv = mbedtls_ecdsa_verify(&group, data, dataLen, &q, &r, &s) == 0 ? CKR_OK : CKR_SIGNATURE_INVALID;

cleanup:
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&r);
  mbedtls_ecp_point_free(&q);
  mbedtls_ecp_group_free(&group);
  return rv;
}

static CK_RV verifyPrepared(CNK_PKCS11_SESSION *session, const CK_BYTE *data, CK_ULONG dataLen,
                            const CK_BYTE *signature, CK_ULONG signatureLen) {
  if (isMechRSA(session->verifyingContext.mechanism.mechanism))
    return verifyRsaSignature(session, data, dataLen, signature, signatureLen);
  if (isMechEC(session->verifyingContext.mechanism.mechanism))
    return verifyEcSignature(session, data, dataLen, signature, signatureLen);
  if (session->verifyingContext.mechanism.mechanism == CKM_ML_DSA) {
    if (signatureLen != CNK_MLDSA65_SIGNATURE_BYTES)
      return CKR_SIGNATURE_LEN_RANGE;
    const CK_BYTE *publicKey;
    CK_ULONG publicKeyLen;
    CNK_ENSURE_OK(getPublicKeyComponent(session->verifyingContext.publicKey, session->verifyingContext.publicKeyLen,
                                        0x86, &publicKey, &publicKeyLen));
    if (publicKeyLen != CNK_MLDSA65_PUBLIC_KEY_BYTES)
      return CKR_KEY_TYPE_INCONSISTENT;
    return cnk_mldsa65_verify_signature(publicKey, data, dataLen, signature);
  }
  return CKR_MECHANISM_INVALID;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, hKey: %lu", hSession, pMechanism, hKey);
  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pMechanism);

  CNK_PKCS11_SESSION *session;
  CK_BYTE objectId, pivSlot;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (session->verifyingContext.hKey != 0)
    CNK_RETURN(CKR_OPERATION_ACTIVE, "verify operation is already active");
  CNK_ENSURE_OK(CNK_ValidateObject(hKey, session, CKO_PUBLIC_KEY, &objectId));
  CNK_ENSURE_OK(CNK_ObjectIdToPivTag(objectId, &pivSlot));

  // Verification is host-side. Read the immutable public key from PIV metadata
  // once and bind that snapshot to this operation.
  CK_BYTE algorithmType;
  CK_BYTE publicKey[2048];
  CK_ULONG publicKeyLen = sizeof(publicKey);
  CNK_ENSURE_OK(cnk_get_metadata(session->slotId, pivSlot, &algorithmType, publicKey, &publicKeyLen, NULL, NULL));
  if (pMechanism->mechanism == CKM_ML_DSA) {
    if (algorithmType != session->mldsa65Algorithm)
      CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "verify key is not ML-DSA-65");
    if (pMechanism->pParameter != NULL || pMechanism->ulParameterLen != 0)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "ML-DSA context is not supported");
  } else if (isMechRSA(pMechanism->mechanism)) {
    if (algorithmType != PIV_ALG_RSA_2048 && algorithmType != PIV_ALG_RSA_3072 && algorithmType != PIV_ALG_RSA_4096)
      CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "verify key is not RSA");
    if (isMechRsaPss(pMechanism->mechanism))
      CNK_ENSURE_OK(validateRsaPssParams(pMechanism));
    else if (pMechanism->pParameter != NULL || pMechanism->ulParameterLen != 0)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "unexpected RSA mechanism parameters");
  } else if (isMechEC(pMechanism->mechanism)) {
    if (getEcSignatureLength(algorithmType) == 0)
      CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "verify key is not EC");
    if (pMechanism->pParameter != NULL || pMechanism->ulParameterLen != 0)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "unexpected ECDSA mechanism parameters");
  } else {
    CNK_RETURN(CKR_MECHANISM_INVALID, "invalid verify mechanism");
  }

  memset(&session->verifyingContext, 0, sizeof(session->verifyingContext));
  session->verifyingContext.hKey = hKey;
  session->verifyingContext.algorithmType = algorithmType;
  session->verifyingContext.publicKeyLen = publicKeyLen;
  memcpy(session->verifyingContext.publicKey, publicKey, publicKeyLen);
  session->verifyingContext.mechanism.mechanism = pMechanism->mechanism;
  session->verifyingContext.mechanism.ulParameterLen = pMechanism->ulParameterLen;
  // PSS parameters are copied because the caller may release its CK_MECHANISM
  // immediately after C_VerifyInit returns.
  if (pMechanism->ulParameterLen > 0) {
    session->verifyingContext.mechanism.pParameter = ck_malloc(pMechanism->ulParameterLen);
    if (session->verifyingContext.mechanism.pParameter == NULL) {
      resetVerifyingContext(session);
      return CKR_HOST_MEMORY;
    }
    memcpy(session->verifyingContext.mechanism.pParameter, pMechanism->pParameter, pMechanism->ulParameterLen);
  }

  CK_RV rv = CKR_OK;
  if (isMechRequireDigesting(pMechanism->mechanism)) {
    rv = initDigestingContext(session, pMechanism->mechanism);
    if (rv == CKR_OK) {
      session->verifyingContext.ownsDigestContext = CK_TRUE;
      session->verifyingContext.mdType = session->digestingContext.type;
    }
  } else if (pMechanism->mechanism == CKM_RSA_PKCS_PSS) {
    const CK_RSA_PKCS_PSS_PARAMS *params = (const CK_RSA_PKCS_PSS_PARAMS *)pMechanism->pParameter;
    rv = cnk_hash_mech_to_md(params->hashAlg, &session->verifyingContext.mdType);
  }
  if (rv != CKR_OK) {
    resetVerifyingContext(session);
    return rv;
  }
  CNK_RET_OK;
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
               CK_ULONG ulSignatureLen) {
  CNK_LOG_FUNC(": hSession: %lu, pData: %p, ulDataLen: %lu, pSignature: %p, ulSignatureLen: %lu", hSession, pData,
               ulDataLen, pSignature, ulSignatureLen);
  CNK_ENSURE_INITIALIZED();
  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (session->verifyingContext.hKey == 0)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_VerifyInit not called");
  if ((pData == NULL && ulDataLen > 0) || pSignature == NULL) {
    resetVerifyingContext(session);
    CNK_RETURN(CKR_ARGUMENTS_BAD, "invalid verify input");
  }

  CK_RV rv;
  if (isMechRequireDigesting(session->verifyingContext.mechanism.mechanism)) {
    rv = C_VerifyUpdate(hSession, pData, ulDataLen);
    if (rv == CKR_OK)
      rv = C_VerifyFinal(hSession, pSignature, ulSignatureLen);
    else
      resetVerifyingContext(session);
    return rv;
  }
  rv = verifyPrepared(session, pData, ulDataLen, pSignature, ulSignatureLen);
  resetVerifyingContext(session);
  return rv;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pPart: %p, ulPartLen: %lu", hSession, pPart, ulPartLen);
  CNK_ENSURE_INITIALIZED();
  if (pPart == NULL && ulPartLen > 0)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "invalid verify part");
  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (session->verifyingContext.hKey == 0)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_VerifyInit not called");

  if (isMechRequireDigesting(session->verifyingContext.mechanism.mechanism)) {
    if (session->digestingContext.mechanismType == 0)
      CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "verify digest is not initialized");
    if (mbedtls_md_update(&session->digestingContext.context, pPart, ulPartLen) != 0) {
      resetVerifyingContext(session);
      CNK_RETURN(CKR_FUNCTION_FAILED, "verify digest update failed");
    }
    CNK_RET_OK;
  }
  return appendVerifyingMessage(session, pPart, ulPartLen);
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
  CNK_LOG_FUNC(": hSession: %lu, pSignature: %p, ulSignatureLen: %lu", hSession, pSignature, ulSignatureLen);
  CNK_ENSURE_INITIALIZED();
  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (session->verifyingContext.hKey == 0)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_VerifyInit not called");
  if (pSignature == NULL) {
    resetVerifyingContext(session);
    CNK_RETURN(CKR_ARGUMENTS_BAD, "signature is NULL");
  }

  CK_RV rv;
  if (isMechRequireDigesting(session->verifyingContext.mechanism.mechanism)) {
    if (session->digestingContext.mechanismType == 0) {
      resetVerifyingContext(session);
      return CKR_OPERATION_NOT_INITIALIZED;
    }
    CK_BYTE digest[MBEDTLS_MD_MAX_SIZE];
    const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(session->digestingContext.type);
    if (mdInfo == NULL || mbedtls_md_finish(&session->digestingContext.context, digest) != 0) {
      mbedtls_platform_zeroize(digest, sizeof(digest));
      resetVerifyingContext(session);
      return CKR_FUNCTION_FAILED;
    }
    rv = verifyPrepared(session, digest, mbedtls_md_get_size(mdInfo), pSignature, ulSignatureLen);
    mbedtls_platform_zeroize(digest, sizeof(digest));
  } else {
    rv = verifyPrepared(session, session->verifyingContext.message, session->verifyingContext.messageLen, pSignature,
                        ulSignatureLen);
  }
  // VerifyFinal always consumes the operation, including signature mismatch.
  resetVerifyingContext(session);
  return rv;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, hKey: %lu", hSession, pMechanism, hKey);
  CNK_RET_UNSUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData,
                      CK_ULONG_PTR pulDataLen) {
  CNK_LOG_FUNC(": hSession: %lu, pSignature: %p, ulSignatureLen: %lu, pData: %p, pulDataLen: %p", hSession, pSignature,
               ulSignatureLen, pData, pulDataLen);
  CNK_RET_UNSUPPORTED;
}
