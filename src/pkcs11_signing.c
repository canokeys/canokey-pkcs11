#include "logging.h"
#include "pcsc_backend.h"
#include "pkcs11.h"
#include "pkcs11_macros.h"
#include "pkcs11_object.h"
#include "pkcs11_session.h"
#include "rsa_utils.h"
#include "utils.h"

#include <string.h>

static const CK_MECHANISM_TYPE rsaMechs[] = {
    CKM_RSA_PKCS,          CKM_RSA_X_509,           CKM_RSA_PKCS_OAEP,     CKM_RSA_PKCS_PSS,
    CKM_SHA1_RSA_PKCS,     CKM_SHA1_RSA_PKCS_PSS,   CKM_SHA224_RSA_PKCS,   CKM_SHA224_RSA_PKCS_PSS,
    CKM_SHA256_RSA_PKCS,   CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS,   CKM_SHA384_RSA_PKCS_PSS,
    CKM_SHA512_RSA_PKCS,   CKM_SHA512_RSA_PKCS_PSS, CKM_SHA3_224_RSA_PKCS, CKM_SHA3_224_RSA_PKCS_PSS,
    CKM_SHA3_256_RSA_PKCS, CKM_SHA3_384_RSA_PKCS,   CKM_SHA3_512_RSA_PKCS,
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

  // Validate parameters based on mechanism
  switch (m->mechanism) {
  case CKM_SHA1_RSA_PKCS_PSS:
    if (p->hashAlg != CKM_SHA_1 || p->mgf != CKG_MGF1_SHA1)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad PSS param: hashAlg or mgf");
    break;
  case CKM_SHA224_RSA_PKCS_PSS:
    if (p->hashAlg != CKM_SHA224 || p->mgf != CKG_MGF1_SHA224)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad PSS param: hashAlg or mgf");
    break;
  case CKM_SHA256_RSA_PKCS_PSS:
    if (p->hashAlg != CKM_SHA256 || p->mgf != CKG_MGF1_SHA256)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad PSS param: hashAlg or mgf");
    break;
  case CKM_SHA384_RSA_PKCS_PSS:
    if (p->hashAlg != CKM_SHA384 || p->mgf != CKG_MGF1_SHA384)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad PSS param: hashAlg or mgf");
    break;
  case CKM_SHA512_RSA_PKCS_PSS:
    if (p->hashAlg != CKM_SHA512 || p->mgf != CKG_MGF1_SHA512)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad PSS param: hashAlg or mgf");
    break;
  case CKM_SHA3_224_RSA_PKCS_PSS:
    if (p->hashAlg != CKM_SHA3_224 || p->mgf != CKG_MGF1_SHA3_224)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad PSS param: hashAlg or mgf");
    break;
  case CKM_SHA3_256_RSA_PKCS_PSS:
    if (p->hashAlg != CKM_SHA3_256 || p->mgf != CKG_MGF1_SHA3_256)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad PSS param: hashAlg or mgf");
    break;
  case CKM_SHA3_384_RSA_PKCS_PSS:
    if (p->hashAlg != CKM_SHA3_384 || p->mgf != CKG_MGF1_SHA3_384)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad PSS param: hashAlg or mgf");
    break;
  case CKM_SHA3_512_RSA_PKCS_PSS:
    if (p->hashAlg != CKM_SHA3_512 || p->mgf != CKG_MGF1_SHA3_512)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad PSS param: hashAlg or mgf");
    break;
  default:
    // CKM_RSA_PKCS_PSS: hashAlg and mgf are not used
    break;
  }

  return CKR_OK;
}

static CK_RV validateRsaMech(CNK_PKCS11_SESSION *session, const CK_MECHANISM *m, CK_BYTE algorithmType,
                             const CK_BYTE *abPublicKey, CK_ULONG cbPublicKey) {
  if (algorithmType != PIV_ALG_RSA_2048 && algorithmType != PIV_ALG_RSA_3072 && algorithmType != PIV_ALG_RSA_4096)
    CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "key is not RSA");

  if (isMechRsaPss(m->mechanism))
    CNK_ENSURE_OK(validateRsaPssParams(m));

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

CK_ULONG getEcSignatureLength(CK_BYTE algorithmType) {
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

CK_RV initDigestingContext(CNK_PKCS11_SESSION *session, CK_MECHANISM_TYPE mechanism) {
  mbedtls_md_type_t mdType;
  switch (mechanism) {
  case CKM_SHA1_RSA_PKCS:
  case CKM_SHA1_RSA_PKCS_PSS:
  case CKM_ECDSA_SHA1:
    mdType = MBEDTLS_MD_SHA1;
    break;
  case CKM_SHA224_RSA_PKCS:
  case CKM_SHA224_RSA_PKCS_PSS:
  case CKM_ECDSA_SHA224:
    mdType = MBEDTLS_MD_SHA224;
    break;
  case CKM_SHA256_RSA_PKCS:
  case CKM_SHA256_RSA_PKCS_PSS:
  case CKM_ECDSA_SHA256:
    mdType = MBEDTLS_MD_SHA256;
    break;
  case CKM_SHA384_RSA_PKCS:
  case CKM_SHA384_RSA_PKCS_PSS:
  case CKM_ECDSA_SHA384:
    mdType = MBEDTLS_MD_SHA384;
    break;
  case CKM_SHA512_RSA_PKCS:
  case CKM_SHA512_RSA_PKCS_PSS:
  case CKM_ECDSA_SHA512:
    mdType = MBEDTLS_MD_SHA512;
    break;
  case CKM_SHA3_224_RSA_PKCS:
  case CKM_SHA3_224_RSA_PKCS_PSS:
  case CKM_ECDSA_SHA3_224:
    mdType = MBEDTLS_MD_SHA3_224;
    break;
  case CKM_SHA3_256_RSA_PKCS:
  case CKM_SHA3_256_RSA_PKCS_PSS:
  case CKM_ECDSA_SHA3_256:
    mdType = MBEDTLS_MD_SHA3_256;
    break;
  case CKM_SHA3_384_RSA_PKCS:
  case CKM_SHA3_384_RSA_PKCS_PSS:
  case CKM_ECDSA_SHA3_384:
    mdType = MBEDTLS_MD_SHA3_384;
    break;
  case CKM_SHA3_512_RSA_PKCS:
  case CKM_SHA3_512_RSA_PKCS_PSS:
  case CKM_ECDSA_SHA3_512:
    mdType = MBEDTLS_MD_SHA3_512;
    break;
  default:
    CNK_RETURN(CKR_MECHANISM_INVALID, "unsupported mechanism");
  }

  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(mdType);
  if (!md_info)
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "invalid md_info");

  mbedtls_md_init(&session->digestingContext.context);
  if (mbedtls_md_setup(&session->digestingContext.context, md_info, 0) != 0)
    CNK_RETURN(CKR_HOST_MEMORY, "md setup failed");
  if (mbedtls_md_starts(&session->digestingContext.context) != 0)
    CNK_RETURN(CKR_FUNCTION_FAILED, "md start failed");
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
  session->signingContext.mechanism.mechanism = 0;
  session->signingContext.mechanism.ulParameterLen = 0;
  ck_free(session->signingContext.mechanism.pParameter);
  session->signingContext.mechanism.pParameter = NULL;
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
  CK_RV rv = CKR_OK;
  CK_BYTE pivSlot = pSession->signingContext.pivSlot;
  CNK_DEBUG("Signing with active key, PIV slot 0x%x", pivSlot);

  CK_BYTE_PTR pbSignRawData = NULL_PTR;
  CK_ULONG cbSignRawData;

  if (isMechRSA(pSession->signingContext.mechanism.mechanism)) {
    pbSignRawData = ck_malloc(pSession->signingContext.cbSignature);
    cbSignRawData = pSession->signingContext.cbSignature;
    if (isMechRsaPkcsV15(pSession->signingContext.mechanism.mechanism)) {
      pkcs1_v1_5_pad(pInputData, cbInputData, pbSignRawData, cbSignRawData, pSession->digestingContext.type);
    } else if (isMechRsaPss(pSession->signingContext.mechanism.mechanism)) {
      const CK_RSA_PKCS_PSS_PARAMS *pss_params =
          (CK_RSA_PKCS_PSS_PARAMS *)pSession->signingContext.mechanism.pParameter;
      CK_ULONG cbModulus = pSession->signingContext.cbSignature;
      CK_ULONG cbSalt = pss_params->sLen;
      pss_encode(pInputData, cbInputData, pSession->signingContext.abModulus, cbModulus, cbSalt,
                 pSession->digestingContext.type, pbSignRawData);
    } else if (pSession->signingContext.mechanism.mechanism == CKM_RSA_X_509) {
      CNK_ENSURE_EQUAL(cbSignRawData, cbInputData);
      memcpy(pbSignRawData, pInputData, cbInputData);
    } else {
      CNK_ERROR("Unexpected code path");
      return CKR_FUNCTION_FAILED;
    }
  } else if (isMechEC(pSession->signingContext.mechanism.mechanism)) {
    cbSignRawData = pSession->signingContext.cbSignature / 2;
    if (cbInputData > cbSignRawData)
      return CKR_DATA_LEN_RANGE;
    pbSignRawData = ck_malloc(cbSignRawData);
    memset(pbSignRawData, 0, cbSignRawData);
    memcpy(pbSignRawData + cbSignRawData - cbInputData, pInputData, cbInputData);
  } else {
    CNK_ERROR("Unexpected code path");
    return CKR_FUNCTION_FAILED;
  }

  // Sign the data
  rv = cnk_piv_sign(pSession->slotId, pSession, pbSignRawData, cbSignRawData, pSignature, pulSignatureLen);
  if (rv != CKR_OK) {
    CNK_ERROR("Failed to sign data: ret = %lu", rv);
  }

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
  CNK_ENSURE_OK(CNK_ValidateObject(hKey, session, CKO_PRIVATE_KEY, &objId));
  CNK_ENSURE_OK(C_CNK_ObjIdToPivTag(objId, &pivTag));

  // Get metadata
  CK_BYTE algorithmType;
  CK_BYTE abPublicKey[512];
  CK_ULONG cbPublicKey = sizeof(abPublicKey);
  CNK_ENSURE_OK(cnk_get_metadata(session->slotId, pivTag, &algorithmType, abPublicKey, &cbPublicKey));

  if (isMechRSA(pMechanism->mechanism)) {
    CNK_ENSURE_OK(validateRsaMech(session, pMechanism, algorithmType, abPublicKey, cbPublicKey));
  } else if (isMechEC(pMechanism->mechanism)) {
    session->signingContext.cbSignature = getEcSignatureLength(algorithmType);
  } else {
    CNK_RETURN(CKR_MECHANISM_INVALID, "Invalid mechanism");
  }

  if (isMechRequireDigesting(pMechanism->mechanism)) {
    CNK_ENSURE_OK(initDigestingContext(session, pMechanism->mechanism));
  }

  // Store active key and mechanism in the session
  session->signingContext.hKey = hKey;
  session->signingContext.pivSlot = pivTag;
  session->signingContext.algorithmType = algorithmType;
  session->signingContext.mechanism.mechanism = pMechanism->mechanism;
  session->signingContext.mechanism.pParameter = ck_malloc(pMechanism->ulParameterLen);
  session->signingContext.mechanism.ulParameterLen = pMechanism->ulParameterLen;
  memcpy(session->signingContext.mechanism.pParameter, pMechanism->pParameter, pMechanism->ulParameterLen);

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

  // For signature-only call to get the signature length
  if (pSignature == NULL_PTR) {
    *pulSignatureLen = session->signingContext.cbSignature;
    CNK_RET_OK;
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
  // Reset the context
  resetSigningContext(session);

  return rv;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pPart: %p, ulPartLen: %lu", hSession, pPart, ulPartLen);

  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pPart);

  // Validate the session, check if we have an active key, and check if we have a mechanism
  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (session->signingContext.hKey == 0)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_SignInit not called");
  if (!isMechRequireDigesting(session->signingContext.mechanism.mechanism))
    CNK_RETURN(CKR_ARGUMENTS_BAD, "single-part mechanism");
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

  // Parameter validation
  if (!pSignature && *pulSignatureLen > 0)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "pSignature is NULL but pulSignatureLen > 0");

  // Validate the session, check if we have an active key, and check if we have a mechanism
  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (session->signingContext.hKey == 0)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_SignInit not called");
  if (!isMechRequireDigesting(session->signingContext.mechanism.mechanism))
    CNK_RETURN(CKR_ARGUMENTS_BAD, "single-part mechanism");
  if (session->digestingContext.mechanismType == 0)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_SignInit not called");

  // For signature-only call to get the signature length
  if (pSignature == NULL) {
    *pulSignatureLen = session->signingContext.cbSignature;
    CNK_RET_OK;
  }

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
  // Reset signing context
  resetSigningContext(session);

  // Reset digesting context
  ck_free(pMD);
  mbedtls_md_free(&session->digestingContext.context);
  session->digestingContext.type = MBEDTLS_MD_NONE;

  CNK_RETURN(rv, "C_SignFinal finished");
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, hKey: %lu", hSession, pMechanism, hKey);
  CNK_RET_UNIMPL;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                    CK_ULONG_PTR pulSignatureLen) {
  CNK_LOG_FUNC(": hSession: %lu, pData: %p, ulDataLen: %lu, pSignature: %p, pulSignatureLen: %p", hSession, pData,
               ulDataLen, pSignature, pulSignatureLen);
  CNK_RET_UNIMPL;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, hKey: %lu", hSession, pMechanism, hKey);
  CNK_RET_UNIMPL;
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
               CK_ULONG ulSignatureLen) {
  CNK_LOG_FUNC(": hSession: %lu, pData: %p, ulDataLen: %lu, pSignature: %p, ulSignatureLen: %lu", hSession, pData,
               ulDataLen, pSignature, ulSignatureLen);
  CNK_RET_UNIMPL;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pPart: %p, ulPartLen: %lu", hSession, pPart, ulPartLen);
  CNK_RET_UNIMPL;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
  CNK_LOG_FUNC(": hSession: %lu, pSignature: %p, ulSignatureLen: %lu", hSession, pSignature, ulSignatureLen);
  CNK_RET_UNIMPL;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, hKey: %lu", hSession, pMechanism, hKey);
  CNK_RET_UNIMPL;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData,
                      CK_ULONG_PTR pulDataLen) {
  CNK_LOG_FUNC(": hSession: %lu, pSignature: %p, ulSignatureLen: %lu, pData: %p, pulDataLen: %p", hSession, pSignature,
               ulSignatureLen, pData, pulDataLen);
  CNK_RET_UNIMPL;
}
