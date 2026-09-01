#include "api/object.h"
#include "api/session.h"
#include "backend/pcsc.h"
#include "internal/crypto.h"
#include "internal/logging.h"
#include "internal/macros.h"
#include "internal/rsa.h"
#include "internal/util.h"
#include "pkcs11.h"

#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>
#include <string.h>

static CK_BBOOL isDecryptMechanism(CK_MECHANISM_TYPE mechanism) {
  switch (mechanism) {
  case CKM_RSA_X_509:
  case CKM_RSA_PKCS:
  case CKM_RSA_PKCS_OAEP:
    return CK_TRUE;
  default:
    return CK_FALSE;
  }
}

static CK_RV getOaepMdTypes(const CK_MECHANISM *mechanism, mbedtls_md_type_t *mdType, mbedtls_md_type_t *mgfMdType) {
  CNK_ENSURE_NONNULL(mechanism, mdType, mgfMdType);

  if (mechanism->pParameter == NULL || mechanism->ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS))
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad OAEP parameter pointer/len");

  const CK_RSA_PKCS_OAEP_PARAMS *params = (const CK_RSA_PKCS_OAEP_PARAMS *)mechanism->pParameter;
  if (params->source != CKZ_DATA_SPECIFIED)
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "unsupported OAEP source");
  if (params->ulSourceDataLen > 0 && params->pSourceData == NULL)
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "OAEP label pointer is NULL");

  CK_RV rv = cnk_hash_mech_to_md(params->hashAlg, mdType);
  if (rv != CKR_OK)
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "unsupported OAEP hash");

  rv = cnk_mgf_to_md(params->mgf, mgfMdType);
  if (rv != CKR_OK)
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "unsupported OAEP MGF");

  CNK_RET_OK;
}

static CK_RV getOaepOutputUpperBound(const CK_MECHANISM *mechanism, CK_ULONG cbModulus, CK_ULONG_PTR cbOutput) {
  CNK_ENSURE_NONNULL(cbOutput);

  mbedtls_md_type_t mdType;
  mbedtls_md_type_t mgfMdType;
  CNK_ENSURE_OK(getOaepMdTypes(mechanism, &mdType, &mgfMdType));

  const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(mdType);
  if (mdInfo == NULL)
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "invalid OAEP hash");

  CK_ULONG cbHash = mbedtls_md_get_size(mdInfo);
  if (cbModulus < 2 * cbHash + 2)
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "OAEP hash too large for key");

  *cbOutput = cbModulus - 2 * cbHash - 2;
  CNK_RET_OK;
}

static CK_RV getDecryptOutputUpperBound(CNK_PKCS11_DECRYPTING_CONTEXT *context, CK_ULONG_PTR cbOutput) {
  CNK_ENSURE_NONNULL(context, cbOutput);

  switch (context->mechanism.mechanism) {
  case CKM_RSA_X_509:
    *cbOutput = context->cbModulus;
    break;
  case CKM_RSA_PKCS:
    if (context->cbModulus < 11)
      CNK_RETURN(CKR_KEY_SIZE_RANGE, "RSA modulus too small for PKCS#1 v1.5");
    *cbOutput = context->cbModulus - 11;
    break;
  case CKM_RSA_PKCS_OAEP:
    CNK_ENSURE_OK(getOaepOutputUpperBound(&context->mechanism, context->cbModulus, cbOutput));
    break;
  default:
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "decrypt context not initialized");
  }

  CNK_RET_OK;
}

static void resetDecryptingContext(CNK_PKCS11_SESSION *session) {
  if (session == NULL)
    return;

  ck_free(session->decryptingContext.mechanism.pParameter);
  memset(&session->decryptingContext, 0, sizeof(session->decryptingContext));
}

static CK_RV copyRsaCryptMechanism(CK_MECHANISM *destination, const CK_MECHANISM *mechanism) {
  destination->mechanism = mechanism->mechanism;
  destination->pParameter = NULL_PTR;
  destination->ulParameterLen = mechanism->ulParameterLen;

  if (mechanism->ulParameterLen == 0)
    CNK_RET_OK;

  CNK_ENSURE_NONNULL(mechanism->pParameter);
  // OAEP embeds a caller-owned label pointer. Keep the params and label in one
  // allocation so an active operation never depends on caller buffer lifetime.
  CK_ULONG allocationLen = mechanism->ulParameterLen;
  if (mechanism->mechanism == CKM_RSA_PKCS_OAEP) {
    const CK_RSA_PKCS_OAEP_PARAMS *params = (const CK_RSA_PKCS_OAEP_PARAMS *)mechanism->pParameter;
    if (params->ulSourceDataLen > (CK_ULONG)-1 - allocationLen)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "OAEP label is too large");
    allocationLen += params->ulSourceDataLen;
  }

  destination->pParameter = ck_malloc(allocationLen);
  if (destination->pParameter == NULL)
    CNK_RETURN(CKR_HOST_MEMORY, "failed to copy mechanism parameters");
  memcpy(destination->pParameter, mechanism->pParameter, mechanism->ulParameterLen);
  if (mechanism->mechanism == CKM_RSA_PKCS_OAEP) {
    const CK_RSA_PKCS_OAEP_PARAMS *source = (const CK_RSA_PKCS_OAEP_PARAMS *)mechanism->pParameter;
    CK_RSA_PKCS_OAEP_PARAMS *copy = (CK_RSA_PKCS_OAEP_PARAMS *)destination->pParameter;
    if (source->ulSourceDataLen > 0) {
      copy->pSourceData = (CK_BYTE_PTR)destination->pParameter + mechanism->ulParameterLen;
      memcpy(copy->pSourceData, source->pSourceData, source->ulSourceDataLen);
    } else {
      copy->pSourceData = NULL;
    }
  }
  CNK_RET_OK;
}

static CK_RV getRsaPublicComponents(const CK_BYTE *publicKey, CK_ULONG publicKeyLen, const CK_BYTE **modulus,
                                    CK_ULONG_PTR modulusLen, const CK_BYTE **exponent, CK_ULONG_PTR exponentLen) {
  CNK_ENSURE_NONNULL(publicKey, modulus, modulusLen, exponent, exponentLen);
  *modulus = NULL;
  *exponent = NULL;
  *modulusLen = 0;
  *exponentLen = 0;

  CK_ULONG vpos = 0;
  while (vpos < publicKeyLen) {
    CK_BYTE itag = publicKey[vpos++];
    if (vpos >= publicKeyLen)
      break;

    CK_LONG fail = 0;
    CK_ULONG lengthSize = 0;
    CK_ULONG ilen = tlvGetLengthSafe(&publicKey[vpos], publicKeyLen - vpos, &fail, &lengthSize);
    if (fail)
      CNK_RETURN(CKR_DEVICE_ERROR, "Bad length in public-key TLV");
    vpos += lengthSize;

    if (itag == 0x81) {
      *modulus = publicKey + vpos;
      *modulusLen = ilen;
    } else if (itag == 0x82) {
      *exponent = publicKey + vpos;
      *exponentLen = ilen;
    }

    vpos += ilen;
  }

  if (*modulus == NULL || *exponent == NULL)
    CNK_RETURN(CKR_DEVICE_ERROR, "RSA public-key component is missing");
  CNK_RET_OK;
}

static void resetEncryptingContext(CNK_PKCS11_SESSION *session) {
  if (session == NULL)
    return;
  ck_free(session->encryptingContext.mechanism.pParameter);
  memset(&session->encryptingContext, 0, sizeof(session->encryptingContext));
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, hKey: %lu", hSession, pMechanism, hKey);
  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pMechanism);
  if (!isDecryptMechanism(pMechanism->mechanism))
    CNK_RETURN(CKR_MECHANISM_INVALID, "invalid encrypt mechanism");
  if (pMechanism->mechanism == CKM_RSA_PKCS_OAEP) {
    mbedtls_md_type_t mdType, mgfMdType;
    CNK_ENSURE_OK(getOaepMdTypes(pMechanism, &mdType, &mgfMdType));
  } else if (pMechanism->pParameter != NULL || pMechanism->ulParameterLen != 0) {
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "unexpected encrypt mechanism parameters");
  }

  CNK_PKCS11_SESSION *session;
  CK_BYTE objectId, pivSlot;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (session->encryptingContext.hKey != 0)
    CNK_RETURN(CKR_OPERATION_ACTIVE, "encrypt operation is already active");
  CNK_ENSURE_OK(CNK_ValidateObject(hKey, session, CKO_PUBLIC_KEY, &objectId));
  CNK_ENSURE_OK(CNK_ObjectIdToPivTag(objectId, &pivSlot));

  // Encryption is a host public-key operation; metadata supplies the public
  // components while the private key remains on the card for C_Decrypt.
  CK_BYTE algorithmType;
  CK_BYTE publicKey[2048];
  CK_ULONG publicKeyLen = sizeof(publicKey);
  CNK_ENSURE_OK(cnk_get_metadata(session->slotId, pivSlot, &algorithmType, publicKey, &publicKeyLen, NULL, NULL));
  if (algorithmType != PIV_ALG_RSA_2048 && algorithmType != PIV_ALG_RSA_3072 && algorithmType != PIV_ALG_RSA_4096)
    CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "encrypt key is not RSA");

  const CK_BYTE *modulus, *exponent;
  CK_ULONG modulusLen, exponentLen;
  CNK_ENSURE_OK(getRsaPublicComponents(publicKey, publicKeyLen, &modulus, &modulusLen, &exponent, &exponentLen));

  resetEncryptingContext(session);
  session->encryptingContext.hKey = hKey;
  session->encryptingContext.publicKeyLen = publicKeyLen;
  session->encryptingContext.modulusLen = modulusLen;
  memcpy(session->encryptingContext.publicKey, publicKey, publicKeyLen);
  CK_RV rv = copyRsaCryptMechanism(&session->encryptingContext.mechanism, pMechanism);
  if (rv != CKR_OK) {
    resetEncryptingContext(session);
    return rv;
  }
  CNK_RET_OK;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
                CK_ULONG_PTR pulEncryptedDataLen) {
  CNK_LOG_FUNC(": hSession: %lu, pData: %p, ulDataLen: %lu, pEncryptedData: %p, pulEncryptedDataLen: %p", hSession,
               pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);
  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pulEncryptedDataLen);
  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (session->encryptingContext.hKey == 0)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_EncryptInit not called");
  if (pData == NULL && ulDataLen > 0) {
    resetEncryptingContext(session);
    CNK_RETURN(CKR_ARGUMENTS_BAD, "pData is NULL but ulDataLen > 0");
  }

  CK_ULONG modulusLen = session->encryptingContext.modulusLen;
  // Length queries and short buffers must preserve the initialized operation
  // so callers can retry without another C_EncryptInit.
  if (pEncryptedData == NULL) {
    *pulEncryptedDataLen = modulusLen;
    CNK_RET_OK;
  }
  if (*pulEncryptedDataLen < modulusLen) {
    *pulEncryptedDataLen = modulusLen;
    return CKR_BUFFER_TOO_SMALL;
  }

  const CK_BYTE *modulus, *exponent;
  CK_ULONG parsedModulusLen, exponentLen;
  CK_RV rv = getRsaPublicComponents(session->encryptingContext.publicKey, session->encryptingContext.publicKeyLen,
                                    &modulus, &parsedModulusLen, &exponent, &exponentLen);
  if (rv != CKR_OK)
    goto cleanup;

  CK_BYTE encoded[512];
  if (modulusLen > sizeof(encoded)) {
    rv = CKR_KEY_SIZE_RANGE;
    goto cleanup;
  }
  memset(encoded, 0, modulusLen);
  // Encode the message first, then perform exactly one raw RSA public
  // operation for all three supported mechanisms.
  switch (session->encryptingContext.mechanism.mechanism) {
  case CKM_RSA_X_509:
    if (ulDataLen > modulusLen) {
      rv = CKR_DATA_LEN_RANGE;
      break;
    }
    if (ulDataLen > 0)
      memcpy(encoded + modulusLen - ulDataLen, pData, ulDataLen);
    rv = CKR_OK;
    break;
  case CKM_RSA_PKCS:
    rv = pkcs1_v1_5_encrypt_pad(pData, ulDataLen, encoded, modulusLen);
    break;
  case CKM_RSA_PKCS_OAEP: {
    mbedtls_md_type_t mdType, mgfMdType;
    rv = getOaepMdTypes(&session->encryptingContext.mechanism, &mdType, &mgfMdType);
    if (rv != CKR_OK)
      break;
    const CK_RSA_PKCS_OAEP_PARAMS *params =
        (const CK_RSA_PKCS_OAEP_PARAMS *)session->encryptingContext.mechanism.pParameter;
    rv = oaep_pad(pData, ulDataLen, encoded, modulusLen, mdType, mgfMdType, params->pSourceData,
                  params->ulSourceDataLen);
    break;
  }
  default:
    rv = CKR_OPERATION_NOT_INITIALIZED;
    break;
  }
  if (rv == CKR_OK)
    rv = cnk_rsa_public(modulus, parsedModulusLen, exponent, exponentLen, encoded, modulusLen, pEncryptedData);
  mbedtls_platform_zeroize(encoded, sizeof(encoded));
  if (rv == CKR_OK)
    *pulEncryptedDataLen = modulusLen;

cleanup:
  resetEncryptingContext(session);
  return rv;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                      CK_ULONG_PTR pulEncryptedPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pPart: %p, ulPartLen: %lu, pEncryptedPart: %p, pulEncryptedPartLen: %p", hSession,
               pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
  CNK_RET_UNSUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pLastEncryptedPart: %p, pulLastEncryptedPartLen: %p", hSession, pLastEncryptedPart,
               pulLastEncryptedPartLen);
  CNK_RET_UNSUPPORTED;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, hKey: %lu", hSession, pMechanism, hKey);

  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pMechanism);

  if (!isDecryptMechanism(pMechanism->mechanism))
    CNK_RETURN(CKR_MECHANISM_INVALID, "invalid decrypt mechanism");

  if (pMechanism->ulParameterLen > 0)
    CNK_ENSURE_NONNULL(pMechanism->pParameter);

  if (pMechanism->mechanism == CKM_RSA_PKCS_OAEP) {
    mbedtls_md_type_t mdType;
    mbedtls_md_type_t mgfMdType;
    CNK_ENSURE_OK(getOaepMdTypes(pMechanism, &mdType, &mgfMdType));
  } else if (pMechanism->pParameter != NULL || pMechanism->ulParameterLen != 0) {
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "unexpected decrypt mechanism parameters");
  }

  CNK_PKCS11_SESSION *session;
  CK_BYTE objId;
  CK_BYTE pivTag;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (session->decryptingContext.hKey != 0)
    CNK_RETURN(CKR_OPERATION_ACTIVE, "decrypt operation is already active");
  CNK_ENSURE_OK(CNK_ValidateObject(hKey, session, CKO_PRIVATE_KEY, &objId));
  CNK_ENSURE_OK(C_CNK_ObjIdToPivTag(objId, &pivTag));

  CK_BYTE algorithmType;
  CK_BYTE pinPolicy = CNK_DefaultPinPolicyForPivObjectId(objId);
  CK_BYTE abPublicKey[512];
  CK_ULONG cbPublicKey = sizeof(abPublicKey);
  CNK_ENSURE_OK(cnk_get_metadata(session->slotId, pivTag, &algorithmType, abPublicKey, &cbPublicKey, &pinPolicy, NULL));

  if (!CNK_PivPrivateKeyCanDecrypt(algorithmType))
    CNK_RETURN(CKR_KEY_FUNCTION_NOT_PERMITTED, "key is not usable for decrypt");

  if (algorithmType != PIV_ALG_RSA_2048 && algorithmType != PIV_ALG_RSA_3072 && algorithmType != PIV_ALG_RSA_4096)
    CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "decrypt key is not RSA");

  CK_ULONG cbModulus = 0;
  const CK_BYTE *modulus, *exponent;
  CK_ULONG exponentLen;
  CNK_ENSURE_OK(getRsaPublicComponents(abPublicKey, cbPublicKey, &modulus, &cbModulus, &exponent, &exponentLen));
  CNK_UNUSED(modulus, exponent, exponentLen);

  resetDecryptingContext(session);

  session->decryptingContext.hKey = hKey;
  session->decryptingContext.pivSlot = pivTag;
  session->decryptingContext.algorithmType = algorithmType;
  session->decryptingContext.pinPolicy = pinPolicy;
  session->decryptingContext.cbModulus = cbModulus;

  CK_RV rv = copyRsaCryptMechanism(&session->decryptingContext.mechanism, pMechanism);
  if (rv != CKR_OK) {
    resetDecryptingContext(session);
    CNK_RETURN(rv, "copyDecryptMechanism failed");
  }

  CNK_RET_OK;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
                CK_ULONG_PTR pulDataLen) {
  CNK_LOG_FUNC(": hSession: %lu, pEncryptedData: %p, ulEncryptedDataLen: %lu, pData: %p, pulDataLen: %p", hSession,
               pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);

  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pulDataLen);

  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  if (session->decryptingContext.hKey == 0)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_DecryptInit not called");
  if (pEncryptedData == NULL_PTR && ulEncryptedDataLen > 0) {
    resetDecryptingContext(session);
    CNK_RETURN(CKR_ARGUMENTS_BAD, "pEncryptedData is NULL but ulEncryptedDataLen > 0");
  }

  CK_RV rv = CKR_OK;
  CK_BYTE rawData[512];
  CK_ULONG cbRawData = sizeof(rawData);

  if (pData == NULL_PTR) {
    // This is an upper bound for padded modes. No card operation occurs, and
    // the decrypt context remains active for the real call.
    CNK_ENSURE_OK(getDecryptOutputUpperBound(&session->decryptingContext, pulDataLen));
    CNK_RET_OK;
  }
  if (session->decryptingContext.pinPolicy == CNK_PIV_PIN_POLICY_ALWAYS &&
      !session->decryptingContext.contextAuthenticated)
    CNK_RETURN(CKR_USER_NOT_LOGGED_IN, "PIN-always key requires context-specific login");

  if (ulEncryptedDataLen != session->decryptingContext.cbModulus) {
    resetDecryptingContext(session);
    CNK_RETURN(CKR_ENCRYPTED_DATA_LEN_RANGE, "encrypted data length does not match RSA modulus");
  }

  rv = cnk_piv_decrypt(session->slotId, session, pEncryptedData, ulEncryptedDataLen, rawData, &cbRawData);
  if (rv != CKR_OK)
    goto cleanup;

  switch (session->decryptingContext.mechanism.mechanism) {
  case CKM_RSA_X_509:
    if (*pulDataLen < cbRawData) {
      *pulDataLen = cbRawData;
      rv = CKR_BUFFER_TOO_SMALL;
      break;
    }
    memcpy(pData, rawData, cbRawData);
    *pulDataLen = cbRawData;
    rv = CKR_OK;
    break;

  case CKM_RSA_PKCS:
    rv = pkcs1_v1_5_unpad(rawData, cbRawData, pData, pulDataLen);
    break;

  case CKM_RSA_PKCS_OAEP: {
    mbedtls_md_type_t mdType;
    mbedtls_md_type_t mgfMdType;
    rv = getOaepMdTypes(&session->decryptingContext.mechanism, &mdType, &mgfMdType);
    if (rv != CKR_OK)
      break;

    const CK_RSA_PKCS_OAEP_PARAMS *params =
        (const CK_RSA_PKCS_OAEP_PARAMS *)session->decryptingContext.mechanism.pParameter;
    rv = oaep_unpad(rawData, cbRawData, pData, pulDataLen, mdType, mgfMdType, params->pSourceData,
                    params->ulSourceDataLen);
    break;
  }

  default:
    rv = CKR_OPERATION_NOT_INITIALIZED;
    break;
  }

cleanup:
  mbedtls_platform_zeroize(rawData, sizeof(rawData));

  if (rv != CKR_BUFFER_TOO_SMALL)
    resetDecryptingContext(session);

  CNK_RETURN(rv, "C_Decrypt finished");
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
                      CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pEncryptedPart: %p, ulEncryptedPartLen: %lu, pPart: %p, pulPartLen: %p", hSession,
               pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
  CNK_RET_UNSUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pLastPart: %p, pulLastPartLen: %p", hSession, pLastPart, pulLastPartLen);
  CNK_RET_UNSUPPORTED;
}
