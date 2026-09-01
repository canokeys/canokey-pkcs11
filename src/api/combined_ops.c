#include "api/object.h"
#include "api/session.h"
#include "backend/pcsc.h"
#include "internal/crypto.h"
#include "internal/logging.h"
#include "internal/macros.h"
#include "internal/util.h"
#include "pkcs11.h"
#include "pkcs11_canokey.h"

#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>
#include <psa/crypto.h>
#include <string.h>

#define CNK_MAX_ECDH_PUBLIC_DATA 133
#define CNK_MAX_ECDH_SECRET_LEN 66

static CK_RV getTemplateAttr(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_ATTRIBUTE_TYPE type,
                             CK_ATTRIBUTE_PTR *attr) {
  CNK_ENSURE_NONNULL(attr);
  *attr = NULL;

  for (CK_ULONG i = 0; i < ulCount; i++) {
    if (pTemplate[i].type == type) {
      *attr = &pTemplate[i];
      CNK_RET_OK;
    }
  }

  CNK_RETURN(CKR_TEMPLATE_INCOMPLETE, "required attribute is missing");
}

static CK_RV getTemplateByte(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_ATTRIBUTE_TYPE type, CK_BYTE *value) {
  CK_ATTRIBUTE_PTR attr;
  CNK_ENSURE_NONNULL(value);
  CNK_ENSURE_OK(getTemplateAttr(pTemplate, ulCount, type, &attr));
  if (attr->pValue == NULL || attr->ulValueLen != sizeof(CK_BYTE))
    CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad byte template attribute");
  *value = *(CK_BYTE *)attr->pValue;
  CNK_RET_OK;
}

static CK_RV getTemplateObjectClass(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_ATTRIBUTE_TYPE type,
                                    CK_OBJECT_CLASS *value) {
  CK_ATTRIBUTE_PTR attr;
  CNK_ENSURE_NONNULL(value);
  CNK_ENSURE_OK(getTemplateAttr(pTemplate, ulCount, type, &attr));
  if (attr->pValue == NULL || attr->ulValueLen != sizeof(CK_OBJECT_CLASS))
    CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CKA_CLASS template attribute");
  *value = *(CK_OBJECT_CLASS *)attr->pValue;
  CNK_RET_OK;
}

static CK_RV readTemplateBool(CK_ATTRIBUTE_PTR attribute, CK_BBOOL *value) {
  CNK_ENSURE_NONNULL(attribute, value);
  if (attribute->pValue == NULL || attribute->ulValueLen != sizeof(CK_BBOOL))
    CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad boolean template attribute");
  *value = *(CK_BBOOL *)attribute->pValue;
  CNK_RET_OK;
}

static CK_RV ecParamsToAlgorithm(CK_BYTE_PTR params, CK_ULONG paramsLen, CK_BYTE *algorithmType) {
  CNK_ENSURE_NONNULL(params, algorithmType);

  static const CK_BYTE p256[] = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
  static const CK_BYTE p384[] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22};
  static const CK_BYTE secp256k1[] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A};

  if (paramsLen == sizeof(p256) && memcmp(params, p256, sizeof(p256)) == 0) {
    *algorithmType = PIV_ALG_ECC_256;
  } else if (paramsLen == sizeof(p384) && memcmp(params, p384, sizeof(p384)) == 0) {
    *algorithmType = PIV_ALG_ECC_384;
  } else if (paramsLen == sizeof(secp256k1) && memcmp(params, secp256k1, sizeof(secp256k1)) == 0) {
    *algorithmType = PIV_ALG_SECP256K1;
  } else {
    CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "unsupported EC params");
  }

  CNK_RET_OK;
}

static CK_RV x963Kdf(mbedtls_md_type_t mdType, CK_BYTE_PTR pSharedSecret, CK_ULONG cbSharedSecret,
                     CK_BYTE_PTR pSharedData, CK_ULONG cbSharedData, CK_BYTE_PTR pOutput, CK_ULONG cbOutput) {
  const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(mdType);
  if (mdInfo == NULL)
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "unsupported KDF hash");

  CK_ULONG hashLen = mbedtls_md_get_size(mdInfo);
  if (hashLen == 0)
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad KDF hash size");

  CK_BYTE digest[MBEDTLS_MD_MAX_SIZE];
  CK_ULONG produced = 0;
  CK_ULONG counter = 1;
  CK_RV rv = CKR_OK;

  while (produced < cbOutput) {
    CK_BYTE counterBytes[4] = {
        (CK_BYTE)(counter >> 24),
        (CK_BYTE)(counter >> 16),
        (CK_BYTE)(counter >> 8),
        (CK_BYTE)counter,
    };

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, mdInfo, 0) != 0 || mbedtls_md_starts(&ctx) != 0 ||
        mbedtls_md_update(&ctx, pSharedSecret, cbSharedSecret) != 0 ||
        mbedtls_md_update(&ctx, counterBytes, sizeof(counterBytes)) != 0 ||
        (cbSharedData > 0 && mbedtls_md_update(&ctx, pSharedData, cbSharedData) != 0) ||
        mbedtls_md_finish(&ctx, digest) != 0) {
      mbedtls_md_free(&ctx);
      rv = CKR_DEVICE_ERROR;
      goto cleanup;
    }
    mbedtls_md_free(&ctx);

    CK_ULONG copyLen = cbOutput - produced;
    if (copyLen > hashLen)
      copyLen = hashLen;
    memcpy(pOutput + produced, digest, copyLen);
    produced += copyLen;

    if (counter == 0xFFFFFFFFUL && produced < cbOutput) {
      rv = CKR_KEY_SIZE_RANGE;
      goto cleanup;
    }
    counter++;
  }

cleanup:
  mbedtls_platform_zeroize(digest, sizeof(digest));
  return rv;
}

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                            CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pPart: %p, ulPartLen: %lu, pEncryptedPart: %p, pulEncryptedPartLen: %p", hSession,
               pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
  CNK_RET_UNSUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
                            CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pEncryptedPart: %p, ulEncryptedPartLen: %lu, pPart: %p, pulPartLen: %p", hSession,
               pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
  CNK_RET_UNSUPPORTED;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                          CK_ULONG_PTR pulEncryptedPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pPart: %p, ulPartLen: %lu, pEncryptedPart: %p, pulEncryptedPartLen: %p", hSession,
               pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
  CNK_RET_UNSUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
                            CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pEncryptedPart: %p, ulEncryptedPartLen: %lu, pPart: %p, pulPartLen: %p", hSession,
               pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
  CNK_RET_UNSUPPORTED;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate,
                    CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, pTemplate: %p, ulCount: %lu, phKey: %p", hSession, pMechanism,
               pTemplate, ulCount, phKey);
  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pMechanism);
  CNK_ENSURE_NONNULL(phKey);
  if (ulCount > 0)
    CNK_ENSURE_NONNULL(pTemplate);
  if (pMechanism->pParameter != NULL || pMechanism->ulParameterLen != 0)
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "key generation mechanism takes no parameters");

  CK_KEY_TYPE expectedKeyType;
  switch (pMechanism->mechanism) {
  case CKM_GENERIC_SECRET_KEY_GEN:
    expectedKeyType = CKK_GENERIC_SECRET;
    break;
  case CKM_AES_KEY_GEN:
    expectedKeyType = CKK_AES;
    break;
  default:
    CNK_RETURN(CKR_MECHANISM_INVALID, "unsupported secret-key generation mechanism");
  }

  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  // C_GenerateKey is intentionally host-side and session-only. Advertising
  // these mechanisms does not imply a card RNG or persistent symmetric store.
  CNK_PKCS11_SECRET_KEY_OBJECT prototype = {0};
  prototype.keyType = expectedKeyType;
  prototype.private = CK_TRUE;
  prototype.extractable = CK_TRUE;
  prototype.local = CK_TRUE;
  prototype.modifiable = CK_TRUE;
  prototype.copyable = CK_TRUE;
  prototype.destroyable = CK_TRUE;
  prototype.keyGenMechanism = pMechanism->mechanism;

  CK_BBOOL valueLenSpecified = CK_FALSE;
  CK_BBOOL labelSpecified = CK_FALSE;
  for (CK_ULONG i = 0; i < ulCount; i++) {
    CK_ATTRIBUTE_PTR attribute = &pTemplate[i];
    switch (attribute->type) {
    case CKA_CLASS:
      if (attribute->pValue == NULL || attribute->ulValueLen != sizeof(CK_OBJECT_CLASS) ||
          *(CK_OBJECT_CLASS *)attribute->pValue != CKO_SECRET_KEY)
        CNK_RETURN(CKR_TEMPLATE_INCONSISTENT, "generated object must be CKO_SECRET_KEY");
      break;
    case CKA_KEY_TYPE:
      if (attribute->pValue == NULL || attribute->ulValueLen != sizeof(CK_KEY_TYPE) ||
          *(CK_KEY_TYPE *)attribute->pValue != expectedKeyType)
        CNK_RETURN(CKR_TEMPLATE_INCONSISTENT, "generated key type does not match mechanism");
      break;
    case CKA_VALUE_LEN:
      if (attribute->pValue == NULL || attribute->ulValueLen != sizeof(CK_ULONG))
        CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CKA_VALUE_LEN");
      prototype.valueLen = *(CK_ULONG *)attribute->pValue;
      valueLenSpecified = CK_TRUE;
      break;
    case CKA_TOKEN:
      CNK_ENSURE_OK(readTemplateBool(attribute, &prototype.token));
      break;
    case CKA_PRIVATE:
      CNK_ENSURE_OK(readTemplateBool(attribute, &prototype.private));
      break;
    case CKA_SENSITIVE:
      CNK_ENSURE_OK(readTemplateBool(attribute, &prototype.sensitive));
      break;
    case CKA_EXTRACTABLE:
      CNK_ENSURE_OK(readTemplateBool(attribute, &prototype.extractable));
      break;
    case CKA_ENCRYPT:
      CNK_ENSURE_OK(readTemplateBool(attribute, &prototype.encrypt));
      break;
    case CKA_DECRYPT:
      CNK_ENSURE_OK(readTemplateBool(attribute, &prototype.decrypt));
      break;
    case CKA_SIGN:
      CNK_ENSURE_OK(readTemplateBool(attribute, &prototype.sign));
      break;
    case CKA_VERIFY:
      CNK_ENSURE_OK(readTemplateBool(attribute, &prototype.verify));
      break;
    case CKA_WRAP:
      CNK_ENSURE_OK(readTemplateBool(attribute, &prototype.wrap));
      break;
    case CKA_UNWRAP:
      CNK_ENSURE_OK(readTemplateBool(attribute, &prototype.unwrap));
      break;
    case CKA_DERIVE:
      CNK_ENSURE_OK(readTemplateBool(attribute, &prototype.derive));
      break;
    case CKA_MODIFIABLE:
      CNK_ENSURE_OK(readTemplateBool(attribute, &prototype.modifiable));
      break;
    case CKA_COPYABLE:
      CNK_ENSURE_OK(readTemplateBool(attribute, &prototype.copyable));
      break;
    case CKA_DESTROYABLE:
      CNK_ENSURE_OK(readTemplateBool(attribute, &prototype.destroyable));
      break;
    case CKA_LABEL:
      if ((attribute->pValue == NULL && attribute->ulValueLen != 0) || attribute->ulValueLen > sizeof(prototype.label))
        CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad generated-key label");
      if (attribute->ulValueLen > 0)
        memcpy(prototype.label, attribute->pValue, attribute->ulValueLen);
      prototype.labelLen = attribute->ulValueLen;
      labelSpecified = CK_TRUE;
      break;
    default:
      CNK_RETURN(CKR_ATTRIBUTE_TYPE_INVALID, "unsupported generated-key template attribute");
    }
  }

  if (!valueLenSpecified)
    CNK_RETURN(CKR_TEMPLATE_INCOMPLETE, "CKA_VALUE_LEN is required");
  if (prototype.token)
    CNK_RETURN(CKR_TEMPLATE_INCONSISTENT, "token secret-key generation is not supported");
  if (prototype.valueLen == 0 || prototype.valueLen > sizeof(prototype.value))
    CNK_RETURN(CKR_KEY_SIZE_RANGE, "generated key length is out of range");
  if (expectedKeyType == CKK_AES && prototype.valueLen != 16 && prototype.valueLen != 24 && prototype.valueLen != 32)
    CNK_RETURN(CKR_KEY_SIZE_RANGE, "AES key length must be 16, 24, or 32 bytes");
  if (prototype.private && !cnk_token_pin_is_cached(session))
    CNK_RETURN(CKR_USER_NOT_LOGGED_IN, "private session key requires USER login");

  if (!labelSpecified) {
    const char *defaultLabel = expectedKeyType == CKK_AES ? "Generated AES Key" : "Generated Generic Secret";
    prototype.labelLen = (CK_ULONG)strlen(defaultLabel);
    memcpy(prototype.label, defaultLabel, prototype.labelLen);
  }

  // Generate directly into the temporary prototype and erase it after the
  // session allocator has copied the value.
  psa_status_t status = psa_generate_random(prototype.value, prototype.valueLen);
  if (status != PSA_SUCCESS) {
    mbedtls_platform_zeroize(&prototype, sizeof(prototype));
    CNK_RETURN(CKR_RANDOM_NO_RNG, "host random generation failed");
  }

  CK_RV rv = CNK_CreateSessionSecretKey(session, &prototype, phKey);
  mbedtls_platform_zeroize(&prototype, sizeof(prototype));
  return rv;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                        CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                        CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey,
                        CK_OBJECT_HANDLE_PTR phPrivateKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, pPublicKeyTemplate: %p, ulPublicKeyAttributeCount: %lu, "
               "pPrivateKeyTemplate: %p, ulPrivateKeyAttributeCount: %lu, phPublicKey: %p, phPrivateKey: %p",
               hSession, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate,
               ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey);
  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pMechanism);
  CNK_ENSURE_NONNULL(phPublicKey, phPrivateKey);
  if (ulPublicKeyAttributeCount > 0)
    CNK_ENSURE_NONNULL(pPublicKeyTemplate);
  if (ulPrivateKeyAttributeCount > 0)
    CNK_ENSURE_NONNULL(pPrivateKeyTemplate);

  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (!(session->flags & CKF_RW_SESSION))
    CNK_RETURN(CKR_SESSION_READ_ONLY, "write session is required");
  if (!cnk_token_management_key_is_cached(session))
    CNK_RETURN(CKR_USER_NOT_LOGGED_IN, "CKU_SO login is required");

  CK_OBJECT_CLASS publicClass;
  CK_OBJECT_CLASS privateClass;
  CK_BYTE publicId;
  CK_BYTE privateId;
  CNK_ENSURE_OK(getTemplateObjectClass(pPublicKeyTemplate, ulPublicKeyAttributeCount, CKA_CLASS, &publicClass));
  CNK_ENSURE_OK(getTemplateObjectClass(pPrivateKeyTemplate, ulPrivateKeyAttributeCount, CKA_CLASS, &privateClass));
  CNK_ENSURE_OK(getTemplateByte(pPublicKeyTemplate, ulPublicKeyAttributeCount, CKA_ID, &publicId));
  CNK_ENSURE_OK(getTemplateByte(pPrivateKeyTemplate, ulPrivateKeyAttributeCount, CKA_ID, &privateId));

  if (publicClass != CKO_PUBLIC_KEY || privateClass != CKO_PRIVATE_KEY)
    CNK_RETURN(CKR_TEMPLATE_INCONSISTENT, "bad key pair object classes");
  if (publicId != privateId || publicId < 1 || publicId > PIV_SLOT_COUNT)
    CNK_RETURN(CKR_TEMPLATE_INCONSISTENT, "bad or mismatched PIV key ID");

  CK_BYTE algorithmType;
  switch (pMechanism->mechanism) {
  case CKM_RSA_PKCS_KEY_PAIR_GEN: {
    CK_ATTRIBUTE_PTR bitsAttr;
    CK_ULONG modulusBits;
    CNK_ENSURE_OK(getTemplateAttr(pPublicKeyTemplate, ulPublicKeyAttributeCount, CKA_MODULUS_BITS, &bitsAttr));
    if (bitsAttr->pValue == NULL || bitsAttr->ulValueLen != sizeof(CK_ULONG))
      CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CKA_MODULUS_BITS");
    modulusBits = *(CK_ULONG *)bitsAttr->pValue;
    if (modulusBits == 2048)
      algorithmType = PIV_ALG_RSA_2048;
    else if (modulusBits == 3072)
      algorithmType = PIV_ALG_RSA_3072;
    else if (modulusBits == 4096)
      algorithmType = PIV_ALG_RSA_4096;
    else
      CNK_RETURN(CKR_KEY_SIZE_RANGE, "unsupported RSA key size");
    break;
  }

  case CKM_EC_KEY_PAIR_GEN: {
    CK_ATTRIBUTE_PTR paramsAttr;
    CNK_ENSURE_OK(getTemplateAttr(pPublicKeyTemplate, ulPublicKeyAttributeCount, CKA_EC_PARAMS, &paramsAttr));
    CNK_ENSURE_OK(ecParamsToAlgorithm((CK_BYTE_PTR)paramsAttr->pValue, paramsAttr->ulValueLen, &algorithmType));
    break;
  }

  case CKM_ML_DSA_KEY_PAIR_GEN:
  case CKM_ML_KEM_KEY_PAIR_GEN: {
    CK_ATTRIBUTE_PTR parameterSetAttr;
    CNK_ENSURE_OK(getTemplateAttr(pPublicKeyTemplate, ulPublicKeyAttributeCount, CKA_PARAMETER_SET, &parameterSetAttr));
    if (parameterSetAttr->pValue == NULL || parameterSetAttr->ulValueLen != sizeof(CK_ULONG))
      CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CKA_PARAMETER_SET");
    CK_ULONG parameterSet = *(CK_ULONG *)parameterSetAttr->pValue;
    if (pMechanism->mechanism == CKM_ML_DSA_KEY_PAIR_GEN) {
      if (parameterSet != CKP_ML_DSA_65)
        CNK_RETURN(CKR_KEY_SIZE_RANGE, "only ML-DSA-65 is supported");
      algorithmType = session->mldsa65Algorithm;
    } else {
      if (parameterSet != CKP_ML_KEM_768)
        CNK_RETURN(CKR_KEY_SIZE_RANGE, "only ML-KEM-768 is supported");
      algorithmType = session->mlkem768Algorithm;
    }
    break;
  }

  default:
    CNK_RETURN(CKR_MECHANISM_INVALID, "unsupported key pair generation mechanism");
  }

  CK_BYTE pivTag;
  CK_BYTE pinPolicy = CNK_DefaultPinPolicyForPivObjectId(privateId);
  CK_BYTE touchPolicy;
  CNK_ENSURE_OK(CNK_ObjectIdToPivTag(publicId, &pivTag));
  CNK_ENSURE_OK(CNK_GetPivPolicies(pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
                                   CNK_DefaultPinPolicyForPivObjectId(privateId), &pinPolicy, &touchPolicy));

  CK_BYTE publicKey[2048];
  CK_ULONG publicKeyLen = sizeof(publicKey);
  CNK_ENSURE_OK(cnk_piv_generate_keypair(session->slotId, session, algorithmType, pivTag, pinPolicy, touchPolicy,
                                         publicKey, &publicKeyLen));

  *phPublicKey = CNK_MakeObjectHandle(session->slotId, CKO_PUBLIC_KEY, publicId);
  *phPrivateKey = CNK_MakeObjectHandle(session->slotId, CKO_PRIVATE_KEY, privateId);
  CNK_RET_OK;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey,
                CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, hWrappingKey: %lu, hKey: %lu, pWrappedKey: %p, pulWrappedKeyLen: %p",
               hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen);
  CNK_RET_UNSUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey,
                  CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, hUnwrappingKey: %lu, pWrappedKey: %p, ulWrappedKeyLen: %lu, "
               "pTemplate: %p, ulAttributeCount: %lu, phKey: %p",
               hSession, pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen, pTemplate, ulAttributeCount, phKey);
  CNK_RET_UNSUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey,
                  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, hBaseKey: %lu, pTemplate: %p, ulAttributeCount: %lu, phKey: %p",
               hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey);

  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pMechanism);
  CNK_ENSURE_NONNULL(phKey);
  if (ulAttributeCount > 0)
    CNK_ENSURE_NONNULL(pTemplate);

  if (pMechanism->mechanism != CKM_ECDH1_DERIVE)
    CNK_RETURN(CKR_MECHANISM_INVALID, "unsupported derive mechanism");

  if (pMechanism->pParameter == NULL || pMechanism->ulParameterLen != sizeof(CK_ECDH1_DERIVE_PARAMS))
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad ECDH parameters");

  const CK_ECDH1_DERIVE_PARAMS *params = (const CK_ECDH1_DERIVE_PARAMS *)pMechanism->pParameter;
  if (params->kdf == CKD_NULL && params->ulSharedDataLen > 0)
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "shared data is not supported with CKD_NULL");
  if (params->kdf != CKD_NULL && params->ulSharedDataLen > 0)
    CNK_ENSURE_NONNULL(params->pSharedData);
  if (params->pPublicData == NULL || params->ulPublicDataLen == 0 || params->ulPublicDataLen > CNK_MAX_ECDH_PUBLIC_DATA)
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad peer public key data");

  mbedtls_md_type_t kdfMdType = MBEDTLS_MD_NONE;
  if (params->kdf != CKD_NULL)
    CNK_ENSURE_OK(cnk_ec_kdf_to_md(params->kdf, &kdfMdType));

  CNK_PKCS11_SESSION *session;
  CK_BYTE objId;
  CK_BYTE pivTag;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  CNK_ENSURE_OK(CNK_ValidateObject(hBaseKey, session, CKO_PRIVATE_KEY, &objId));
  CNK_ENSURE_OK(C_CNK_ObjIdToPivTag(objId, &pivTag));

  CK_BYTE algorithmType;
  CK_BYTE pinPolicy = CNK_DefaultPinPolicyForPivObjectId(objId);
  CK_BYTE abPublicKey[512];
  CK_ULONG cbPublicKey = sizeof(abPublicKey);
  CNK_ENSURE_OK(cnk_get_metadata(session->slotId, pivTag, &algorithmType, abPublicKey, &cbPublicKey, &pinPolicy, NULL));

  if (!CNK_PivPrivateKeyCanDerive(algorithmType))
    CNK_RETURN(CKR_KEY_FUNCTION_NOT_PERMITTED, "key is not usable for ECDH derive");

  CK_ULONG expectedSecretLen = 0;
  switch (algorithmType) {
  case PIV_ALG_ECC_256:
  case PIV_ALG_SECP256K1:
    expectedSecretLen = 32;
    break;
  case PIV_ALG_ECC_384:
    expectedSecretLen = 48;
    break;
  default:
    CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "base key is not a supported EC key");
  }

  if (params->ulPublicDataLen != 1 + expectedSecretLen * 2 || params->pPublicData[0] != 0x04)
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "peer public key must be an uncompressed EC point");

  CK_OBJECT_CLASS objectClass = CKO_SECRET_KEY;
  CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
  CK_ULONG requestedValueLen = expectedSecretLen;
  CK_BBOOL valueLenSpecified = CK_FALSE;
  CK_BBOOL token = CK_FALSE;
  CK_BBOOL private = CK_TRUE;
  CK_BBOOL sensitive = CK_FALSE;
  CK_BBOOL extractable = CK_TRUE;
  CK_BBOOL encrypt = CK_FALSE;
  CK_BBOOL decrypt = CK_FALSE;
  CK_BBOOL sign = CK_FALSE;
  CK_BBOOL verify = CK_FALSE;
  CK_BBOOL wrap = CK_FALSE;
  CK_BBOOL unwrap = CK_FALSE;
  CK_BBOOL derive = CK_FALSE;
  const CK_BYTE *label = NULL;
  CK_ULONG labelLen = 0;

  for (CK_ULONG i = 0; i < ulAttributeCount; i++) {
    CK_ATTRIBUTE_PTR attr = &pTemplate[i];
    if (attr->pValue == NULL) {
      if (attr->type == CKA_LABEL && attr->ulValueLen == 0) {
        label = NULL;
        labelLen = 0;
        continue;
      }
      CNK_RETURN(CKR_TEMPLATE_INCONSISTENT, "template attribute value is NULL");
    }

    switch (attr->type) {
    case CKA_CLASS:
      if (attr->ulValueLen != sizeof(CK_OBJECT_CLASS))
        CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CKA_CLASS size");
      objectClass = *(CK_OBJECT_CLASS *)attr->pValue;
      break;
    case CKA_KEY_TYPE:
      if (attr->ulValueLen != sizeof(CK_KEY_TYPE))
        CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CKA_KEY_TYPE size");
      keyType = *(CK_KEY_TYPE *)attr->pValue;
      break;
    case CKA_VALUE_LEN:
      if (attr->ulValueLen != sizeof(CK_ULONG))
        CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CKA_VALUE_LEN size");
      requestedValueLen = *(CK_ULONG *)attr->pValue;
      valueLenSpecified = CK_TRUE;
      break;
    case CKA_TOKEN:
      if (attr->ulValueLen != sizeof(CK_BBOOL))
        CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CKA_TOKEN size");
      token = *(CK_BBOOL *)attr->pValue;
      break;
    case CKA_PRIVATE:
      if (attr->ulValueLen != sizeof(CK_BBOOL))
        CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CKA_PRIVATE size");
      private = *(CK_BBOOL *)attr->pValue;
      break;
    case CKA_SENSITIVE:
      if (attr->ulValueLen != sizeof(CK_BBOOL))
        CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CKA_SENSITIVE size");
      sensitive = *(CK_BBOOL *)attr->pValue;
      break;
    case CKA_EXTRACTABLE:
      if (attr->ulValueLen != sizeof(CK_BBOOL))
        CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CKA_EXTRACTABLE size");
      extractable = *(CK_BBOOL *)attr->pValue;
      break;
    case CKA_ENCRYPT:
      if (attr->ulValueLen != sizeof(CK_BBOOL))
        CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CKA_ENCRYPT size");
      encrypt = *(CK_BBOOL *)attr->pValue;
      break;
    case CKA_DECRYPT:
      if (attr->ulValueLen != sizeof(CK_BBOOL))
        CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CKA_DECRYPT size");
      decrypt = *(CK_BBOOL *)attr->pValue;
      break;
    case CKA_SIGN:
      if (attr->ulValueLen != sizeof(CK_BBOOL))
        CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CKA_SIGN size");
      sign = *(CK_BBOOL *)attr->pValue;
      break;
    case CKA_VERIFY:
      if (attr->ulValueLen != sizeof(CK_BBOOL))
        CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CKA_VERIFY size");
      verify = *(CK_BBOOL *)attr->pValue;
      break;
    case CKA_WRAP:
      if (attr->ulValueLen != sizeof(CK_BBOOL))
        CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CKA_WRAP size");
      wrap = *(CK_BBOOL *)attr->pValue;
      break;
    case CKA_UNWRAP:
      if (attr->ulValueLen != sizeof(CK_BBOOL))
        CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CKA_UNWRAP size");
      unwrap = *(CK_BBOOL *)attr->pValue;
      break;
    case CKA_DERIVE:
      if (attr->ulValueLen != sizeof(CK_BBOOL))
        CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CKA_DERIVE size");
      derive = *(CK_BBOOL *)attr->pValue;
      break;
    case CKA_LABEL:
      label = (const CK_BYTE *)attr->pValue;
      labelLen = attr->ulValueLen;
      break;
    default:
      CNK_RETURN(CKR_ATTRIBUTE_TYPE_INVALID, "unsupported derived key template attribute");
    }
  }

  if (objectClass != CKO_SECRET_KEY)
    CNK_RETURN(CKR_TEMPLATE_INCONSISTENT, "derived key must be CKO_SECRET_KEY");
  if (keyType != CKK_GENERIC_SECRET && keyType != CKK_AES)
    CNK_RETURN(CKR_TEMPLATE_INCONSISTENT, "only generic secret and AES derived keys are supported");
  if (token)
    CNK_RETURN(CKR_TEMPLATE_INCONSISTENT, "token derived keys are not supported");
  CK_ULONG maxDerivedSecretLen =
      params->kdf == CKD_NULL ? expectedSecretLen : (CK_ULONG)sizeof(session->secretKeys[0].value);
  if (requestedValueLen == 0 || requestedValueLen > maxDerivedSecretLen)
    CNK_RETURN(CKR_KEY_SIZE_RANGE, "bad derived key length");
  if (keyType == CKK_AES && requestedValueLen != 16 && requestedValueLen != 24 && requestedValueLen != 32)
    CNK_RETURN(CKR_KEY_SIZE_RANGE, "bad AES derived key length");
  if (labelLen > sizeof(session->secretKeys[0].label))
    CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "derived key label is too long");

  // The card returns the raw big-endian ECDH X coordinate. CKD_NULL preserves
  // it; the X9.63 KDF variants expand it before constructing the session key.
  CK_BYTE sharedSecret[CNK_MAX_ECDH_SECRET_LEN] = {0};
  CK_ULONG sharedSecretLen = sizeof(sharedSecret);
  CK_RV rv = cnk_piv_ecdh(session->slotId, session, algorithmType, pivTag, pinPolicy, params->pPublicData,
                          params->ulPublicDataLen, sharedSecret, &sharedSecretLen);
  if (rv != CKR_OK)
    CNK_RETURN(rv, "PIV ECDH failed");
  if (params->kdf == CKD_NULL && sharedSecretLen < requestedValueLen) {
    mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
    CNK_RETURN(CKR_DEVICE_ERROR, "ECDH secret shorter than requested key");
  }
  if (params->kdf != CKD_NULL && sharedSecretLen == 0) {
    mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
    CNK_RETURN(CKR_DEVICE_ERROR, "ECDH secret is empty");
  }

  CK_BYTE derivedSecret[sizeof(session->secretKeys[0].value)] = {0};
  if (params->kdf == CKD_NULL) {
    memcpy(derivedSecret, sharedSecret, requestedValueLen);
  } else {
    rv = x963Kdf(kdfMdType, sharedSecret, sharedSecretLen, params->pSharedData, params->ulSharedDataLen, derivedSecret,
                 requestedValueLen);
    if (rv != CKR_OK) {
      mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
      mbedtls_platform_zeroize(derivedSecret, sizeof(derivedSecret));
      CNK_RETURN(rv, "ECDH KDF failed");
    }
  }

  CNK_PKCS11_SECRET_KEY_OBJECT prototype = {0};
  prototype.keyType = keyType;
  prototype.valueLen = requestedValueLen;
  prototype.extractable = extractable;
  prototype.sensitive = sensitive;
  prototype.private = private;
  prototype.encrypt = encrypt;
  prototype.decrypt = decrypt;
  prototype.sign = sign;
  prototype.verify = verify;
  prototype.wrap = wrap;
  prototype.unwrap = unwrap;
  prototype.derive = derive;
  prototype.local = CK_TRUE;
  prototype.modifiable = CK_TRUE;
  prototype.copyable = CK_TRUE;
  prototype.destroyable = CK_TRUE;
  prototype.keyGenMechanism = CKM_ECDH1_DERIVE;
  memcpy(prototype.value, derivedSecret, requestedValueLen);
  if (label != NULL && labelLen > 0) {
    prototype.labelLen = labelLen;
    memcpy(prototype.label, label, labelLen);
  } else {
    const char defaultLabel[] = "PIV ECDH Shared Secret";
    prototype.labelLen = sizeof(defaultLabel) - 1;
    memcpy(prototype.label, defaultLabel, prototype.labelLen);
  }

  rv = CNK_CreateSessionSecretKey(session, &prototype, phKey);

  // Neither the raw agreement nor the KDF output may outlive this call.
  mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
  mbedtls_platform_zeroize(derivedSecret, sizeof(derivedSecret));
  mbedtls_platform_zeroize(&prototype, sizeof(prototype));
  if (rv != CKR_OK)
    return rv;
  CNK_DEBUG("Derived ECDH secret key handle %lu (%lu bytes%s)", *phKey, requestedValueLen,
            valueLenSpecified ? ", requested length" : "");
  CNK_RET_OK;
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
  CNK_LOG_FUNC(": hSession: %lu, pSeed: %p, ulSeedLen: %lu", hSession, pSeed, ulSeedLen);
  CNK_ENSURE_INITIALIZED();
  if (pSeed == NULL && ulSeedLen > 0)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "pSeed is NULL but ulSeedLen > 0");

  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  CK_BBOOL supported = CK_FALSE;
  CNK_ENSURE_OK(cnk_piv_random_supported(session->slotId, &supported));
  if (!supported)
    return CKR_RANDOM_NO_RNG;

  // The token RNG is self-seeded and firmware exposes no entropy-injection APDU.
  return CKR_RANDOM_SEED_NOT_SUPPORTED;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {
  CNK_LOG_FUNC(": hSession: %lu, pRandomData: %p, ulRandomLen: %lu", hSession, pRandomData, ulRandomLen);
  CNK_ENSURE_INITIALIZED();
  if (pRandomData == NULL && ulRandomLen > 0)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "pRandomData is NULL but ulRandomLen > 0");

  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  return cnk_piv_generate_random(session->slotId, pRandomData, ulRandomLen);
}
