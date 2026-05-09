/**
 * @file object.c
 * @brief PKCS#11 object management implementation
 *
 * This module implements the PKCS#11 object management functions for the CanoKey PKCS#11 module.
 * It handles the creation, manipulation, and querying of cryptographic objects like keys and certificates.
 */

#include "api/object.h"
#include "backend/pcsc.h"
#include "internal/logging.h"
#include "internal/macros.h"
#include "internal/mutex.h"
#include "internal/util.h"
#include "pkcs11.h"
#include "pkcs11_canokey.h"

#include <mbedtls/asn1write.h>
#include <mbedtls/platform_util.h>
#include <stddef.h> // For size_t
#include <string.h>

// Maximum size for certificate data buffer
#define MAX_PIV_CERTIFICATE_OBJECT_SIZE 4096

// Maximum size for public key buffer
#define MAX_PUBLIC_KEY_SIZE 512

// Maximum size for PIV asymmetric key import data.
#define MAX_PIV_IMPORT_KEY_SIZE 1400

// Object handle bit field masks
#define OBJECT_SLOT_MASK 0xFFFF0000
#define OBJECT_CLASS_MASK 0x0000FF00
#define OBJECT_ID_MASK 0x000000FF

// Object handle bit shifts
#define OBJECT_SLOT_SHIFT 16
#define OBJECT_CLASS_SHIFT 8

#define OBJECT_CLASS_SECRET_KEY_HANDLE ((CK_OBJECT_CLASS)CKO_SECRET_KEY)

// PIV slot to tag mapping
typedef struct {
  CK_BYTE objId;
  CK_BYTE pivTag;
  CK_BYTE certTag;
} PivSlotMapping;

static const PivSlotMapping PIV_SLOT_MAPPING[] = {
    {PIV_SLOT_9A, 0x9A, PIV_OBJECT_TAG_CERT_9A}, {PIV_SLOT_9C, 0x9C, PIV_OBJECT_TAG_CERT_9C},
    {PIV_SLOT_9D, 0x9D, PIV_OBJECT_TAG_CERT_9D}, {PIV_SLOT_9E, 0x9E, PIV_OBJECT_TAG_CERT_9E},
    {PIV_SLOT_82, 0x82, PIV_OBJECT_TAG_CERT_82}, {PIV_SLOT_83, 0x83, PIV_OBJECT_TAG_CERT_83},
};

// Size of the PIV slot mapping array
#define PIV_SLOT_MAPPING_SIZE (sizeof(PIV_SLOT_MAPPING) / sizeof(PIV_SLOT_MAPPING[0]))

/**
 * @brief Set a single attribute value with bounds checking
 *
 * @param attribute The attribute to set
 * @param value The value to set
 * @param cbValue Size of the value
 * @return CK_RV CKR_OK on success, error code otherwise
 */
static CK_RV setSingleAttributeValue(CK_ATTRIBUTE_PTR attribute, const void *value, CK_ULONG cbValue) {
  if (!attribute) {
    CNK_ERROR("Attribute pointer is NULL");
    return CKR_ARGUMENTS_BAD;
  }

  // Always update the value length
  attribute->ulValueLen = cbValue;

  // If pValue is NULL, we're just querying the required size
  if (!attribute->pValue) {
    return CKR_OK;
  }

  // Check if the provided buffer is large enough
  if (attribute->ulValueLen < cbValue) {
    return CKR_BUFFER_TOO_SMALL;
  }

  // Copy the value if provided
  if (value && cbValue > 0) {
    memcpy(attribute->pValue, value, cbValue);
  }

  return CKR_OK;
}

static CK_RV writeTlvLength(CK_BYTE *buffer, CK_ULONG bufferLen, CK_ULONG length, CK_ULONG_PTR written) {
  CNK_ENSURE_NONNULL(buffer, written);

  if (length < 0x80) {
    if (bufferLen < 1)
      CNK_RETURN(CKR_BUFFER_TOO_SMALL, "length buffer too small");
    buffer[0] = (CK_BYTE)length;
    *written = 1;
  } else if (length <= 0xFF) {
    if (bufferLen < 2)
      CNK_RETURN(CKR_BUFFER_TOO_SMALL, "length buffer too small");
    buffer[0] = 0x81;
    buffer[1] = (CK_BYTE)length;
    *written = 2;
  } else if (length <= 0xFFFF) {
    if (bufferLen < 3)
      CNK_RETURN(CKR_BUFFER_TOO_SMALL, "length buffer too small");
    buffer[0] = 0x82;
    buffer[1] = (CK_BYTE)(length >> 8);
    buffer[2] = (CK_BYTE)length;
    *written = 3;
  } else {
    CNK_RETURN(CKR_DATA_LEN_RANGE, "TLV length too large");
  }

  CNK_RET_OK;
}

static CK_RV appendTlv(CK_BYTE *buffer, CK_ULONG bufferLen, CK_ULONG_PTR offset, CK_BYTE tag, const CK_BYTE *value,
                       CK_ULONG valueLen) {
  CNK_ENSURE_NONNULL(buffer, offset);
  if (valueLen > 0)
    CNK_ENSURE_NONNULL(value);

  if (*offset >= bufferLen)
    CNK_RETURN(CKR_BUFFER_TOO_SMALL, "TLV buffer full");
  buffer[(*offset)++] = tag;

  CK_ULONG lengthSize;
  CNK_ENSURE_OK(writeTlvLength(buffer + *offset, bufferLen - *offset, valueLen, &lengthSize));
  *offset += lengthSize;

  if (bufferLen - *offset < valueLen)
    CNK_RETURN(CKR_BUFFER_TOO_SMALL, "TLV value buffer too small");
  if (valueLen > 0)
    memcpy(buffer + *offset, value, valueLen);
  *offset += valueLen;

  CNK_RET_OK;
}

/**
 * @brief Extract object information from a handle
 *
 * @param hObject The object handle
 * @param slotId [out] Slot ID (can be NULL)
 * @param objClass [out] Object class (can be NULL)
 * @param objId [out] Object ID (can be NULL)
 */
static void extractObjectInfo(CK_OBJECT_HANDLE hObject, CK_SLOT_ID *slotId, CK_OBJECT_CLASS *objClass, CK_BYTE *objId) {
  if (slotId) {
    *slotId = (hObject & OBJECT_SLOT_MASK) >> OBJECT_SLOT_SHIFT;
  }

  if (objClass) {
    *objClass = (hObject & OBJECT_CLASS_MASK) >> OBJECT_CLASS_SHIFT;
  }

  if (objId) {
    *objId = hObject & OBJECT_ID_MASK;
  }
}

/**
 * @brief Convert algorithm type to key type
 *
 * @param algorithmType The algorithm type
 * @return CK_KEY_TYPE The corresponding key type
 */
static CK_KEY_TYPE algoType2KeyType(CK_BYTE algorithmType) {
  switch (algorithmType) {
  case PIV_ALG_RSA_2048:
  case PIV_ALG_RSA_3072:
  case PIV_ALG_RSA_4096:
    return CKK_RSA;

  case PIV_ALG_ECC_256:
  case PIV_ALG_ECC_384:
  case PIV_ALG_SECP256K1:
  case PIV_ALG_SM2:
    return CKK_EC;

  case PIV_ALG_ED25519:
    return CKK_EC_EDWARDS;

  case PIV_ALG_X25519:
    return CKK_EC_MONTGOMERY;

  default:
    CNK_WARN("Unknown algorithm type: 0x%02X", algorithmType);
    return CKK_VENDOR_DEFINED;
  }
}

/**
 * @brief Handle certificate-specific attributes
 *
 * @param attribute The attribute to handle
 * @param data Certificate data
 * @param data_len Length of certificate data
 * @return CK_RV CKR_OK on success, error code otherwise
 */
static CK_RV handleCertificateAttribute(CK_ATTRIBUTE_PTR attribute, CK_BYTE_PTR data, CK_ULONG data_len);

/**
 * @brief Handle public key attributes
 *
 * @param attribute The attribute to handle
 * @param algorithmType The key algorithm type
 * @param pbPublicKey Public key data
 * @param cbPublicKey Length of public key data
 * @return CK_RV CKR_OK on success, error code otherwise
 */
static CK_RV handlePublicKeyAttribute(CK_ATTRIBUTE_PTR attribute, CK_BYTE algorithmType, CK_BYTE_PTR pbPublicKey,
                                      CK_ULONG cbPublicKey);

/**
 * @brief Handle private key attributes
 *
 * @param attribute The attribute to handle
 * @param algorithmType The key algorithm type
 * @param pinPolicy The stored PIV PIN policy
 * @return CK_RV CKR_OK on success, error code otherwise
 */
static CK_RV handlePrivateKeyAttribute(CK_ATTRIBUTE_PTR attribute, CK_BYTE algorithmType, CK_BYTE pinPolicy);

/**
 * @brief Handle session secret-key attributes
 *
 * @param attribute The attribute to handle
 * @param secret The session secret-key object
 * @return CK_RV CKR_OK on success, error code otherwise
 */
static CK_RV handleSecretKeyAttribute(CK_ATTRIBUTE_PTR attribute, const CNK_PKCS11_SECRET_KEY_OBJECT *secret);

/**
 * @brief Check if an object matches a template
 *
 * @param hSession Session handle
 * @param hObject Object handle
 * @param pTemplate Template to match against
 * @param ulCount Number of attributes in template
 * @return CK_BBOOL CK_TRUE if object matches template, CK_FALSE otherwise
 */
static CK_BBOOL matchTemplate(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                              CK_ULONG ulCount);

static CK_OBJECT_HANDLE makeObjectHandle(CK_SLOT_ID slotId, CK_OBJECT_CLASS objectClass, CK_BYTE objectId) {
  return (slotId << OBJECT_SLOT_SHIFT) | (objectClass << OBJECT_CLASS_SHIFT) | objectId;
}

CK_OBJECT_HANDLE CNK_MakeObjectHandle(CK_SLOT_ID slotId, CK_OBJECT_CLASS objectClass, CK_BYTE objectId) {
  return makeObjectHandle(slotId, objectClass, objectId);
}

static CNK_PKCS11_SECRET_KEY_OBJECT *findSessionSecretKey(CNK_PKCS11_SESSION *session, CK_BYTE objId) {
  if (session == NULL)
    return NULL;

  for (CK_ULONG i = 0; i < MAX_SESSION_SECRET_KEYS; i++) {
    if (session->secretKeys[i].active && session->secretKeys[i].id == objId)
      return &session->secretKeys[i];
  }

  return NULL;
}

static CK_BBOOL isSessionSecretHandle(CNK_PKCS11_SESSION *session, CK_OBJECT_HANDLE hObject,
                                      CNK_PKCS11_SECRET_KEY_OBJECT **secret) {
  CK_SLOT_ID slotId;
  CK_OBJECT_CLASS objClass;
  CK_BYTE objId;

  extractObjectInfo(hObject, &slotId, &objClass, &objId);
  if (slotId != session->slotId || objClass != OBJECT_CLASS_SECRET_KEY_HANDLE)
    return CK_FALSE;

  CNK_PKCS11_SECRET_KEY_OBJECT *found = findSessionSecretKey(session, objId);
  if (found == NULL)
    return CK_FALSE;

  if (secret != NULL)
    *secret = found;
  return CK_TRUE;
}

static CK_RV getAttr(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_ATTRIBUTE_TYPE type, CK_ATTRIBUTE_PTR *attr) {
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

static CK_RV getOptionalAttr(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_ATTRIBUTE_TYPE type,
                             CK_ATTRIBUTE_PTR *attr) {
  CNK_ENSURE_NONNULL(attr);
  *attr = NULL;

  for (CK_ULONG i = 0; i < ulCount; i++) {
    if (pTemplate[i].type == type) {
      *attr = &pTemplate[i];
      break;
    }
  }

  CNK_RET_OK;
}

static CK_RV attrGetByte(CK_ATTRIBUTE_PTR attr, CK_BYTE *value) {
  CNK_ENSURE_NONNULL(attr, value);
  if (attr->pValue == NULL || attr->ulValueLen != sizeof(CK_BYTE))
    CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad byte attribute");
  *value = *(CK_BYTE *)attr->pValue;
  CNK_RET_OK;
}

static CK_RV attrGetObjectClass(CK_ATTRIBUTE_PTR attr, CK_OBJECT_CLASS *value) {
  CNK_ENSURE_NONNULL(attr, value);
  if (attr->pValue == NULL || attr->ulValueLen != sizeof(CK_OBJECT_CLASS))
    CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CKA_CLASS attribute");
  *value = *(CK_OBJECT_CLASS *)attr->pValue;
  CNK_RET_OK;
}

static CK_RV checkPivObjectExists(CNK_PKCS11_SESSION *session, CK_OBJECT_CLASS objectClass, CK_BYTE objectId,
                                  CK_BBOOL *exists) {
  CK_SLOT_ID slotId = session->slotId;
  CK_BYTE pivTag;
  CK_BYTE certTag;
  CK_RV rv;

  CNK_ENSURE_NONNULL(exists);
  *exists = CK_FALSE;

  if (objectId < 1 || objectId > 6) {
    return CKR_OK;
  }

  rv = C_CNK_ObjIdToPivTag(objectId, &pivTag);
  if (rv == CKR_OBJECT_HANDLE_INVALID) {
    return CKR_OK;
  }
  if (rv != CKR_OK) {
    return rv;
  }

  switch (objectClass) {
  case CKO_CERTIFICATE:
    rv = CNK_ObjectIdToCertificateTag(objectId, &certTag);
    if (rv == CKR_OBJECT_HANDLE_INVALID) {
      return CKR_OK;
    }
    if (rv != CKR_OK) {
      return rv;
    }

    rv = cnk_get_piv_data(slotId, certTag, NULL, NULL, CK_FALSE);
    if (rv == CKR_OK) {
      *exists = CK_TRUE;
      return CKR_OK;
    }
    if (rv == CKR_DATA_INVALID) {
      return CKR_OK;
    }
    return rv;

  case CKO_PUBLIC_KEY:
  case CKO_PRIVATE_KEY: {
    CK_BYTE algorithmType = 0;
    CK_BYTE publicKey[MAX_PUBLIC_KEY_SIZE];
    CK_ULONG publicKeyLen = sizeof(publicKey);
    rv = cnk_get_metadata(slotId, pivTag, &algorithmType, publicKey, &publicKeyLen, NULL, NULL);
    if (rv == CKR_OK) {
      *exists = CK_TRUE;
      return CKR_OK;
    }
    if (rv == CKR_DATA_INVALID || rv == CKR_OBJECT_HANDLE_INVALID || rv == CKR_KEY_HANDLE_INVALID) {
      return CKR_OK;
    }
    return rv;
  }

  default:
    return CKR_OK;
  }
}

static CK_RV getTemplateObjectId(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_BYTE *objId) {
  CK_ATTRIBUTE_PTR attr;
  CNK_ENSURE_OK(getAttr(pTemplate, ulCount, CKA_ID, &attr));
  CNK_ENSURE_OK(attrGetByte(attr, objId));
  if (*objId < 1 || *objId > 6)
    CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "unsupported PIV object ID");

  CNK_RET_OK;
}

static CK_RV getTemplateObjectClass(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_CLASS *objectClass) {
  CK_ATTRIBUTE_PTR attr;
  CNK_ENSURE_OK(getAttr(pTemplate, ulCount, CKA_CLASS, &attr));
  CNK_ENSURE_OK(attrGetObjectClass(attr, objectClass));
  CNK_RET_OK;
}

static CK_RV getTemplateKeyType(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_KEY_TYPE *keyType) {
  CK_ATTRIBUTE_PTR attr;
  CNK_ENSURE_NONNULL(keyType);
  CNK_ENSURE_OK(getAttr(pTemplate, ulCount, CKA_KEY_TYPE, &attr));
  if (attr->pValue == NULL || attr->ulValueLen != sizeof(CK_KEY_TYPE))
    CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CKA_KEY_TYPE attribute");
  *keyType = *(CK_KEY_TYPE *)attr->pValue;
  CNK_RET_OK;
}

static CK_RV getOptionalBbool(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_ATTRIBUTE_TYPE type,
                              CK_BBOOL defaultValue, CK_BBOOL *value) {
  CK_ATTRIBUTE_PTR attr;
  CK_BBOOL boolValue;
  CNK_ENSURE_NONNULL(value);
  CNK_ENSURE_OK(getOptionalAttr(pTemplate, ulCount, type, &attr));
  if (attr == NULL) {
    *value = defaultValue;
    CNK_RET_OK;
  }
  if (attr->pValue == NULL || attr->ulValueLen != sizeof(CK_BBOOL))
    CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CK_BBOOL attribute");
  boolValue = *(CK_BBOOL *)attr->pValue;
  if (boolValue != CK_FALSE && boolValue != CK_TRUE)
    CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CK_BBOOL value");
  *value = boolValue;
  CNK_RET_OK;
}

static CK_RV getOptionalByte(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_ATTRIBUTE_TYPE type, CK_BYTE defaultValue,
                             CK_BYTE *value) {
  CK_ATTRIBUTE_PTR attr;
  CNK_ENSURE_NONNULL(value);
  CNK_ENSURE_OK(getOptionalAttr(pTemplate, ulCount, type, &attr));
  if (attr == NULL) {
    *value = defaultValue;
    CNK_RET_OK;
  }
  CNK_ENSURE_OK(attrGetByte(attr, value));
  CNK_RET_OK;
}

static CK_RV validatePivPinPolicy(CK_BYTE policy) {
  if (policy < CNK_PIV_PIN_POLICY_NEVER || policy > CNK_PIV_PIN_POLICY_ALWAYS)
    CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CKA_CNK_PIV_PIN_POLICY");

  CNK_RET_OK;
}

static CK_RV validatePivTouchPolicy(CK_BYTE policy) {
  if (policy < CNK_PIV_TOUCH_POLICY_NEVER || policy > CNK_PIV_TOUCH_POLICY_CACHED)
    CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad CKA_CNK_PIV_TOUCH_POLICY");

  CNK_RET_OK;
}

CK_RV CNK_GetPivPolicies(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_BYTE defaultPinPolicy, CK_BYTE *pinPolicy,
                         CK_BYTE *touchPolicy) {
  CK_BBOOL alwaysAuthenticate;
  CNK_ENSURE_NONNULL(pinPolicy, touchPolicy);
  CNK_ENSURE_OK(validatePivPinPolicy(defaultPinPolicy));
  CNK_ENSURE_OK(getOptionalBbool(pTemplate, ulCount, CKA_ALWAYS_AUTHENTICATE, CK_FALSE, &alwaysAuthenticate));

  *pinPolicy = alwaysAuthenticate ? CNK_PIV_PIN_POLICY_ALWAYS : defaultPinPolicy;
  CNK_ENSURE_OK(getOptionalByte(pTemplate, ulCount, CKA_CNK_PIV_PIN_POLICY, *pinPolicy, pinPolicy));
  CNK_ENSURE_OK(getOptionalByte(pTemplate, ulCount, CKA_CNK_PIV_TOUCH_POLICY, CNK_PIV_TOUCH_POLICY_NEVER, touchPolicy));
  CNK_ENSURE_OK(validatePivPinPolicy(*pinPolicy));
  CNK_ENSURE_OK(validatePivTouchPolicy(*touchPolicy));
  CNK_RET_OK;
}

static CK_RV buildPivCertificateObject(CK_BYTE_PTR cert, CK_ULONG certLen, CK_BYTE *output, CK_ULONG outputLen,
                                       CK_ULONG_PTR written) {
  CNK_ENSURE_NONNULL(cert, output, written);

  CK_BYTE inner[MAX_PIV_CERTIFICATE_OBJECT_SIZE];
  CK_ULONG innerLen = 0;
  CK_BYTE certInfo[] = {0x00};

  CNK_ENSURE_OK(appendTlv(inner, sizeof(inner), &innerLen, 0x70, cert, certLen));
  CNK_ENSURE_OK(appendTlv(inner, sizeof(inner), &innerLen, 0x71, certInfo, sizeof(certInfo)));
  CNK_ENSURE_OK(appendTlv(inner, sizeof(inner), &innerLen, 0xFE, NULL, 0));

  CK_ULONG offset = 0;
  CNK_ENSURE_OK(appendTlv(output, outputLen, &offset, 0x53, inner, innerLen));
  *written = offset;

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

static CK_RV rsaComponentSizeToAlgorithm(CK_ULONG componentLen, CK_BYTE *algorithmType) {
  CNK_ENSURE_NONNULL(algorithmType);

  switch (componentLen) {
  case 128:
    *algorithmType = PIV_ALG_RSA_2048;
    break;
  case 192:
    *algorithmType = PIV_ALG_RSA_3072;
    break;
  case 256:
    *algorithmType = PIV_ALG_RSA_4096;
    break;
  default:
    CNK_RETURN(CKR_KEY_SIZE_RANGE, "unsupported RSA CRT component size");
  }

  CNK_RET_OK;
}

static CK_RV appendImportTlv(CK_BYTE *buffer, CK_ULONG bufferLen, CK_ULONG_PTR offset, CK_BYTE tag,
                             CK_ATTRIBUTE_PTR attr) {
  CNK_ENSURE_NONNULL(attr);
  if (attr->pValue == NULL || attr->ulValueLen == 0 || attr->ulValueLen > 0xFFFF)
    CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad private-key component attribute");

  CNK_ENSURE_OK(appendTlv(buffer, bufferLen, offset, tag, attr->pValue, attr->ulValueLen));
  CNK_RET_OK;
}

static CK_RV buildRsaImportData(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_BYTE *output, CK_ULONG outputLen,
                                CK_ULONG_PTR written, CK_BYTE *algorithmType) {
  CK_ATTRIBUTE_PTR pAttr;
  CK_ATTRIBUTE_PTR qAttr;
  CK_ATTRIBUTE_PTR dpAttr;
  CK_ATTRIBUTE_PTR dqAttr;
  CK_ATTRIBUTE_PTR qInvAttr;
  CK_BYTE pinPolicy;
  CK_BYTE touchPolicy;
  CK_ULONG offset = 0;

  CNK_ENSURE_NONNULL(output, written, algorithmType);
  CNK_ENSURE_OK(getAttr(pTemplate, ulCount, CKA_PRIME_1, &pAttr));
  CNK_ENSURE_OK(getAttr(pTemplate, ulCount, CKA_PRIME_2, &qAttr));
  CNK_ENSURE_OK(getAttr(pTemplate, ulCount, CKA_EXPONENT_1, &dpAttr));
  CNK_ENSURE_OK(getAttr(pTemplate, ulCount, CKA_EXPONENT_2, &dqAttr));
  CNK_ENSURE_OK(getAttr(pTemplate, ulCount, CKA_COEFFICIENT, &qInvAttr));

  if (pAttr->pValue == NULL || qAttr->pValue == NULL || dpAttr->pValue == NULL || dqAttr->pValue == NULL ||
      qInvAttr->pValue == NULL) {
    CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "missing RSA CRT component value");
  }
  if (pAttr->ulValueLen != qAttr->ulValueLen || pAttr->ulValueLen != dpAttr->ulValueLen ||
      pAttr->ulValueLen != dqAttr->ulValueLen || pAttr->ulValueLen != qInvAttr->ulValueLen) {
    CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "RSA CRT component sizes do not match");
  }

  CNK_ENSURE_OK(rsaComponentSizeToAlgorithm(pAttr->ulValueLen, algorithmType));
  CK_BYTE objId;
  CNK_ENSURE_OK(getTemplateObjectId(pTemplate, ulCount, &objId));
  CNK_ENSURE_OK(
      CNK_GetPivPolicies(pTemplate, ulCount, CNK_DefaultPinPolicyForPivObjectId(objId), &pinPolicy, &touchPolicy));

  CNK_ENSURE_OK(appendImportTlv(output, outputLen, &offset, 0x01, pAttr));
  CNK_ENSURE_OK(appendImportTlv(output, outputLen, &offset, 0x02, qAttr));
  CNK_ENSURE_OK(appendImportTlv(output, outputLen, &offset, 0x03, dpAttr));
  CNK_ENSURE_OK(appendImportTlv(output, outputLen, &offset, 0x04, dqAttr));
  CNK_ENSURE_OK(appendImportTlv(output, outputLen, &offset, 0x05, qInvAttr));
  CNK_ENSURE_OK(appendTlv(output, outputLen, &offset, 0xAA, &pinPolicy, sizeof(pinPolicy)));
  CNK_ENSURE_OK(appendTlv(output, outputLen, &offset, 0xAB, &touchPolicy, sizeof(touchPolicy)));

  *written = offset;
  CNK_RET_OK;
}

static CK_RV buildEcImportData(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_BYTE *output, CK_ULONG outputLen,
                               CK_ULONG_PTR written, CK_BYTE *algorithmType) {
  CK_ATTRIBUTE_PTR paramsAttr;
  CK_ATTRIBUTE_PTR valueAttr;
  CK_BYTE pinPolicy;
  CK_BYTE touchPolicy;
  CK_ULONG offset = 0;

  CNK_ENSURE_NONNULL(output, written, algorithmType);
  CNK_ENSURE_OK(getAttr(pTemplate, ulCount, CKA_EC_PARAMS, &paramsAttr));
  CNK_ENSURE_OK(getAttr(pTemplate, ulCount, CKA_VALUE, &valueAttr));
  if (paramsAttr->pValue == NULL || valueAttr->pValue == NULL || valueAttr->ulValueLen == 0)
    CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad EC private-key template");

  CNK_ENSURE_OK(ecParamsToAlgorithm((CK_BYTE_PTR)paramsAttr->pValue, paramsAttr->ulValueLen, algorithmType));
  switch (*algorithmType) {
  case PIV_ALG_ECC_256:
  case PIV_ALG_SECP256K1:
    if (valueAttr->ulValueLen != 32)
      CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad P-256 private scalar size");
    break;
  case PIV_ALG_ECC_384:
    if (valueAttr->ulValueLen != 48)
      CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad P-384 private scalar size");
    break;
  default:
    CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "unsupported EC key type");
  }

  CK_BYTE objId;
  CNK_ENSURE_OK(getTemplateObjectId(pTemplate, ulCount, &objId));
  CNK_ENSURE_OK(
      CNK_GetPivPolicies(pTemplate, ulCount, CNK_DefaultPinPolicyForPivObjectId(objId), &pinPolicy, &touchPolicy));
  CNK_ENSURE_OK(appendImportTlv(output, outputLen, &offset, 0x06, valueAttr));
  CNK_ENSURE_OK(appendTlv(output, outputLen, &offset, 0xAA, &pinPolicy, sizeof(pinPolicy)));
  CNK_ENSURE_OK(appendTlv(output, outputLen, &offset, 0xAB, &touchPolicy, sizeof(touchPolicy)));

  *written = offset;
  CNK_RET_OK;
}

static CK_RV appendMatchingPivObjects(CNK_PKCS11_SESSION *session, CK_SESSION_HANDLE hSession,
                                      CK_OBJECT_CLASS objectClass, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  CK_BYTE firstId = session->findIdSpecified ? session->findObjectId : 1;
  CK_BYTE lastId = session->findIdSpecified ? session->findObjectId : 6;

  for (CK_BYTE id = firstId; id <= lastId; id++) {
    CK_BBOOL exists;
    CK_RV rv = checkPivObjectExists(session, objectClass, id, &exists);
    if (rv != CKR_OK) {
      return rv;
    }
    if (!exists) {
      continue;
    }

    CK_OBJECT_HANDLE hObject = makeObjectHandle(session->slotId, objectClass, id);
    if (ulCount == 0 || matchTemplate(hSession, hObject, pTemplate, ulCount)) {
      if (session->findObjectsCount >= MAX_FIND_OBJECTS) {
        return CKR_HOST_MEMORY;
      }
      session->findObjects[session->findObjectsCount++] = hObject;
    }
  }

  return CKR_OK;
}

static CK_RV appendMatchingSecretObjects(CNK_PKCS11_SESSION *session, CK_SESSION_HANDLE hSession,
                                         CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  for (CK_ULONG i = 0; i < MAX_SESSION_SECRET_KEYS; i++) {
    if (!session->secretKeys[i].active)
      continue;

    CK_BYTE id = session->secretKeys[i].id;
    if (session->findIdSpecified && session->findObjectId != id)
      continue;

    CK_OBJECT_HANDLE hObject = makeObjectHandle(session->slotId, CKO_SECRET_KEY, id);
    if (ulCount == 0 || matchTemplate(hSession, hObject, pTemplate, ulCount)) {
      if (session->findObjectsCount >= MAX_FIND_OBJECTS)
        return CKR_HOST_MEMORY;

      session->findObjects[session->findObjectsCount++] = hObject;
    }
  }

  return CKR_OK;
}

/**
 * @brief Map a PIV object ID to its corresponding PIV tag
 *
 * @param objId The PIV object ID to map
 * @param pivTag [out] Pointer to store the resulting PIV tag
 * @return CK_RV CKR_OK on success, CKR_OBJECT_HANDLE_INVALID if the object ID is unknown
 */
CK_RV C_CNK_ObjIdToPivTag(CK_BYTE objId, CK_BYTE *pivTag) {
  if (!pivTag) {
    CNK_ERROR("pivTag cannot be NULL");
    return CKR_ARGUMENTS_BAD;
  }

  for (size_t i = 0; i < PIV_SLOT_MAPPING_SIZE; i++) {
    if (PIV_SLOT_MAPPING[i].objId == objId) {
      *pivTag = PIV_SLOT_MAPPING[i].pivTag;
      CNK_DEBUG("Mapped object ID 0x%02X to PIV tag 0x%02X", objId, *pivTag);
      return CKR_OK;
    }
  }

  CNK_ERROR("Invalid object ID: 0x%02X", objId);
  return CKR_OBJECT_HANDLE_INVALID;
}

CK_RV CNK_ObjectIdToPivTag(CK_BYTE objId, CK_BYTE *pivTag) { return C_CNK_ObjIdToPivTag(objId, pivTag); }

CK_BYTE CNK_DefaultPinPolicyForPivObjectId(CK_BYTE objId) {
  return objId == PIV_SLOT_9E ? CNK_PIV_PIN_POLICY_NEVER : CNK_PIV_PIN_POLICY_ONCE;
}

CK_BBOOL CNK_PivPrivateKeyCanSign(CK_BYTE algorithmType) {
  switch (algorithmType) {
  case PIV_ALG_RSA_2048:
  case PIV_ALG_RSA_3072:
  case PIV_ALG_RSA_4096:
  case PIV_ALG_ECC_256:
  case PIV_ALG_ECC_384:
  case PIV_ALG_SECP256K1:
    return CK_TRUE;
  default:
    return CK_FALSE;
  }
}

CK_BBOOL CNK_PivPrivateKeyCanDecrypt(CK_BYTE algorithmType) {
  switch (algorithmType) {
  case PIV_ALG_RSA_2048:
  case PIV_ALG_RSA_3072:
  case PIV_ALG_RSA_4096:
    return CK_TRUE;
  default:
    return CK_FALSE;
  }
}

CK_BBOOL CNK_PivPrivateKeyCanDerive(CK_BYTE algorithmType) {
  switch (algorithmType) {
  case PIV_ALG_ECC_256:
  case PIV_ALG_ECC_384:
  case PIV_ALG_SECP256K1:
    return CK_TRUE;
  default:
    return CK_FALSE;
  }
}

CK_RV CNK_ObjectIdToCertificateTag(CK_BYTE objId, CK_BYTE *dataTag) {
  if (!dataTag) {
    CNK_ERROR("dataTag cannot be NULL");
    return CKR_ARGUMENTS_BAD;
  }

  for (size_t i = 0; i < PIV_SLOT_MAPPING_SIZE; i++) {
    if (PIV_SLOT_MAPPING[i].objId == objId) {
      *dataTag = PIV_SLOT_MAPPING[i].certTag;
      CNK_DEBUG("Mapped object ID 0x%02X to PIV certificate tag 0x%02X", objId, *dataTag);
      return CKR_OK;
    }
  }

  CNK_ERROR("Invalid object ID: 0x%02X", objId);
  return CKR_OBJECT_HANDLE_INVALID;
}

/**
 * @brief Validate an object handle against a session and expected class
 *
 * @param hObject The object handle to validate
 * @param session The session to validate against
 * @param expectedClass The expected object class (0 to skip check)
 * @param objId [out] Will contain the object ID if not NULL
 * @return CK_RV CKR_OK if valid, error code otherwise
 */
CK_RV CNK_ValidateObject(CK_OBJECT_HANDLE hObject, CNK_PKCS11_SESSION *session, CK_OBJECT_CLASS expectedClass,
                         CK_BYTE *objId) {
  if (!session) {
    CNK_ERROR("Session handle is NULL");
    return CKR_SESSION_HANDLE_INVALID;
  }

  // Extract object information from the handle
  CK_SLOT_ID slot_id;
  CK_OBJECT_CLASS obj_class;
  CK_BYTE localObjId;
  extractObjectInfo(hObject, &slot_id, &obj_class, &localObjId);
  if (objId != NULL)
    *objId = localObjId;

  // Verify the slot ID matches the session's slot ID
  if (slot_id != session->slotId) {
    CNK_ERROR("Slot ID mismatch: handle=0x%04X, session=0x%04X", slot_id, session->slotId);
    return CKR_OBJECT_HANDLE_INVALID;
  }

  // Verify the object class if expectedClass is not 0
  if (expectedClass != 0 && obj_class != expectedClass) {
    CNK_ERROR("Object class mismatch: expected=0x%08lX, actual=0x%08lX", expectedClass, obj_class);
    return CKR_KEY_TYPE_INCONSISTENT;
  }

  if (obj_class == OBJECT_CLASS_SECRET_KEY_HANDLE) {
    if (findSessionSecretKey(session, localObjId) == NULL)
      return CKR_OBJECT_HANDLE_INVALID;
    return CKR_OK;
  }

  return CKR_OK;
}

// Object operation implementations
CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                     CK_OBJECT_HANDLE_PTR phObject) {
  CNK_LOG_FUNC(": hSession: %lu, pTempate: %p, ulCount: %lu, phObject: %p", hSession, pTemplate, ulCount, phObject);
  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(phObject);
  if (ulCount > 0)
    CNK_ENSURE_NONNULL(pTemplate);

  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  if (!(session->flags & CKF_RW_SESSION))
    CNK_RETURN(CKR_SESSION_READ_ONLY, "write session is required");
  if (session->state != SESSION_STATE_RW_SO)
    CNK_RETURN(CKR_USER_NOT_LOGGED_IN, "CKU_SO login is required");

  CK_OBJECT_CLASS objectClass;
  CK_BYTE objId;
  CNK_ENSURE_OK(getTemplateObjectClass(pTemplate, ulCount, &objectClass));
  CNK_ENSURE_OK(getTemplateObjectId(pTemplate, ulCount, &objId));

  switch (objectClass) {
  case CKO_CERTIFICATE: {
    CK_ATTRIBUTE_PTR valueAttr;
    CNK_ENSURE_OK(getAttr(pTemplate, ulCount, CKA_VALUE, &valueAttr));
    if (valueAttr->pValue == NULL || valueAttr->ulValueLen == 0)
      CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad certificate value");

    CK_BYTE certTag;
    CK_BYTE certObject[MAX_PIV_CERTIFICATE_OBJECT_SIZE];
    CK_ULONG certObjectLen = 0;
    CNK_ENSURE_OK(CNK_ObjectIdToCertificateTag(objId, &certTag));
    CNK_ENSURE_OK(buildPivCertificateObject((CK_BYTE_PTR)valueAttr->pValue, valueAttr->ulValueLen, certObject,
                                            sizeof(certObject), &certObjectLen));
    CNK_ENSURE_OK(cnk_put_piv_data(session->slotId, session, certTag, certObject, certObjectLen));

    *phObject = makeObjectHandle(session->slotId, CKO_CERTIFICATE, objId);
    CNK_RET_OK;
  }

  case CKO_PRIVATE_KEY: {
    CK_KEY_TYPE keyType;
    CK_BYTE pivTag;
    CK_BYTE algorithmType;
    CK_BYTE importData[MAX_PIV_IMPORT_KEY_SIZE];
    CK_ULONG importDataLen = 0;

    CNK_ENSURE_OK(getTemplateKeyType(pTemplate, ulCount, &keyType));
    CNK_ENSURE_OK(CNK_ObjectIdToPivTag(objId, &pivTag));

    switch (keyType) {
    case CKK_RSA:
      CNK_ENSURE_OK(
          buildRsaImportData(pTemplate, ulCount, importData, sizeof(importData), &importDataLen, &algorithmType));
      break;
    case CKK_EC:
      CNK_ENSURE_OK(
          buildEcImportData(pTemplate, ulCount, importData, sizeof(importData), &importDataLen, &algorithmType));
      break;
    default:
      CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "unsupported private key type for C_CreateObject");
    }

    CK_RV rv = cnk_piv_import_key(session->slotId, session, algorithmType, pivTag, importData, importDataLen);
    mbedtls_platform_zeroize(importData, sizeof(importData));
    CNK_ENSURE_OK(rv);

    *phObject = makeObjectHandle(session->slotId, CKO_PRIVATE_KEY, objId);
    CNK_RET_OK;
  }

  default:
    CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "unsupported object class for C_CreateObject");
  }
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                   CK_OBJECT_HANDLE_PTR phNewObject) {
  CNK_LOG_FUNC(": hSession: %lu, hObject: %lu, pTemplate: %p, ulCount: %lu, phNewObject: %p", hSession, hObject,
               pTemplate, ulCount, phNewObject);
  CNK_ENSURE_INITIALIZED();

  CNK_RET_UNSUPPORTED;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
  CNK_LOG_FUNC(": hSession: %lu, hObject: %lu", hSession, hObject);
  CNK_ENSURE_INITIALIZED();

  // CanoKey PIV has PUT DATA and key import/generation APDUs, but this module
  // intentionally does not expose object deletion yet. Key deletion has no
  // standard PIV APDU, and certificate deletion would use the CanoKey/Yubico
  // special case of PUT DATA with an empty certificate object.
  CNK_RET_NOT_IMPLEMENTED;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) {
  CNK_LOG_FUNC(": hSession: %lu, hObject: %lu, pulSize: %p", hSession, hObject, pulSize);
  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pulSize);

  CK_OBJECT_CLASS objClass;
  extractObjectInfo(hObject, NULL, &objClass, NULL);

  CK_ATTRIBUTE sizeAttrs[] = {
      {CKA_CLASS, NULL_PTR, 0}, {CKA_TOKEN, NULL_PTR, 0}, {CKA_PRIVATE, NULL_PTR, 0},
      {CKA_ID, NULL_PTR, 0},    {CKA_LABEL, NULL_PTR, 0}, {CKA_KEY_TYPE, NULL_PTR, 0},
  };

  switch (objClass) {
  case CKO_CERTIFICATE:
    sizeAttrs[5].type = CKA_CERTIFICATE_TYPE;
    break;
  case CKO_PUBLIC_KEY:
  case CKO_PRIVATE_KEY:
  case OBJECT_CLASS_SECRET_KEY_HANDLE:
    break;
  default:
    CNK_RETURN(CKR_OBJECT_HANDLE_INVALID, "Invalid object class");
  }

  CK_RV rv = C_GetAttributeValue(hSession, hObject, sizeAttrs, sizeof(sizeAttrs) / sizeof(sizeAttrs[0]));
  if (rv != CKR_OK)
    CNK_RETURN(rv, "failed to query object size attributes");

  CK_ULONG size = 0;
  for (CK_ULONG i = 0; i < sizeof(sizeAttrs) / sizeof(sizeAttrs[0]); i++) {
    if (sizeAttrs[i].ulValueLen == CK_UNAVAILABLE_INFORMATION)
      continue;
    size += sizeof(CK_ATTRIBUTE) + sizeAttrs[i].ulValueLen;
  }

  if (objClass == CKO_PUBLIC_KEY || objClass == CKO_PRIVATE_KEY) {
    CK_ULONG baseSize = size;
    CK_ATTRIBUTE keyPolicyAttrs[] = {
        {CKA_CNK_PIV_PIN_POLICY, NULL_PTR, 0},
        {CKA_CNK_PIV_TOUCH_POLICY, NULL_PTR, 0},
    };
    rv = C_GetAttributeValue(hSession, hObject, keyPolicyAttrs, sizeof(keyPolicyAttrs) / sizeof(keyPolicyAttrs[0]));
    if (rv != CKR_OK)
      CNK_RETURN(rv, "failed to query PIV key policy size attributes");
    for (CK_ULONG i = 0; i < sizeof(keyPolicyAttrs) / sizeof(keyPolicyAttrs[0]); i++) {
      if (keyPolicyAttrs[i].ulValueLen != CK_UNAVAILABLE_INFORMATION)
        size += sizeof(CK_ATTRIBUTE) + keyPolicyAttrs[i].ulValueLen;
    }

    if (objClass == CKO_PRIVATE_KEY) {
      if (size == baseSize)
        CNK_RETURN(rv, "failed to find any private object size attributes");
    } else {
      CK_ATTRIBUTE publicAttrs[] = {
          {CKA_MODULUS, NULL_PTR, 0},   {CKA_PUBLIC_EXPONENT, NULL_PTR, 0}, {CKA_EC_POINT, NULL_PTR, 0},
          {CKA_EC_PARAMS, NULL_PTR, 0}, {CKA_MODULUS_BITS, NULL_PTR, 0},
      };
      rv = C_GetAttributeValue(hSession, hObject, publicAttrs, sizeof(publicAttrs) / sizeof(publicAttrs[0]));
      if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID && rv != CKR_ATTRIBUTE_VALUE_INVALID)
        CNK_RETURN(rv, "failed to query public object size attributes");
      for (CK_ULONG i = 0; i < sizeof(publicAttrs) / sizeof(publicAttrs[0]); i++) {
        if (publicAttrs[i].ulValueLen != CK_UNAVAILABLE_INFORMATION)
          size += sizeof(CK_ATTRIBUTE) + publicAttrs[i].ulValueLen;
      }
      if (size == baseSize)
        CNK_RETURN(rv, "failed to find any public object size attributes");
    }
  } else if (objClass == CKO_CERTIFICATE) {
    CK_ATTRIBUTE certValue = {CKA_VALUE, NULL_PTR, 0};
    rv = C_GetAttributeValue(hSession, hObject, &certValue, 1);
    if (rv != CKR_OK)
      CNK_RETURN(rv, "failed to query certificate value size");
    size += sizeof(CK_ATTRIBUTE) + certValue.ulValueLen;
  } else if (objClass == OBJECT_CLASS_SECRET_KEY_HANDLE) {
    CK_ATTRIBUTE secretAttrs[] = {
        {CKA_VALUE_LEN, NULL_PTR, 0}, {CKA_SENSITIVE, NULL_PTR, 0}, {CKA_EXTRACTABLE, NULL_PTR, 0},
        {CKA_ENCRYPT, NULL_PTR, 0},   {CKA_DECRYPT, NULL_PTR, 0},   {CKA_SIGN, NULL_PTR, 0},
        {CKA_VERIFY, NULL_PTR, 0},    {CKA_WRAP, NULL_PTR, 0},      {CKA_UNWRAP, NULL_PTR, 0},
        {CKA_DERIVE, NULL_PTR, 0},
    };
    rv = C_GetAttributeValue(hSession, hObject, secretAttrs, sizeof(secretAttrs) / sizeof(secretAttrs[0]));
    if (rv != CKR_OK)
      CNK_RETURN(rv, "failed to query secret object size attributes");
    for (CK_ULONG i = 0; i < sizeof(secretAttrs) / sizeof(secretAttrs[0]); i++) {
      if (secretAttrs[i].ulValueLen != CK_UNAVAILABLE_INFORMATION)
        size += sizeof(CK_ATTRIBUTE) + secretAttrs[i].ulValueLen;
    }
  }

  *pulSize = size;
  CNK_RET_OK;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                          CK_ULONG ulCount) {
  CNK_LOG_FUNC(": hSession: %lu, hObject: %lu, ulCount: %lu", hSession, hObject, ulCount);
  CNK_ENSURE_INITIALIZED();

  // Validate parameters
  if (!pTemplate && ulCount > 0) {
    CNK_RETURN(CKR_ARGUMENTS_BAD, "pTemplate is null or ulCount is 0");
  }

  // Validate session
  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  CNK_PKCS11_SECRET_KEY_OBJECT *secret = NULL;
  if (isSessionSecretHandle(session, hObject, &secret)) {
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_RV rvReturn = CKR_OK;

    for (CK_ULONG i = 0; i < ulCount; i++) {
      CK_RV rv = CKR_ATTRIBUTE_TYPE_INVALID;

      switch (pTemplate[i].type) {
      case CKA_CLASS:
        rv = setSingleAttributeValue(&pTemplate[i], &secretClass, sizeof(secretClass));
        break;
      case CKA_TOKEN:
        rv = setSingleAttributeValue(&pTemplate[i], &secret->token, sizeof(secret->token));
        break;
      case CKA_PRIVATE:
        rv = setSingleAttributeValue(&pTemplate[i], &secret->private, sizeof(secret->private));
        break;
      case CKA_ID:
        rv = setSingleAttributeValue(&pTemplate[i], &secret->id, sizeof(secret->id));
        break;
      case CKA_LABEL:
        rv = setSingleAttributeValue(&pTemplate[i], secret->label, secret->labelLen);
        break;
      default:
        rv = handleSecretKeyAttribute(&pTemplate[i], secret);
        break;
      }

      if (rv != CKR_OK) {
        pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
        if (rvReturn == CKR_OK)
          rvReturn = rv;
      }
    }

    CNK_RETURN(rvReturn, "Finished secret-key attributes");
  }

  // Extract and validate object information
  CK_OBJECT_CLASS objClass;
  CK_BYTE objId;
  CNK_ENSURE_OK(CNK_ValidateObject(hObject, session, 0, &objId));

  // Get object class from handle
  extractObjectInfo(hObject, NULL, &objClass, NULL);
  CNK_DEBUG("Object handle: slot %lu, class %lu, id %lu", session->slotId, objClass, objId);

  // Map object ID to PIV tag
  CK_BYTE bPivSlot;
  CNK_ENSURE_OK(C_CNK_ObjIdToPivTag(objId, &bPivSlot));

  // Fetch the PIV data for this object
  CK_BYTE data[4096];
  CK_ULONG cbData = sizeof(data);
  CK_BYTE bAlgorithmType = 0;
  CK_BYTE bPinPolicy = 0;
  CK_BYTE bTouchPolicy = 0;
  CK_BYTE abPublicKey[512];
  CK_ULONG cbPublicKey = sizeof(abPublicKey);

  switch (objClass) {
  case CKO_PUBLIC_KEY:
  case CKO_PRIVATE_KEY: {
    CK_RV rvMeta = cnk_get_metadata(session->slotId, bPivSlot, &bAlgorithmType, abPublicKey, &cbPublicKey, &bPinPolicy,
                                    &bTouchPolicy);
    if (rvMeta != CKR_OK) {
      CNK_DEBUG("Failed to get metadata for PIV slot 0x%02X: %lu", bPivSlot, rvMeta);
    } else {
      CNK_DEBUG("Retrieved algorithm type %u for PIV slot 0x%02X with public key size %lu", bAlgorithmType, bPivSlot,
                cbPublicKey);
    }
    break;
  }

  case CKO_CERTIFICATE:
    CNK_ENSURE_OK(CNK_ObjectIdToCertificateTag(objId, &bPivSlot));
    CNK_ENSURE_OK(cnk_get_piv_data(session->slotId, bPivSlot, data, &cbData, CK_TRUE));
    if (cbData == 0) {
      CNK_RETURN(CKR_OBJECT_HANDLE_INVALID, "No data found for PIV slot");
    }
    break;

  default:
    CNK_RETURN(CKR_OBJECT_HANDLE_INVALID, "Invalid object class");
  }

  // Process each attribute in the template
  CK_RV rvReturn = CKR_OK; // Final return value

  for (CK_ULONG i = 0; i < ulCount; i++) {
    CK_RV rv = CKR_ATTRIBUTE_TYPE_INVALID; // Default to attribute not found
    CK_BBOOL bbool;

    // Common attributes for all object types
    switch (pTemplate[i].type) {
    case CKA_CLASS:
      rv = setSingleAttributeValue(&pTemplate[i], &objClass, sizeof(objClass));
      break;

    case CKA_TOKEN:
      bbool = CK_TRUE;
      rv = setSingleAttributeValue(&pTemplate[i], &bbool, sizeof(bbool));
      break;

    case CKA_PRIVATE:
      bbool = (objClass == CKO_PRIVATE_KEY) ? CK_TRUE : CK_FALSE;
      rv = setSingleAttributeValue(&pTemplate[i], &bbool, sizeof(bbool));
      break;

    case CKA_ID:
      rv = setSingleAttributeValue(&pTemplate[i], &objId, sizeof(objId));
      break;

    case CKA_LABEL: {
      // Create a label based on the object type and ID
      char label[32];
      const char *type_str = "Unknown";

      switch (objClass) {
      case CKO_CERTIFICATE:
        type_str = "Certificate";
        break;
      case CKO_PUBLIC_KEY:
        type_str = "Public Key";
        break;
      case CKO_PRIVATE_KEY:
        type_str = "Private Key";
        break;
      case CKO_DATA:
        type_str = "Data";
        break;
      default:
        // do nothing.
        break;
      }

      snprintf(label, sizeof(label), "PIV %s %02X", type_str, bPivSlot);
      CK_ULONG label_len = (CK_ULONG)strlen(label);
      rv = setSingleAttributeValue(&pTemplate[i], label, label_len);
      break;
    }

    default:
      // Not a common attribute, handle based on object class
      break;
    }

    // If we've already handled this attribute, continue to the next one
    if (rv != CKR_ATTRIBUTE_TYPE_INVALID) {
      CNK_DEBUG("Handled attribute %lu, continue.", pTemplate[i].type);
      continue;
    }

    // Object class specific attributes
    switch (objClass) {
    case CKO_CERTIFICATE:
      rv = handleCertificateAttribute(&pTemplate[i], data, cbData);
      break;

    case CKO_PUBLIC_KEY:
      if (pTemplate[i].type == CKA_CNK_PIV_PIN_POLICY) {
        rv = setSingleAttributeValue(&pTemplate[i], &bPinPolicy, sizeof(bPinPolicy));
      } else if (pTemplate[i].type == CKA_CNK_PIV_TOUCH_POLICY) {
        rv = setSingleAttributeValue(&pTemplate[i], &bTouchPolicy, sizeof(bTouchPolicy));
      } else {
        rv = handlePublicKeyAttribute(&pTemplate[i], bAlgorithmType, abPublicKey, cbPublicKey);
      }
      break;

    case CKO_PRIVATE_KEY:
      if (pTemplate[i].type == CKA_CNK_PIV_PIN_POLICY) {
        rv = setSingleAttributeValue(&pTemplate[i], &bPinPolicy, sizeof(bPinPolicy));
      } else if (pTemplate[i].type == CKA_CNK_PIV_TOUCH_POLICY) {
        rv = setSingleAttributeValue(&pTemplate[i], &bTouchPolicy, sizeof(bTouchPolicy));
      } else {
        rv = handlePrivateKeyAttribute(&pTemplate[i], bAlgorithmType, bPinPolicy);
      }
      break;

    default:
      // Unsupported object class
      rv = CKR_ATTRIBUTE_TYPE_INVALID;
      break;
    }

    if (rv != CKR_OK) {
      pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
      if (rvReturn == CKR_OK) {
        rvReturn = rv;
      }
    }
  }

  CNK_RETURN(rvReturn, "Finished");
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                          CK_ULONG ulCount) {
  CNK_LOG_FUNC(": hSession: %lu, hObject: %lu, pTemplate: %p, ulCount: %lu", hSession, hObject, pTemplate, ulCount);
  CNK_ENSURE_INITIALIZED();
  if (ulCount > 0)
    CNK_ENSURE_NONNULL(pTemplate);

  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  CNK_ENSURE_OK(CNK_ValidateObject(hObject, session, 0, NULL));

  if (ulCount == 0)
    CNK_RET_OK;

  CNK_RETURN(CKR_ATTRIBUTE_READ_ONLY, "PIV object attributes are read-only");
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  CNK_LOG_FUNC(": hSession: %lu, ulCount: %lu", hSession, ulCount);
  CNK_ENSURE_INITIALIZED();

  // Validate the session
  CNK_PKCS11_SESSION *session;
  CK_RV rv = CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  // Lock the session
  cnk_mutex_lock(&session->lock);

  // Check if a find operation is already active
  if (session->findActive) {
    cnk_mutex_unlock(&session->lock);
    return CKR_OPERATION_ACTIVE;
  }

  // Reset find operation state
  session->findActive = CK_TRUE;
  session->findObjectsCount = 0;
  session->findObjectsPosition = 0;
  session->findIdSpecified = CK_FALSE;
  session->findClassSpecified = CK_FALSE;

  // Parse the template
  for (CK_ULONG i = 0; i < ulCount; i++) {
    if (pTemplate[i].type == CKA_CLASS && pTemplate[i].pValue != NULL &&
        pTemplate[i].ulValueLen == sizeof(CK_OBJECT_CLASS)) {
      session->findObjectClass = *((CK_OBJECT_CLASS *)pTemplate[i].pValue);
      session->findClassSpecified = CK_TRUE;
    } else if (pTemplate[i].type == CKA_ID && pTemplate[i].pValue != NULL &&
               pTemplate[i].ulValueLen == sizeof(CK_BYTE)) {
      session->findObjectId = *((CK_BYTE *)pTemplate[i].pValue);
      session->findIdSpecified = CK_TRUE;
    }
  }

  // Check if the specified class is supported
  if (session->findClassSpecified && session->findObjectClass != CKO_CERTIFICATE &&
      session->findObjectClass != CKO_PUBLIC_KEY && session->findObjectClass != CKO_PRIVATE_KEY &&
      session->findObjectClass != CKO_SECRET_KEY) {
    cnk_mutex_unlock(&session->lock);
    CNK_RET_OK; // Return OK but with no results
  }

  if (session->findIdSpecified && session->findObjectId < 1) {
    cnk_mutex_unlock(&session->lock);
    CNK_RET_OK; // Return OK but with no results
  }

  if (session->findClassSpecified) {
    if (session->findObjectClass == CKO_SECRET_KEY) {
      rv = appendMatchingSecretObjects(session, hSession, pTemplate, ulCount);
    } else {
      if (session->findIdSpecified && session->findObjectId > 6) {
        rv = CKR_OK;
      } else {
        rv = appendMatchingPivObjects(session, hSession, session->findObjectClass, pTemplate, ulCount);
      }
    }
  } else {
    static const CK_OBJECT_CLASS searchableClasses[] = {CKO_CERTIFICATE, CKO_PUBLIC_KEY, CKO_PRIVATE_KEY};
    for (CK_ULONG i = 0; i < sizeof(searchableClasses) / sizeof(searchableClasses[0]); i++) {
      if (session->findIdSpecified && session->findObjectId > 6) {
        rv = CKR_OK;
      } else {
        rv = appendMatchingPivObjects(session, hSession, searchableClasses[i], pTemplate, ulCount);
      }
      if (rv != CKR_OK) {
        break;
      }
    }
    if (rv == CKR_OK)
      rv = appendMatchingSecretObjects(session, hSession, pTemplate, ulCount);
  }

  if (rv != CKR_OK) {
    session->findActive = CK_FALSE;
    cnk_mutex_unlock(&session->lock);
    return rv;
  }

  cnk_mutex_unlock(&session->lock);
  CNK_RET_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
                    CK_ULONG_PTR pulObjectCount) {
  CNK_LOG_FUNC(": hSession: %lu, ulMaxObjectCount: %lu", hSession, ulMaxObjectCount);
  CNK_ENSURE_INITIALIZED();

  // Validate parameters
  if (!phObject || !pulObjectCount)
    return CKR_ARGUMENTS_BAD;

  // Find the session
  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  // Lock the session
  cnk_mutex_lock(&session->lock);

  // Check if a find operation is active
  if (!session->findActive) {
    cnk_mutex_unlock(&session->lock);
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  // Calculate how many objects to return
  CK_ULONG remaining = session->findObjectsCount - session->findObjectsPosition;
  CK_ULONG count = (remaining < ulMaxObjectCount) ? remaining : ulMaxObjectCount;

  // Copy the object handles
  for (CK_ULONG i = 0; i < count; i++) {
    phObject[i] = session->findObjects[session->findObjectsPosition + i];
  }

  // Update the position
  session->findObjectsPosition += count;

  // Return the number of objects copied
  *pulObjectCount = count;

  cnk_mutex_unlock(&session->lock);
  CNK_RET_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
  CNK_LOG_FUNC(": hSession: %lu", hSession);
  CNK_ENSURE_INITIALIZED();

  // Find the session
  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  // Lock the session
  cnk_mutex_lock(&session->lock);

  // Check if a find operation is active
  if (!session->findActive) {
    cnk_mutex_unlock(&session->lock);
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  // End the find operation
  session->findActive = CK_FALSE;
  session->findObjectsCount = 0;
  session->findObjectsPosition = 0;

  cnk_mutex_unlock(&session->lock);
  CNK_RET_OK;
}

static CK_BBOOL matchTemplate(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                              CK_ULONG ulCount) {
  // Copy the template
  CK_ATTRIBUTE_PTR attrs = (CK_ATTRIBUTE_PTR)ck_malloc(sizeof(CK_ATTRIBUTE) * ulCount);
  if (attrs == NULL)
    CNK_RETURN(CK_FALSE, "Failed to allocate memory for attributes");

  for (CK_ULONG i = 0; i < ulCount; i++) {
    attrs[i].type = pTemplate[i].type;
    attrs[i].ulValueLen = pTemplate[i].ulValueLen;
    attrs[i].pValue = ck_malloc(pTemplate[i].ulValueLen);
    if (attrs[i].pValue == NULL) {
      for (CK_ULONG j = 0; j < i; j++) {
        ck_free(attrs[j].pValue);
      }
      ck_free(attrs);
      CNK_RETURN(CK_FALSE, "Failed to allocate memory for attribute values");
    }
  }

  // Get attribute values and compare
  CK_BBOOL matched = CK_FALSE;

  CK_RV rv = C_GetAttributeValue(hSession, hObject, attrs, ulCount);
  if (rv != CKR_OK) {
    for (CK_ULONG i = 0; i < ulCount; i++) {
      ck_free(attrs[i].pValue);
    }
    ck_free(attrs);
    CNK_RETURN(CK_FALSE, "Failed to get attribute values");
  }

  // Compare attribute values
  for (CK_ULONG i = 0; i < ulCount; i++) {
    if (attrs[i].ulValueLen != pTemplate[i].ulValueLen) {
      matched = CK_FALSE;
      break;
    }
    if (memcmp(attrs[i].pValue, pTemplate[i].pValue, attrs[i].ulValueLen) != 0) {
      matched = CK_FALSE;
      break;
    }
    matched = CK_TRUE;
  }

  // Free memory
  for (CK_ULONG i = 0; i < ulCount; i++) {
    ck_free(attrs[i].pValue);
  }
  ck_free(attrs);

  CNK_RETURN(matched, "Template matching finished");
}

/**
 * @brief Handle certificate-specific attributes
 *
 * @param attribute The attribute to handle
 * @param data Certificate data
 * @param data_len Length of certificate data
 * @return CK_RV CKR_OK on success, error code otherwise
 */
static CK_RV handleCertificateAttribute(CK_ATTRIBUTE_PTR attribute, CK_BYTE_PTR data, CK_ULONG data_len) {
  CNK_LOG_FUNC(" attribute = %d, data_len = %lu", attribute->type, data_len);

  CK_RV rv = CKR_ATTRIBUTE_TYPE_INVALID;

  switch (attribute->type) {
  case CKA_CERTIFICATE_TYPE: {
    CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
    rv = setSingleAttributeValue(attribute, &cert_type, sizeof(cert_type));
    break;
  }

  case CKA_VALUE:
    // Extract X.509 certificate from the encoded data
    // Format: 53 L1 70 L2 [cert] 71 01 00 FE 00
    if (data_len > 0 && data[0] == 0x53) {
      CK_ULONG offset = 1; // Start at the length byte after tag 0x53
      CK_LONG fail = 0;
      CK_ULONG length_size = 0;

      // Parse L1 (length of the entire structure)
      // We don't actually use l1_len for validation since tlv_get_length_safe already checks buffer bounds
      tlvGetLengthSafe(data + offset, data_len - offset, &fail, &length_size);
      if (fail) {
        CNK_DEBUG("Failed to parse L1 length field");
        rv = CKR_DATA_INVALID;
        break;
      }

      // Move offset past the length field
      offset += length_size;

      // Check for tag 0x70 (certificate data)
      if (offset < data_len && data[offset] == 0x70) {
        offset += 1; // Move to L2

        // Parse L2 (length of the certificate)
        fail = 0;
        length_size = 0;
        uint16_t cert_len = tlvGetLengthSafe(data + offset, data_len - offset, &fail, &length_size);
        if (fail) {
          CNK_DEBUG("Failed to parse L2 length field");
          rv = CKR_DATA_INVALID;
          break;
        }

        // Move offset past the length field
        offset += length_size;

        // Check if we have enough data for the certificate
        if (offset + cert_len <= data_len) {
          rv = setSingleAttributeValue(attribute, data + offset, cert_len);
        } else {
          CNK_DEBUG("Certificate data exceeds available buffer");
          rv = CKR_DATA_INVALID;
        }
      } else {
        CNK_DEBUG("Expected tag 0x70 not found");
        rv = CKR_DATA_INVALID;
      }
    } else {
      // Fallback to sending the entire data if format is unexpected
      CNK_DEBUG("Unexpected format, using entire data as certificate");
      rv = setSingleAttributeValue(attribute, data, data_len);
    }
    break;

  default:
    rv = CKR_ATTRIBUTE_TYPE_INVALID;
    break;
  }

  CNK_RETURN(rv, "-");
}

// Handle public key specific attributes
static CK_RV handlePublicKeyAttribute(CK_ATTRIBUTE_PTR attribute, CK_BYTE algorithm_type, CK_BYTE_PTR pbPublicKey,
                                      CK_ULONG cbPublicKey) {
  CNK_LOG_FUNC(" attribute = 0x%x, algorithm_type = 0x%x", attribute->type, algorithm_type);

  CK_RV rv = CKR_ATTRIBUTE_TYPE_INVALID;
  CK_KEY_TYPE keyType = algoType2KeyType(algorithm_type);

  CK_BYTE_PTR pbModulus = NULL;
  CK_ULONG cbModulus = 0;
  CK_BYTE_PTR pbPublicExponent = NULL;
  CK_ULONG cbPublicExponent = 0;
  CK_BYTE_PTR pbPublicPoint = NULL;
  CK_ULONG cbPublicPoint = 0;
  CK_BYTE abEcParams[16];
  CK_ULONG cbEcParams = 0;

  // Parse the public key data. The public key data is encoded in TLV.
  CK_ULONG vpos = 0; /* cursor inside the value buffer   */
  while (vpos < cbPublicKey) {
    /* ---- read inner tag --------------------------------------- */
    CK_BYTE itag = pbPublicKey[vpos++];
    if (vpos >= cbPublicKey)
      break; /* malformed */
    /* ---- read inner length (DER) ------------------------------ */
    CK_LONG fail;
    CK_ULONG lengthSize;
    CK_ULONG ilen = tlvGetLengthSafe(&pbPublicKey[vpos], cbPublicKey - vpos, &fail, &lengthSize);
    if (fail)
      CNK_RETURN(CKR_DEVICE_ERROR, "Bad length in public-key TLV");
    vpos += lengthSize;
    /* ---- RSA modulus lives in tag 0x81 ------------------------ */
    if (itag == 0x81) {
      pbModulus = pbPublicKey + vpos;
      cbModulus = ilen;
    }
    /* ---- RSA public exponent lives in tag 0x82 ---------------- */
    if (itag == 0x82) {
      pbPublicExponent = pbPublicKey + vpos;
      cbPublicExponent = ilen;
    }
    /* ---- ECC public point lives in tag 0x86 ---------------- */
    if (itag == 0x86) {
      pbPublicPoint = pbPublicKey + vpos;
      cbPublicPoint = ilen;
    }
    vpos += ilen; /* advance to next inner TLV        */
  }

  switch (attribute->type) {
  case CKA_KEY_TYPE:
    rv = setSingleAttributeValue(attribute, &keyType, sizeof(keyType));
    break;

  case CKA_VERIFY: {
    // Public-key verification is not implemented by this module.
    CK_BBOOL value = CK_FALSE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_VERIFY_RECOVER: {
    CK_BBOOL value = CK_FALSE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_ENCRYPT: {
    // Public-key encryption is not implemented by this module.
    CK_BBOOL value = CK_FALSE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_WRAP: {
    CK_BBOOL value = CK_FALSE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_DERIVE: {
    CK_BBOOL value = CK_FALSE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_LOCAL: {
    CK_BBOOL value = CK_FALSE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_DECRYPT: {
    // Public keys cannot decrypt
    CK_BBOOL value = CK_FALSE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_MODULUS_BITS:
    if (keyType == CKK_RSA) {
      CK_ULONG modulus_bits = cbModulus * 8;
      rv = setSingleAttributeValue(attribute, &modulus_bits, sizeof(modulus_bits));
    } else {
      // Not applicable for non-RSA keys
      rv = CKR_ATTRIBUTE_TYPE_INVALID;
    }
    break;

  case CKA_MODULUS:
    if (keyType == CKK_RSA) {
      rv = setSingleAttributeValue(attribute, pbModulus, cbModulus);
    } else {
      // Not applicable for non-RSA keys
      rv = CKR_ATTRIBUTE_TYPE_INVALID;
    }
    break;

  case CKA_PUBLIC_EXPONENT:
    if (keyType == CKK_RSA) {
      rv = setSingleAttributeValue(attribute, pbPublicExponent, cbPublicExponent);
    } else {
      // Not applicable for non-RSA keys
      rv = CKR_ATTRIBUTE_TYPE_INVALID;
    }
    break;

  case CKA_EC_POINT:
    if (keyType == CKK_EC) {
      rv = setSingleAttributeValue(attribute, pbPublicPoint, cbPublicPoint);
    } else {
      // Not applicable for non-ECC keys
      rv = CKR_ATTRIBUTE_TYPE_INVALID;
    }
    break;

  case CKA_EC_PARAMS:
    if (keyType == CKK_EC || keyType == CKK_EC_EDWARDS) {
      const char *oid = NULL;
      size_t cbOid = 0;
      switch (algorithm_type) {
      case PIV_ALG_ECC_256:
        oid = "\x2A\x86\x48\xCE\x3D\x03\x01\x07";
        cbOid = 8;
        break;
      case PIV_ALG_ECC_384:
        oid = "\x2B\x81\x04\x00\x22";
        cbOid = 5;
        break;
      case PIV_ALG_SECP256K1:
        oid = "\x2B\x81\x04\x00\x0A";
        cbOid = 5;
        break;
      default:
        CNK_ERROR("Should not be reached");
        break;
      }
      if (oid == NULL) {
        rv = CKR_ATTRIBUTE_VALUE_INVALID;
        break;
      }
      CK_BYTE_PTR pbEcParams = abEcParams + sizeof(abEcParams);
      cbEcParams = mbedtls_asn1_write_oid(&pbEcParams, abEcParams, oid, cbOid);
      rv = setSingleAttributeValue(attribute, pbEcParams, cbEcParams);
    } else {
      // Not applicable for non-ECC keys
      rv = CKR_ATTRIBUTE_TYPE_INVALID;
    }
    break;

  default:
    rv = CKR_ATTRIBUTE_TYPE_INVALID;
    break;
  }

  return rv;
}

static CK_RV handleSecretKeyAttribute(CK_ATTRIBUTE_PTR attribute, const CNK_PKCS11_SECRET_KEY_OBJECT *secret) {
  CNK_LOG_FUNC(" attribute = %d", attribute->type);

  switch (attribute->type) {
  case CKA_KEY_TYPE:
    return setSingleAttributeValue(attribute, &secret->keyType, sizeof(secret->keyType));

  case CKA_VALUE:
    if (secret->sensitive)
      return CKR_ATTRIBUTE_SENSITIVE;
    return setSingleAttributeValue(attribute, secret->value, secret->valueLen);

  case CKA_VALUE_LEN:
    return setSingleAttributeValue(attribute, &secret->valueLen, sizeof(secret->valueLen));

  case CKA_SENSITIVE:
    return setSingleAttributeValue(attribute, &secret->sensitive, sizeof(secret->sensitive));

  case CKA_EXTRACTABLE:
    return setSingleAttributeValue(attribute, &secret->extractable, sizeof(secret->extractable));

  case CKA_ENCRYPT:
    return setSingleAttributeValue(attribute, &secret->encrypt, sizeof(secret->encrypt));

  case CKA_DECRYPT:
    return setSingleAttributeValue(attribute, &secret->decrypt, sizeof(secret->decrypt));

  case CKA_SIGN:
    return setSingleAttributeValue(attribute, &secret->sign, sizeof(secret->sign));

  case CKA_VERIFY:
    return setSingleAttributeValue(attribute, &secret->verify, sizeof(secret->verify));

  case CKA_WRAP:
    return setSingleAttributeValue(attribute, &secret->wrap, sizeof(secret->wrap));

  case CKA_UNWRAP:
    return setSingleAttributeValue(attribute, &secret->unwrap, sizeof(secret->unwrap));

  case CKA_DERIVE:
    return setSingleAttributeValue(attribute, &secret->derive, sizeof(secret->derive));

  default:
    return CKR_ATTRIBUTE_TYPE_INVALID;
  }
}

// Handle private key specific attributes
static CK_RV handlePrivateKeyAttribute(CK_ATTRIBUTE_PTR attribute, CK_BYTE algorithm_type, CK_BYTE pinPolicy) {
  CNK_LOG_FUNC(" attribute = %d, algorithm_type = %d", attribute->type, algorithm_type);

  CK_RV rv = CKR_ATTRIBUTE_TYPE_INVALID;
  CK_KEY_TYPE key_type = algoType2KeyType(algorithm_type);

  switch (attribute->type) {
  case CKA_KEY_TYPE:
    rv = setSingleAttributeValue(attribute, &key_type, sizeof(key_type));
    break;

  case CKA_SIGN: {
    CK_BBOOL value = CNK_PivPrivateKeyCanSign(algorithm_type);
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_SIGN_RECOVER: {
    CK_BBOOL value = CK_FALSE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_DECRYPT: {
    CK_BBOOL value = CNK_PivPrivateKeyCanDecrypt(algorithm_type);
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_ENCRYPT: {
    // Private keys cannot encrypt
    CK_BBOOL value = CK_FALSE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_UNWRAP: {
    CK_BBOOL value = CK_FALSE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_ALWAYS_AUTHENTICATE: {
    CK_BBOOL value = pinPolicy == CNK_PIV_PIN_POLICY_ALWAYS ? CK_TRUE : CK_FALSE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_SENSITIVE:
  case CKA_ALWAYS_SENSITIVE: {
    // Private keys are always sensitive
    CK_BBOOL value = CK_TRUE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_EXTRACTABLE: {
    // Private keys on PIV are never extractable
    CK_BBOOL value = CK_FALSE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_NEVER_EXTRACTABLE: {
    CK_BBOOL value = CK_TRUE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_LOCAL: {
    CK_BBOOL value = CK_FALSE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_DERIVE: {
    CK_BBOOL value = CNK_PivPrivateKeyCanDerive(algorithm_type);
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  default:
    rv = CKR_ATTRIBUTE_TYPE_INVALID;
    break;
  }

  return rv;
}
