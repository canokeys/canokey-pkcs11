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
#include "internal/piv_object.h"
#include "internal/template.h"
#include "internal/util.h"
#include "pkcs11.h"
#include "pkcs11_canokey.h"

#include <mbedtls/asn1write.h>
#include <mbedtls/platform_util.h>
#include <stddef.h> // For size_t
#include <string.h>

// Maximum size for certificate data buffer
#define MAX_PIV_CERTIFICATE_OBJECT_SIZE 8192

// Maximum size for public key buffer
#define MAX_PUBLIC_KEY_SIZE 2048

// Maximum size for PIV asymmetric key import data.
#define MAX_PIV_IMPORT_KEY_SIZE 1400

// Maximum size for generic PIV data objects exposed as CKO_DATA.
#define MAX_PIV_DATA_OBJECT_SIZE 8192

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

typedef struct {
  CK_BYTE objId;
  const CK_BYTE *dataTag;
  CK_ULONG dataTagLen;
  const char *label;
  const char *application;
  const CK_BYTE *objectId;
  CK_ULONG objectIdLen;
  CK_BBOOL privateObject;
  CK_BBOOL writable;
} PivDataObjectMapping;

static const PivSlotMapping PIV_SLOT_MAPPING[] = {
    {PIV_SLOT_9A, 0x9A, PIV_OBJECT_TAG_CERT_9A},
    {PIV_SLOT_9C, 0x9C, PIV_OBJECT_TAG_CERT_9C},
    {PIV_SLOT_9D, 0x9D, PIV_OBJECT_TAG_CERT_9D},
    {PIV_SLOT_9E, 0x9E, PIV_OBJECT_TAG_CERT_9E},
    {PIV_SLOT_82, 0x82, PIV_OBJECT_TAG_CERT_82},
    {PIV_SLOT_83, 0x83, PIV_OBJECT_TAG_CERT_83},
    {7, 0x84, 0x0F},
    {8, 0x85, 0x10},
    {9, 0x86, 0x11},
    {10, 0x87, 0x12},
    {11, 0x88, 0x13},
    {12, 0x89, 0x14},
    {13, 0x8A, 0x15},
    {14, 0x8B, 0x16},
    {15, 0x8C, 0x17},
    {16, 0x8D, 0x18},
    {17, 0x8E, 0x19},
    {18, 0x8F, 0x1A},
    {19, 0x90, 0x1B},
    {20, 0x91, 0x1C},
    {21, 0x92, 0x1D},
    {22, 0x93, 0x1E},
    {23, 0x94, 0x1F},
    {24, 0x95, 0x20},
};

// Size of the PIV slot mapping array
#define PIV_SLOT_MAPPING_SIZE (sizeof(PIV_SLOT_MAPPING) / sizeof(PIV_SLOT_MAPPING[0]))

// CKA_OBJECT_ID is stored as ASN.1 object-identifier content octets, matching
// the encoding OpenSC's pkcs11-tool uses for --application-id.
static const CK_BYTE TAG_CHUID[] = {0x5F, 0xC1, 0x02};
static const CK_BYTE TAG_CARDHOLDER_FINGERPRINTS[] = {0x5F, 0xC1, 0x03};
static const CK_BYTE TAG_SECURITY_OBJECT[] = {0x5F, 0xC1, 0x06};
static const CK_BYTE TAG_CARD_CAPABILITY_CONTAINER[] = {0x5F, 0xC1, 0x07};
static const CK_BYTE TAG_CARDHOLDER_FACIAL_IMAGE[] = {0x5F, 0xC1, 0x08};
static const CK_BYTE TAG_PRINTED_INFORMATION[] = {0x5F, 0xC1, 0x09};
static const CK_BYTE TAG_KEY_HISTORY[] = {0x5F, 0xC1, 0x0C};
static const CK_BYTE TAG_DISCOVERY[] = {0x7E};

static const CK_BYTE OID_CHUID[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x30, 0x00};
static const CK_BYTE OID_CARDHOLDER_FINGERPRINTS[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x60, 0x10};
static const CK_BYTE OID_SECURITY_OBJECT[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x81, 0x10, 0x00};
static const CK_BYTE OID_CARD_CAPABILITY_CONTAINER[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                                                        0x07, 0x01, 0x81, 0x5B, 0x00};
static const CK_BYTE OID_CARDHOLDER_FACIAL_IMAGE[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x60, 0x30};
static const CK_BYTE OID_PRINTED_INFORMATION[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x30, 0x01};
static const CK_BYTE OID_KEY_HISTORY[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x60, 0x60};
static const CK_BYTE OID_DISCOVERY[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x60, 0x50};

static const PivDataObjectMapping PIV_DATA_OBJECT_MAPPING[] = {
    {0x21, TAG_CHUID, sizeof(TAG_CHUID), "PIV CHUID", "PIV", OID_CHUID, sizeof(OID_CHUID), CK_FALSE, CK_TRUE},
    {0x22, TAG_CARDHOLDER_FINGERPRINTS, sizeof(TAG_CARDHOLDER_FINGERPRINTS), "PIV Cardholder Fingerprints", "PIV",
     OID_CARDHOLDER_FINGERPRINTS, sizeof(OID_CARDHOLDER_FINGERPRINTS), CK_TRUE, CK_TRUE},
    {0x23, TAG_SECURITY_OBJECT, sizeof(TAG_SECURITY_OBJECT), "PIV Security Object", "PIV", OID_SECURITY_OBJECT,
     sizeof(OID_SECURITY_OBJECT), CK_FALSE, CK_TRUE},
    {0x24, TAG_CARD_CAPABILITY_CONTAINER, sizeof(TAG_CARD_CAPABILITY_CONTAINER), "PIV Card Capability Container", "PIV",
     OID_CARD_CAPABILITY_CONTAINER, sizeof(OID_CARD_CAPABILITY_CONTAINER), CK_FALSE, CK_TRUE},
    {0x25, TAG_CARDHOLDER_FACIAL_IMAGE, sizeof(TAG_CARDHOLDER_FACIAL_IMAGE), "PIV Cardholder Facial Image", "PIV",
     OID_CARDHOLDER_FACIAL_IMAGE, sizeof(OID_CARDHOLDER_FACIAL_IMAGE), CK_TRUE, CK_TRUE},
    {0x26, TAG_PRINTED_INFORMATION, sizeof(TAG_PRINTED_INFORMATION), "PIV Printed Information", "PIV",
     OID_PRINTED_INFORMATION, sizeof(OID_PRINTED_INFORMATION), CK_TRUE, CK_TRUE},
    {0x27, TAG_KEY_HISTORY, sizeof(TAG_KEY_HISTORY), "PIV Key History Object", "PIV", OID_KEY_HISTORY,
     sizeof(OID_KEY_HISTORY), CK_FALSE, CK_TRUE},
    {0x28, TAG_DISCOVERY, sizeof(TAG_DISCOVERY), "PIV Discovery Object", "PIV", OID_DISCOVERY, sizeof(OID_DISCOVERY),
     CK_FALSE, CK_TRUE},
};

#define PIV_DATA_OBJECT_MAPPING_SIZE (sizeof(PIV_DATA_OBJECT_MAPPING) / sizeof(PIV_DATA_OBJECT_MAPPING[0]))

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

  CK_ULONG capacity = attribute->ulValueLen;
  attribute->ulValueLen = cbValue;

  // If pValue is NULL, we're just querying the required size
  if (!attribute->pValue) {
    return CKR_OK;
  }

  // Check if the provided buffer is large enough
  if (capacity < cbValue) {
    return CKR_BUFFER_TOO_SMALL;
  }

  // Copy the value if provided
  if (value && cbValue > 0) {
    memcpy(attribute->pValue, value, cbValue);
  }

  return CKR_OK;
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
static CK_KEY_TYPE algoType2KeyType(const CNK_PKCS11_SESSION *session, CK_BYTE algorithmType) {
  if (session->mldsa65Algorithm != 0 && algorithmType == session->mldsa65Algorithm)
    return CKK_ML_DSA;
  if (session->mlkem768Algorithm != 0 && algorithmType == session->mlkem768Algorithm)
    return CKK_ML_KEM;
  if (session->ed25519Algorithm != 0 && algorithmType == session->ed25519Algorithm)
    return CKK_EC_EDWARDS;
  if (session->x25519Algorithm != 0 && algorithmType == session->x25519Algorithm)
    return CKK_EC_MONTGOMERY;
  switch (algorithmType) {
  case PIV_ALG_RSA_2048:
  case PIV_ALG_RSA_3072:
  case PIV_ALG_RSA_4096:
    return CKK_RSA;

  case PIV_ALG_ECC_256:
  case PIV_ALG_ECC_384:
  case PIV_ALG_ECC_521:
  case PIV_ALG_SECP256K1:
  case PIV_ALG_SM2:
    return CKK_EC;

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

static CK_RV handleDataAttribute(CK_ATTRIBUTE_PTR attribute, const PivDataObjectMapping *mapping, CK_BYTE_PTR data,
                                 CK_ULONG data_len);

/**
 * @brief Handle public key attributes
 *
 * @param attribute The attribute to handle
 * @param algorithmType The key algorithm type
 * @param pbPublicKey Public key data
 * @param cbPublicKey Length of public key data
 * @return CK_RV CKR_OK on success, error code otherwise
 */
static CK_RV handlePublicKeyAttribute(CNK_PKCS11_SESSION *session, CK_ATTRIBUTE_PTR attribute, CK_BYTE algorithmType,
                                      CK_BYTE_PTR pbPublicKey, CK_ULONG cbPublicKey);

/**
 * @brief Handle private key attributes
 *
 * @param attribute The attribute to handle
 * @param algorithmType The key algorithm type
 * @param pinPolicy The stored PIV PIN policy
 * @return CK_RV CKR_OK on success, error code otherwise
 */
static CK_RV handlePrivateKeyAttribute(CNK_PKCS11_SESSION *session, CK_ATTRIBUTE_PTR attribute, CK_BYTE algorithmType,
                                       CK_BYTE pinPolicy);

/**
 * @brief Handle session secret-key attributes
 *
 * @param attribute The attribute to handle
 * @param secret The session secret-key object
 * @return CK_RV CKR_OK on success, error code otherwise
 */
static CK_RV handleSecretKeyAttribute(CK_ATTRIBUTE_PTR attribute, const CNK_PKCS11_SECRET_KEY_OBJECT *secret);
static CK_RV handleSessionSecretAttribute(CK_ATTRIBUTE_PTR attribute, const CNK_PKCS11_SECRET_KEY_OBJECT *secret);
static CK_BBOOL matchSessionSecretTemplate(const CNK_PKCS11_SECRET_KEY_OBJECT *secret, CK_ATTRIBUTE_PTR pTemplate,
                                           CK_ULONG ulCount);

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
  // Session secrets share the normal handle encoding but use IDs >= 0x80,
  // outside the fixed PIV object-ID range.
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

CK_RV CNK_GetSessionSecretKey(CNK_PKCS11_SESSION *session, CK_OBJECT_HANDLE object,
                              CNK_PKCS11_SECRET_KEY_OBJECT **secret) {
  CNK_ENSURE_NONNULL(session, secret);
  if (!isSessionSecretHandle(session, object, secret))
    CNK_RETURN(CKR_OBJECT_HANDLE_INVALID, "Invalid session secret-key handle");
  CNK_RET_OK;
}

CK_RV CNK_CreateSessionSecretKey(CNK_PKCS11_SESSION *session, const CNK_PKCS11_SECRET_KEY_OBJECT *prototype,
                                 CK_OBJECT_HANDLE_PTR object) {
  CNK_ENSURE_NONNULL(session, prototype, object);
  CNK_PKCS11_MUTEX *sessionLock CNK_MUTEX_GUARD = &session->lock;
  CNK_ENSURE_OK(cnk_mutex_lock(sessionLock));
  if (prototype->token || prototype->valueLen == 0 || prototype->valueLen > sizeof(prototype->value) ||
      prototype->labelLen > sizeof(prototype->label))
    CNK_RETURN(CKR_TEMPLATE_INCONSISTENT, "Invalid session secret-key prototype");
  if (prototype->keyType != CKK_GENERIC_SECRET && prototype->keyType != CKK_AES)
    CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "Unsupported session secret-key type");

  // Allocate storage and a handle ID independently: destroyed array entries
  // are reusable, while a live handle ID must never alias another live key.
  CK_ULONG index = MAX_SESSION_SECRET_KEYS;
  for (CK_ULONG i = 0; i < MAX_SESSION_SECRET_KEYS; i++) {
    if (!session->secretKeys[i].active) {
      index = i;
      break;
    }
  }
  if (index == MAX_SESSION_SECRET_KEYS)
    CNK_RETURN(CKR_HOST_MEMORY, "Too many session secret keys");

  CK_BYTE newId = session->nextSecretKeyId;
  for (CK_ULONG attempts = 0; attempts <= MAX_SESSION_SECRET_KEYS; attempts++) {
    CK_BBOOL used = CK_FALSE;
    for (CK_ULONG i = 0; i < MAX_SESSION_SECRET_KEYS; i++) {
      if (session->secretKeys[i].active && session->secretKeys[i].id == newId) {
        used = CK_TRUE;
        break;
      }
    }
    if (!used)
      break;
    newId++;
    if (newId < CNK_SESSION_SECRET_KEY_FIRST_ID)
      newId = CNK_SESSION_SECRET_KEY_FIRST_ID;
  }

  // Clear reused storage before copying the caller's fully validated prototype.
  CNK_PKCS11_SECRET_KEY_OBJECT *secret = &session->secretKeys[index];
  mbedtls_platform_zeroize(secret, sizeof(*secret));
  memcpy(secret, prototype, sizeof(*secret));
  secret->active = CK_TRUE;
  secret->id = newId;
  secret->token = CK_FALSE;

  session->nextSecretKeyId = newId + 1;
  if (session->nextSecretKeyId < CNK_SESSION_SECRET_KEY_FIRST_ID)
    session->nextSecretKeyId = CNK_SESSION_SECRET_KEY_FIRST_ID;

  *object = makeObjectHandle(session->slotId, CKO_SECRET_KEY, newId);
  CNK_RET_OK;
}

static CK_RV applyMutableSecretAttributes(CNK_PKCS11_SECRET_KEY_OBJECT *secret, CK_ATTRIBUTE_PTR attributes,
                                          CK_ULONG attributeCount) {
  // Callers apply this to a temporary object and commit only after the complete
  // template succeeds, so a late read-only/invalid attribute cannot half-update
  // a live key.
  CNK_ENSURE_NONNULL(secret);
  if (attributeCount > 0)
    CNK_ENSURE_NONNULL(attributes);

  for (CK_ULONG i = 0; i < attributeCount; i++) {
    CK_ATTRIBUTE_PTR attribute = &attributes[i];
    CK_BBOOL *target = NULL;
    switch (attribute->type) {
    case CKA_LABEL:
      if ((attribute->pValue == NULL && attribute->ulValueLen != 0) || attribute->ulValueLen > sizeof(secret->label))
        CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "Invalid session secret-key label");
      mbedtls_platform_zeroize(secret->label, sizeof(secret->label));
      if (attribute->ulValueLen > 0)
        memcpy(secret->label, attribute->pValue, attribute->ulValueLen);
      secret->labelLen = attribute->ulValueLen;
      continue;
    case CKA_ENCRYPT:
      target = &secret->encrypt;
      break;
    case CKA_DECRYPT:
      target = &secret->decrypt;
      break;
    case CKA_SIGN:
      target = &secret->sign;
      break;
    case CKA_VERIFY:
      target = &secret->verify;
      break;
    case CKA_WRAP:
      target = &secret->wrap;
      break;
    case CKA_UNWRAP:
      target = &secret->unwrap;
      break;
    case CKA_DERIVE:
      target = &secret->derive;
      break;
    case CKA_CLASS:
    case CKA_TOKEN:
    case CKA_PRIVATE:
    case CKA_ID:
    case CKA_KEY_TYPE:
    case CKA_VALUE:
    case CKA_VALUE_LEN:
    case CKA_SENSITIVE:
    case CKA_EXTRACTABLE:
    case CKA_LOCAL:
    case CKA_KEY_GEN_MECHANISM:
    case CKA_MODIFIABLE:
    case CKA_COPYABLE:
    case CKA_DESTROYABLE:
      CNK_RETURN(CKR_ATTRIBUTE_READ_ONLY, "Session secret-key attribute is read-only");
    default:
      CNK_RETURN(CKR_ATTRIBUTE_TYPE_INVALID, "Unsupported session secret-key attribute");
    }

    if (attribute->pValue == NULL || attribute->ulValueLen != sizeof(CK_BBOOL))
      CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "Invalid boolean session secret-key attribute");
    *target = *(CK_BBOOL *)attribute->pValue;
  }

  CNK_RET_OK;
}

static const PivDataObjectMapping *findPivDataObjectById(CK_BYTE objId) {
  for (CK_ULONG i = 0; i < PIV_DATA_OBJECT_MAPPING_SIZE; i++) {
    if (PIV_DATA_OBJECT_MAPPING[i].objId == objId)
      return &PIV_DATA_OBJECT_MAPPING[i];
  }

  return NULL;
}

static CK_RV getTemplateDataObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, const PivDataObjectMapping **mapping) {
  CK_ATTRIBUTE_PTR attr;
  CK_BYTE dataTag;
  CNK_ENSURE_NONNULL(mapping);

  CNK_ENSURE_OK(cnk_template_find_attribute(pTemplate, ulCount, CKA_ID, &attr));
  if (attr != NULL) {
    CNK_ENSURE_OK(cnk_attribute_get_byte(attr, &dataTag));
    *mapping = findPivDataObjectById(dataTag);
    if (*mapping == NULL)
      CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "unsupported PIV data object ID");
  }

  CNK_ENSURE_OK(cnk_template_find_attribute(pTemplate, ulCount, CKA_OBJECT_ID, &attr));
  if (attr != NULL) {
    for (CK_ULONG i = 0; i < PIV_DATA_OBJECT_MAPPING_SIZE; i++) {
      if (PIV_DATA_OBJECT_MAPPING[i].objectIdLen == attr->ulValueLen &&
          memcmp(PIV_DATA_OBJECT_MAPPING[i].objectId, attr->pValue, attr->ulValueLen) == 0) {
        if (*mapping != NULL && *mapping != &PIV_DATA_OBJECT_MAPPING[i])
          CNK_RETURN(CKR_TEMPLATE_INCONSISTENT, "PIV data object ID and OID do not match");
        *mapping = &PIV_DATA_OBJECT_MAPPING[i];
        CNK_RET_OK;
      }
    }
    CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "unsupported PIV data object OID");
  }

  if (*mapping != NULL)
    CNK_RET_OK;

  CNK_RETURN(CKR_TEMPLATE_INCOMPLETE, "missing PIV data object identifier");
}

static CK_RV checkPivObjectExists(CNK_PKCS11_SESSION *session, CK_OBJECT_CLASS objectClass, CK_BYTE objectId,
                                  CK_BBOOL *exists) {
  CK_SLOT_ID slotId = session->slotId;
  CK_BYTE pivTag;
  CK_BYTE certTag;
  CK_RV rv;

  CNK_ENSURE_NONNULL(exists);
  *exists = CK_FALSE;

  switch (objectClass) {
  case CKO_CERTIFICATE:
    if (objectId < 1 || objectId > PIV_SLOT_COUNT) {
      return CKR_OK;
    }

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
    if (objectId < 1 || objectId > PIV_SLOT_COUNT) {
      return CKR_OK;
    }

    rv = C_CNK_ObjIdToPivTag(objectId, &pivTag);
    if (rv == CKR_OBJECT_HANDLE_INVALID) {
      return CKR_OK;
    }
    if (rv != CKR_OK) {
      return rv;
    }

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

  case CKO_DATA: {
    const PivDataObjectMapping *mapping = findPivDataObjectById(objectId);
    if (mapping == NULL) {
      return CKR_OK;
    }

    rv = cnk_get_piv_data_by_tag_with_session(slotId, session, mapping->dataTag, mapping->dataTagLen, NULL, NULL,
                                              CK_FALSE);
    if (rv == CKR_OK) {
      *exists = CK_TRUE;
      return CKR_OK;
    }
    if (rv == CKR_DATA_INVALID) {
      return CKR_OK;
    }
    if (rv == CKR_USER_NOT_LOGGED_IN) {
      return CKR_OK;
    }
    return rv;
  }

  default:
    return CKR_OK;
  }
}

static CK_RV getTemplateObjectId(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_CLASS objectClass,
                                 CK_BYTE *objId) {
  CNK_ENSURE_OK(cnk_template_get_byte(pTemplate, ulCount, CKA_ID, objId));

  if (objectClass == CKO_DATA) {
    if (findPivDataObjectById(*objId) == NULL)
      CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "unsupported PIV data object ID");
    CNK_RET_OK;
  }

  if (*objId < 1 || *objId > PIV_SLOT_COUNT)
    CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "unsupported PIV object ID");

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
  CNK_ENSURE_OK(
      cnk_template_get_optional_bool(pTemplate, ulCount, CKA_ALWAYS_AUTHENTICATE, CK_FALSE, &alwaysAuthenticate));

  *pinPolicy = alwaysAuthenticate ? CNK_PIV_PIN_POLICY_ALWAYS : defaultPinPolicy;
  CNK_ENSURE_OK(cnk_template_get_optional_byte(pTemplate, ulCount, CKA_CNK_PIV_PIN_POLICY, *pinPolicy, pinPolicy));
  CNK_ENSURE_OK(cnk_template_get_optional_byte(pTemplate, ulCount, CKA_CNK_PIV_TOUCH_POLICY, CNK_PIV_TOUCH_POLICY_NEVER,
                                               touchPolicy));
  CNK_ENSURE_OK(validatePivPinPolicy(*pinPolicy));
  CNK_ENSURE_OK(validatePivTouchPolicy(*touchPolicy));
  CNK_RET_OK;
}

static CK_RV appendMatchingPivObjects(CNK_PKCS11_SESSION *session, CK_SESSION_HANDLE hSession,
                                      CK_OBJECT_CLASS objectClass, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                                      const CNK_PIV_METADATA_DIRECTORY_ENTRY *directory, CK_ULONG directoryCount) {
  CK_BYTE firstId = session->findIdSpecified ? session->findObjectId : 1;
  CK_BYTE lastId = session->findIdSpecified ? session->findObjectId : PIV_SLOT_COUNT;

  for (CK_BYTE id = firstId; id <= lastId; id++) {
    CK_BBOOL exists = CK_FALSE;
    if (directory != NULL) {
      CK_BYTE pivTag;
      CK_RV rv = C_CNK_ObjIdToPivTag(id, &pivTag);
      if (rv != CKR_OK)
        return rv;
      for (CK_ULONG i = 0; i < directoryCount; i++) {
        if (directory[i].pivSlot == pivTag) {
          CK_BYTE requiredFlag = objectClass == CKO_CERTIFICATE ? CNK_PIV_METADATA_DIRECTORY_FLAG_CERT
                                                                : CNK_PIV_METADATA_DIRECTORY_FLAG_KEY;
          exists = (directory[i].flags & requiredFlag) != 0;
          break;
        }
      }
    } else {
      CK_RV rv = checkPivObjectExists(session, objectClass, id, &exists);
      if (rv != CKR_OK)
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

static CK_RV appendMatchingPivDataObjects(CNK_PKCS11_SESSION *session, CK_SESSION_HANDLE hSession,
                                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  for (CK_ULONG i = 0; i < PIV_DATA_OBJECT_MAPPING_SIZE; i++) {
    const PivDataObjectMapping *mapping = &PIV_DATA_OBJECT_MAPPING[i];
    CK_BBOOL exists;
    CK_RV rv;

    if (session->findIdSpecified && session->findObjectId != mapping->objId)
      continue;

    rv = checkPivObjectExists(session, CKO_DATA, mapping->objId, &exists);
    if (rv != CKR_OK)
      return rv;
    if (!exists)
      continue;

    CK_OBJECT_HANDLE hObject = makeObjectHandle(session->slotId, CKO_DATA, mapping->objId);
    if (ulCount == 0 || matchTemplate(hSession, hObject, pTemplate, ulCount)) {
      if (session->findObjectsCount >= MAX_FIND_OBJECTS)
        return CKR_HOST_MEMORY;

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
    if (ulCount == 0 || matchSessionSecretTemplate(&session->secretKeys[i], pTemplate, ulCount)) {
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
  case PIV_ALG_ECC_521:
  case PIV_ALG_SECP256K1:
  case PIV_ALG_MLDSA65:
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
  case PIV_ALG_ECC_521:
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

  switch (obj_class) {
  case CKO_CERTIFICATE:
  case CKO_PUBLIC_KEY:
  case CKO_PRIVATE_KEY:
    if (localObjId < 1 || localObjId > PIV_SLOT_COUNT)
      return CKR_OBJECT_HANDLE_INVALID;
    break;
  case CKO_DATA:
    if (findPivDataObjectById(localObjId) == NULL)
      return CKR_OBJECT_HANDLE_INVALID;
    break;
  default:
    return CKR_OBJECT_HANDLE_INVALID;
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

  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  if (!(session->flags & CKF_RW_SESSION))
    CNK_RETURN(CKR_SESSION_READ_ONLY, "write session is required");
  if (!cnk_token_management_key_is_cached(session))
    CNK_RETURN(CKR_USER_NOT_LOGGED_IN, "CKU_SO login is required");

  CK_OBJECT_CLASS objectClass;
  CK_BYTE objId;
  CNK_ENSURE_OK(cnk_template_get_object_class(pTemplate, ulCount, CKA_CLASS, &objectClass));
  if (objectClass == CKO_DATA) {
    const PivDataObjectMapping *mapping;
    CNK_ENSURE_OK(getTemplateDataObject(pTemplate, ulCount, &mapping));
    objId = mapping->objId;
  } else {
    CNK_ENSURE_OK(getTemplateObjectId(pTemplate, ulCount, objectClass, &objId));
  }

  switch (objectClass) {
  case CKO_DATA: {
    const PivDataObjectMapping *mapping = findPivDataObjectById(objId);
    CK_ATTRIBUTE_PTR valueAttr;

    CNK_ENSURE_NONNULL(mapping);
    if (!mapping->writable)
      CNK_RETURN(CKR_ACTION_PROHIBITED, "PIV data object is not writable");
    CNK_ENSURE_OK(cnk_template_get_attribute(pTemplate, ulCount, CKA_VALUE, &valueAttr));
    if (valueAttr->pValue == NULL || valueAttr->ulValueLen == 0 || valueAttr->ulValueLen > MAX_PIV_DATA_OBJECT_SIZE)
      CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad PIV data object value");

    CNK_ENSURE_OK(cnk_put_piv_data_by_tag(session->slotId, session, mapping->dataTag, mapping->dataTagLen,
                                          valueAttr->pValue, valueAttr->ulValueLen));

    *phObject = makeObjectHandle(session->slotId, CKO_DATA, objId);
    CNK_RET_OK;
  }

  case CKO_CERTIFICATE: {
    CK_ATTRIBUTE_PTR valueAttr;
    CNK_ENSURE_OK(cnk_template_get_attribute(pTemplate, ulCount, CKA_VALUE, &valueAttr));
    if (valueAttr->pValue == NULL || valueAttr->ulValueLen == 0)
      CNK_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "bad certificate value");

    CK_BYTE certTag;
    CK_BYTE certObject[MAX_PIV_CERTIFICATE_OBJECT_SIZE];
    CK_ULONG certObjectLen = 0;
    CNK_ENSURE_OK(CNK_ObjectIdToCertificateTag(objId, &certTag));
    CNK_ENSURE_OK(cnk_build_piv_certificate_object((CK_BYTE_PTR)valueAttr->pValue, valueAttr->ulValueLen, certObject,
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

    CNK_ENSURE_OK(cnk_template_get_key_type(pTemplate, ulCount, CKA_KEY_TYPE, &keyType));
    CNK_ENSURE_OK(C_CNK_ObjIdToPivTag(objId, &pivTag));

    switch (keyType) {
    case CKK_RSA:
      CNK_ENSURE_OK(cnk_build_piv_rsa_import(pTemplate, ulCount, objId, importData, sizeof(importData), &importDataLen,
                                             &algorithmType));
      break;
    case CKK_EC:
      CNK_ENSURE_OK(cnk_build_piv_ec_import(pTemplate, ulCount, objId, importData, sizeof(importData), &importDataLen,
                                            &algorithmType));
      break;
    case CKK_EC_EDWARDS:
    case CKK_EC_MONTGOMERY:
      CNK_ENSURE_OK(cnk_build_piv_25519_import(session, pTemplate, ulCount, objId, keyType, importData,
                                               sizeof(importData), &importDataLen, &algorithmType));
      break;
    case CKK_ML_DSA:
    case CKK_ML_KEM:
      CNK_ENSURE_OK(cnk_build_piv_pqc_import(session, pTemplate, ulCount, objId, keyType, importData,
                                             sizeof(importData), &importDataLen, &algorithmType));
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
  CNK_ENSURE_NONNULL(phNewObject);
  if (ulCount > 0)
    CNK_ENSURE_NONNULL(pTemplate);

  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  CNK_PKCS11_SECRET_KEY_OBJECT copy = {0};
  CK_RV rv;
  cnk_mutex_lock(&session->lock);
  CNK_PKCS11_SECRET_KEY_OBJECT *source = NULL;
  rv = CNK_GetSessionSecretKey(session, hObject, &source);
  if (rv == CKR_OK) {
    if (!source->copyable) {
      cnk_mutex_unlock(&session->lock);
      CNK_RETURN(CKR_ACTION_PROHIBITED, "Session secret key is not copyable");
    }
    copy = *source;
  }
  cnk_mutex_unlock(&session->lock);
  if (rv != CKR_OK) {
    CK_OBJECT_CLASS objectClass;
    extractObjectInfo(hObject, NULL, &objectClass, NULL);
    if (objectClass == OBJECT_CLASS_SECRET_KEY_HANDLE)
      CNK_RETURN(CKR_OBJECT_HANDLE_INVALID, "Invalid session secret-key handle");
    CNK_ENSURE_OK(CNK_ValidateObject(hObject, session, 0, NULL));
    CNK_RETURN(CKR_ACTION_PROHIBITED, "PIV token objects are not copyable");
  }

  // The snapshot linearizes the copy before a concurrent destroy. The new
  // object is allocated separately after releasing the non-recursive lock.
  rv = applyMutableSecretAttributes(&copy, pTemplate, ulCount);
  if (rv == CKR_OK)
    rv = CNK_CreateSessionSecretKey(session, &copy, phNewObject);
  mbedtls_platform_zeroize(&copy, sizeof(copy));
  return rv;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
  CNK_LOG_FUNC(": hSession: %lu, hObject: %lu", hSession, hObject);
  CNK_ENSURE_INITIALIZED();

  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  CNK_PKCS11_MUTEX *sessionLock CNK_MUTEX_GUARD = &session->lock;
  CNK_ENSURE_OK(cnk_mutex_lock(sessionLock));
  CNK_PKCS11_SECRET_KEY_OBJECT *secret = NULL;
  if (isSessionSecretHandle(session, hObject, &secret)) {
    if (!secret->destroyable)
      CNK_RETURN(CKR_ACTION_PROHIBITED, "Session secret key is not destroyable");
    mbedtls_platform_zeroize(secret, sizeof(*secret));
    CNK_RET_OK;
  }

  CNK_ENSURE_OK(CNK_ValidateObject(hObject, session, 0, NULL));
  // PIV token objects have no general PKCS#11 deletion semantics.
  CNK_RETURN(CKR_ACTION_PROHIBITED, "PIV token objects are not destroyable");
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
  case CKO_DATA:
    sizeAttrs[5].type = CKA_APPLICATION;
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
  } else if (objClass == CKO_DATA) {
    CK_ATTRIBUTE dataAttrs[] = {
        {CKA_OBJECT_ID, NULL_PTR, 0},
        {CKA_VALUE, NULL_PTR, 0},
    };
    rv = C_GetAttributeValue(hSession, hObject, dataAttrs, sizeof(dataAttrs) / sizeof(dataAttrs[0]));
    if (rv != CKR_OK)
      CNK_RETURN(rv, "failed to query data object size");
    for (CK_ULONG i = 0; i < sizeof(dataAttrs) / sizeof(dataAttrs[0]); i++) {
      if (dataAttrs[i].ulValueLen != CK_UNAVAILABLE_INFORMATION)
        size += sizeof(CK_ATTRIBUTE) + dataAttrs[i].ulValueLen;
    }
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
  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  CK_OBJECT_CLASS requestedClass;
  extractObjectInfo(hObject, NULL, &requestedClass, NULL);
  if (requestedClass == OBJECT_CLASS_SECRET_KEY_HANDLE) {
    CNK_PKCS11_MUTEX *sessionLock CNK_MUTEX_GUARD = &session->lock;
    CNK_ENSURE_OK(cnk_mutex_lock(sessionLock));
    CNK_PKCS11_SECRET_KEY_OBJECT *secret = NULL;
    if (!isSessionSecretHandle(session, hObject, &secret))
      CNK_RETURN(CKR_OBJECT_HANDLE_INVALID, "Invalid session secret-key handle");
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_RV rvReturn = CKR_OK;

    for (CK_ULONG i = 0; i < ulCount; i++) {
      CK_RV rv = pTemplate[i].type == CKA_CLASS
                     ? setSingleAttributeValue(&pTemplate[i], &secretClass, sizeof(secretClass))
                     : handleSessionSecretAttribute(&pTemplate[i], secret);

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
  const PivDataObjectMapping *dataMapping = NULL;
  if (objClass == CKO_DATA) {
    dataMapping = findPivDataObjectById(objId);
    CNK_ENSURE_NONNULL(dataMapping);
    bPivSlot = dataMapping->dataTag[dataMapping->dataTagLen - 1];
  } else {
    CNK_ENSURE_OK(C_CNK_ObjIdToPivTag(objId, &bPivSlot));
  }

  // Fetch the PIV data for this object
  CK_BYTE data[MAX_PIV_CERTIFICATE_OBJECT_SIZE];
  CK_ULONG cbData = sizeof(data);
  CK_BYTE bAlgorithmType = 0;
  CK_BYTE bPinPolicy = 0;
  CK_BYTE bTouchPolicy = 0;
  CK_BYTE abPublicKey[MAX_PUBLIC_KEY_SIZE];
  CK_ULONG cbPublicKey = sizeof(abPublicKey);

  switch (objClass) {
  case CKO_DATA:
    CNK_ENSURE_OK(cnk_get_piv_data_by_tag_with_session(session->slotId, session, dataMapping->dataTag,
                                                       dataMapping->dataTagLen, data, &cbData, CK_TRUE));
    if (cbData == 0) {
      CNK_RETURN(CKR_OBJECT_HANDLE_INVALID, "No data found for PIV data object");
    }
    break;

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
      bbool =
          (objClass == CKO_PRIVATE_KEY || (objClass == CKO_DATA && dataMapping->privateObject)) ? CK_TRUE : CK_FALSE;
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

      if (objClass == CKO_DATA) {
        rv = setSingleAttributeValue(&pTemplate[i], dataMapping->label, (CK_ULONG)strlen(dataMapping->label));
      } else {
        snprintf(label, sizeof(label), "PIV %s %02X", type_str, bPivSlot);
        CK_ULONG label_len = (CK_ULONG)strlen(label);
        rv = setSingleAttributeValue(&pTemplate[i], label, label_len);
      }
      break;
    }

    case CKA_MODIFIABLE: {
      bbool = CK_FALSE;
      rv = setSingleAttributeValue(&pTemplate[i], &bbool, sizeof(bbool));
      break;
    }

    case CKA_COPYABLE:
    case CKA_DESTROYABLE: {
      bbool = CK_FALSE;
      rv = setSingleAttributeValue(&pTemplate[i], &bbool, sizeof(bbool));
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
    case CKO_DATA:
      rv = handleDataAttribute(&pTemplate[i], dataMapping, data, cbData);
      break;

    case CKO_CERTIFICATE:
      rv = handleCertificateAttribute(&pTemplate[i], data, cbData);
      break;

    case CKO_PUBLIC_KEY:
      if (pTemplate[i].type == CKA_CNK_PIV_PIN_POLICY) {
        rv = setSingleAttributeValue(&pTemplate[i], &bPinPolicy, sizeof(bPinPolicy));
      } else if (pTemplate[i].type == CKA_CNK_PIV_TOUCH_POLICY) {
        rv = setSingleAttributeValue(&pTemplate[i], &bTouchPolicy, sizeof(bTouchPolicy));
      } else {
        rv = handlePublicKeyAttribute(session, &pTemplate[i], bAlgorithmType, abPublicKey, cbPublicKey);
      }
      break;

    case CKO_PRIVATE_KEY:
      if (pTemplate[i].type == CKA_CNK_PIV_PIN_POLICY) {
        rv = setSingleAttributeValue(&pTemplate[i], &bPinPolicy, sizeof(bPinPolicy));
      } else if (pTemplate[i].type == CKA_CNK_PIV_TOUCH_POLICY) {
        rv = setSingleAttributeValue(&pTemplate[i], &bTouchPolicy, sizeof(bTouchPolicy));
      } else {
        rv = handlePrivateKeyAttribute(session, &pTemplate[i], bAlgorithmType, bPinPolicy);
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

  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  CK_OBJECT_CLASS requestedClass;
  extractObjectInfo(hObject, NULL, &requestedClass, NULL);
  if (requestedClass == OBJECT_CLASS_SECRET_KEY_HANDLE) {
    CNK_PKCS11_MUTEX *sessionLock CNK_MUTEX_GUARD = &session->lock;
    CNK_ENSURE_OK(cnk_mutex_lock(sessionLock));
    CNK_PKCS11_SECRET_KEY_OBJECT *secret = NULL;
    if (!isSessionSecretHandle(session, hObject, &secret))
      CNK_RETURN(CKR_OBJECT_HANDLE_INVALID, "Invalid session secret-key handle");
    if (ulCount == 0)
      CNK_RET_OK;
    if (!secret->modifiable)
      CNK_RETURN(CKR_ACTION_PROHIBITED, "Session secret key is not modifiable");
    // Validate transactionally because PKCS#11 templates have no defined
    // partial-update semantics.
    CNK_PKCS11_SECRET_KEY_OBJECT updated = *secret;
    CK_RV rv = applyMutableSecretAttributes(&updated, pTemplate, ulCount);
    if (rv == CKR_OK)
      memcpy(secret, &updated, sizeof(*secret));
    mbedtls_platform_zeroize(&updated, sizeof(updated));
    return rv;
  }

  CNK_ENSURE_OK(CNK_ValidateObject(hObject, session, 0, NULL));
  if (ulCount == 0)
    CNK_RET_OK;

  CNK_RETURN(CKR_ATTRIBUTE_READ_ONLY, "PIV object attributes are read-only");
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  CNK_LOG_FUNC(": hSession: %lu, ulCount: %lu", hSession, ulCount);
  CNK_ENSURE_INITIALIZED();
  if (pTemplate == NULL && ulCount > 0)
    return CKR_ARGUMENTS_BAD;

  // Validate the session
  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
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
  if (session->findClassSpecified && session->findObjectClass != CKO_DATA &&
      session->findObjectClass != CKO_CERTIFICATE && session->findObjectClass != CKO_PUBLIC_KEY &&
      session->findObjectClass != CKO_PRIVATE_KEY && session->findObjectClass != CKO_SECRET_KEY) {
    cnk_mutex_unlock(&session->lock);
    CNK_RET_OK; // Return OK but with no results
  }

  CNK_PIV_METADATA_DIRECTORY_ENTRY directory[CNK_PIV_METADATA_DIRECTORY_MAX_ENTRIES];
  CK_ULONG directoryCount = CNK_PIV_METADATA_DIRECTORY_MAX_ENTRIES;
  const CNK_PIV_METADATA_DIRECTORY_ENTRY *directoryPtr = directory;
  if (!session->findClassSpecified ||
      (session->findObjectClass != CKO_DATA && session->findObjectClass != CKO_SECRET_KEY)) {
    rv = cnk_get_piv_metadata_directory(session->slotId, directory, &directoryCount);
    if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
      directoryPtr = NULL;
      directoryCount = 0;
      rv = CKR_OK;
    } else if (rv != CKR_OK) {
      session->findActive = CK_FALSE;
      cnk_mutex_unlock(&session->lock);
      return rv;
    }
  } else {
    directoryPtr = NULL;
    directoryCount = 0;
  }

  if (session->findClassSpecified) {
    if (session->findObjectClass == CKO_SECRET_KEY) {
      rv = appendMatchingSecretObjects(session, hSession, pTemplate, ulCount);
    } else if (session->findObjectClass == CKO_DATA) {
      rv = appendMatchingPivDataObjects(session, hSession, pTemplate, ulCount);
    } else {
      if (session->findIdSpecified && (session->findObjectId < 1 || session->findObjectId > PIV_SLOT_COUNT)) {
        rv = CKR_OK;
      } else {
        rv = appendMatchingPivObjects(session, hSession, session->findObjectClass, pTemplate, ulCount, directoryPtr,
                                      directoryCount);
      }
    }
  } else {
    static const CK_OBJECT_CLASS searchableClasses[] = {CKO_DATA, CKO_CERTIFICATE, CKO_PUBLIC_KEY, CKO_PRIVATE_KEY};
    for (CK_ULONG i = 0; i < sizeof(searchableClasses) / sizeof(searchableClasses[0]); i++) {
      if (searchableClasses[i] == CKO_DATA) {
        rv = appendMatchingPivDataObjects(session, hSession, pTemplate, ulCount);
      } else if (session->findIdSpecified && (session->findObjectId < 1 || session->findObjectId > PIV_SLOT_COUNT)) {
        rv = CKR_OK;
      } else {
        rv = appendMatchingPivObjects(session, hSession, searchableClasses[i], pTemplate, ulCount, directoryPtr,
                                      directoryCount);
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
  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
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
  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
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
  if (ulCount == 0)
    CNK_RETURN(CK_TRUE, "Empty template matches");

  // Copy the template
  CK_ATTRIBUTE_PTR attrs = (CK_ATTRIBUTE_PTR)ck_malloc(sizeof(CK_ATTRIBUTE) * ulCount);
  if (attrs == NULL)
    CNK_RETURN(CK_FALSE, "Failed to allocate memory for attributes");

  for (CK_ULONG i = 0; i < ulCount; i++) {
    attrs[i].type = pTemplate[i].type;
    attrs[i].ulValueLen = pTemplate[i].ulValueLen;
    attrs[i].pValue = NULL;
    if (pTemplate[i].ulValueLen > 0)
      attrs[i].pValue = ck_malloc(pTemplate[i].ulValueLen);
    if (pTemplate[i].ulValueLen > 0 && attrs[i].pValue == NULL) {
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
    if (attrs[i].ulValueLen > 0 && memcmp(attrs[i].pValue, pTemplate[i].pValue, attrs[i].ulValueLen) != 0) {
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

static CK_RV handleDataAttribute(CK_ATTRIBUTE_PTR attribute, const PivDataObjectMapping *mapping, CK_BYTE_PTR data,
                                 CK_ULONG dataLen) {
  CNK_ENSURE_NONNULL(mapping);

  switch (attribute->type) {
  case CKA_APPLICATION:
    return setSingleAttributeValue(attribute, mapping->application, (CK_ULONG)strlen(mapping->application));
  case CKA_OBJECT_ID:
    return setSingleAttributeValue(attribute, mapping->objectId, mapping->objectIdLen);
  case CKA_VALUE:
    return setSingleAttributeValue(attribute, data, dataLen);
  default:
    return CKR_ATTRIBUTE_TYPE_INVALID;
  }
}

static CK_RV setEcParamsAttribute(const CNK_PKCS11_SESSION *session, CK_ATTRIBUTE_PTR attribute,
                                  CK_BYTE algorithmType) {
  const char *oid = NULL;
  size_t oidLen = 0;
  CK_BYTE encoded[16];

  if (algorithmType == session->ed25519Algorithm) {
    oid = "\x2B\x65\x70"; // id-Ed25519, 1.3.101.112
    oidLen = 3;
  } else if (algorithmType == session->x25519Algorithm) {
    oid = "\x2B\x65\x6E"; // id-X25519, 1.3.101.110
    oidLen = 3;
  } else {
    switch (algorithmType) {
    case PIV_ALG_ECC_256:
      oid = "\x2A\x86\x48\xCE\x3D\x03\x01\x07";
      oidLen = 8;
      break;
    case PIV_ALG_ECC_384:
      oid = "\x2B\x81\x04\x00\x22";
      oidLen = 5;
      break;
    case PIV_ALG_ECC_521:
      oid = "\x2B\x81\x04\x00\x23";
      oidLen = 5;
      break;
    case PIV_ALG_SECP256K1:
      oid = "\x2B\x81\x04\x00\x0A";
      oidLen = 5;
      break;
    case PIV_ALG_SM2:
      oid = "\x2A\x81\x1C\xCF\x55\x01\x82\x2D";
      oidLen = 8;
      break;
    default:
      return CKR_ATTRIBUTE_VALUE_INVALID;
    }
  }

  CK_BYTE_PTR output = encoded + sizeof(encoded);
  int encodedLen = mbedtls_asn1_write_oid(&output, encoded, oid, oidLen);
  if (encodedLen < 0)
    return CKR_FUNCTION_FAILED;
  return setSingleAttributeValue(attribute, output, (CK_ULONG)encodedLen);
}

// Handle public key specific attributes
static CK_RV handlePublicKeyAttribute(CNK_PKCS11_SESSION *session, CK_ATTRIBUTE_PTR attribute, CK_BYTE algorithm_type,
                                      CK_BYTE_PTR pbPublicKey, CK_ULONG cbPublicKey) {
  CNK_LOG_FUNC(" attribute = 0x%x, algorithm_type = 0x%x", attribute->type, algorithm_type);

  CK_RV rv = CKR_ATTRIBUTE_TYPE_INVALID;
  CK_KEY_TYPE keyType = algoType2KeyType(session, algorithm_type);

  CK_BYTE_PTR pbModulus = NULL;
  CK_ULONG cbModulus = 0;
  CK_BYTE_PTR pbPublicExponent = NULL;
  CK_ULONG cbPublicExponent = 0;
  CK_BYTE_PTR pbPublicPoint = NULL;
  CK_ULONG cbPublicPoint = 0;

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
    if (fail || lengthSize > cbPublicKey - vpos)
      CNK_RETURN(CKR_DEVICE_ERROR, "Bad length in public-key TLV");
    vpos += lengthSize;
    if (ilen > cbPublicKey - vpos)
      CNK_RETURN(CKR_DEVICE_ERROR, "Public-key TLV value exceeds response");
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
    CK_BBOOL value = CNK_PivPrivateKeyCanSign(algorithm_type) || algorithm_type == session->mldsa65Algorithm;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_ENCAPSULATE: {
    CK_BBOOL value = keyType == CKK_ML_KEM ? CK_TRUE : CK_FALSE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_VERIFY_RECOVER: {
    CK_BBOOL value = CK_FALSE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_ENCRYPT: {
    CK_BBOOL value = keyType == CKK_RSA ? CK_TRUE : CK_FALSE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_WRAP: {
    CK_BBOOL value = CK_FALSE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_DERIVE: {
    CK_BBOOL value = CNK_PivPrivateKeyCanDerive(algorithm_type) ||
                     (session->x25519Algorithm != 0 && algorithm_type == session->x25519Algorithm);
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_PARAMETER_SET: {
    CK_ULONG parameterSet;
    if (keyType == CKK_ML_DSA)
      parameterSet = CKP_ML_DSA_65;
    else if (keyType == CKK_ML_KEM)
      parameterSet = CKP_ML_KEM_768;
    else {
      rv = CKR_ATTRIBUTE_TYPE_INVALID;
      break;
    }
    rv = setSingleAttributeValue(attribute, &parameterSet, sizeof(parameterSet));
    break;
  }

  case CKA_VALUE:
    if ((keyType == CKK_ML_DSA || keyType == CKK_ML_KEM) && pbPublicPoint != NULL && cbPublicPoint > 0)
      rv = setSingleAttributeValue(attribute, pbPublicPoint, cbPublicPoint);
    else if (keyType == CKK_ML_DSA || keyType == CKK_ML_KEM)
      rv = CKR_DEVICE_ERROR;
    else
      rv = CKR_ATTRIBUTE_TYPE_INVALID;
    break;

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
      if (pbPublicPoint == NULL || cbPublicPoint == 0 || cbPublicPoint > 255) {
        rv = CKR_DEVICE_ERROR;
        break;
      }
      // Conventional CKK_EC points use the PKCS#11-mandated DER OCTET STRING
      // wrapper. Edwards and Montgomery objects use raw RFC bytes below.
      CK_BYTE encodedPoint[3 + 255];
      CK_ULONG headerLen;
      encodedPoint[0] = 0x04;
      if (cbPublicPoint < 0x80) {
        encodedPoint[1] = (CK_BYTE)cbPublicPoint;
        headerLen = 2;
      } else {
        encodedPoint[1] = 0x81;
        encodedPoint[2] = (CK_BYTE)cbPublicPoint;
        headerLen = 3;
      }
      memcpy(encodedPoint + headerLen, pbPublicPoint, cbPublicPoint);
      rv = setSingleAttributeValue(attribute, encodedPoint, headerLen + cbPublicPoint);
    } else if (keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
      rv = setSingleAttributeValue(attribute, pbPublicPoint, cbPublicPoint);
    } else {
      // Not applicable for non-ECC keys
      rv = CKR_ATTRIBUTE_TYPE_INVALID;
    }
    break;

  case CKA_EC_PARAMS:
    if (keyType == CKK_EC || keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
      rv = setEcParamsAttribute(session, attribute, algorithm_type);
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

  case CKA_LOCAL:
    return setSingleAttributeValue(attribute, &secret->local, sizeof(secret->local));

  case CKA_KEY_GEN_MECHANISM:
    return setSingleAttributeValue(attribute, &secret->keyGenMechanism, sizeof(secret->keyGenMechanism));

  default:
    return CKR_ATTRIBUTE_TYPE_INVALID;
  }
}

static CK_RV handleSessionSecretAttribute(CK_ATTRIBUTE_PTR attribute, const CNK_PKCS11_SECRET_KEY_OBJECT *secret) {
  switch (attribute->type) {
  case CKA_TOKEN:
    return setSingleAttributeValue(attribute, &secret->token, sizeof(secret->token));
  case CKA_PRIVATE:
    return setSingleAttributeValue(attribute, &secret->private, sizeof(secret->private));
  case CKA_ID:
    return setSingleAttributeValue(attribute, &secret->id, sizeof(secret->id));
  case CKA_LABEL:
    return setSingleAttributeValue(attribute, secret->label, secret->labelLen);
  case CKA_MODIFIABLE:
    return setSingleAttributeValue(attribute, &secret->modifiable, sizeof(secret->modifiable));
  case CKA_COPYABLE:
    return setSingleAttributeValue(attribute, &secret->copyable, sizeof(secret->copyable));
  case CKA_DESTROYABLE:
    return setSingleAttributeValue(attribute, &secret->destroyable, sizeof(secret->destroyable));
  default:
    return handleSecretKeyAttribute(attribute, secret);
  }
}

static CK_BBOOL matchSessionSecretTemplate(const CNK_PKCS11_SECRET_KEY_OBJECT *secret, CK_ATTRIBUTE_PTR pTemplate,
                                           CK_ULONG ulCount) {
  CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
  for (CK_ULONG i = 0; i < ulCount; i++) {
    if (pTemplate[i].ulValueLen > 0 && pTemplate[i].pValue == NULL)
      return CK_FALSE;
    CK_ATTRIBUTE actual = {pTemplate[i].type, NULL, 0};
    CK_RV rv = actual.type == CKA_CLASS ? setSingleAttributeValue(&actual, &secretClass, sizeof(secretClass))
                                        : handleSessionSecretAttribute(&actual, secret);
    if (rv != CKR_OK || actual.ulValueLen != pTemplate[i].ulValueLen)
      return CK_FALSE;
    if (actual.ulValueLen == 0)
      continue;
    actual.pValue = ck_malloc(actual.ulValueLen);
    if (actual.pValue == NULL)
      return CK_FALSE;
    CK_ULONG valueLen = actual.ulValueLen;
    rv = actual.type == CKA_CLASS ? setSingleAttributeValue(&actual, &secretClass, sizeof(secretClass))
                                  : handleSessionSecretAttribute(&actual, secret);
    CK_BBOOL matches =
        rv == CKR_OK && actual.ulValueLen == valueLen && memcmp(actual.pValue, pTemplate[i].pValue, valueLen) == 0;
    mbedtls_platform_zeroize(actual.pValue, valueLen);
    ck_free(actual.pValue);
    if (!matches)
      return CK_FALSE;
  }
  return CK_TRUE;
}

// Handle private key specific attributes
static CK_RV handlePrivateKeyAttribute(CNK_PKCS11_SESSION *session, CK_ATTRIBUTE_PTR attribute, CK_BYTE algorithm_type,
                                       CK_BYTE pinPolicy) {
  CNK_LOG_FUNC(" attribute = %d, algorithm_type = %d", attribute->type, algorithm_type);

  CK_RV rv = CKR_ATTRIBUTE_TYPE_INVALID;
  CK_KEY_TYPE key_type = algoType2KeyType(session, algorithm_type);

  switch (attribute->type) {
  case CKA_KEY_TYPE:
    rv = setSingleAttributeValue(attribute, &key_type, sizeof(key_type));
    break;

  case CKA_SIGN: {
    CK_BBOOL value = CNK_PivPrivateKeyCanSign(algorithm_type) || algorithm_type == session->mldsa65Algorithm ||
                     algorithm_type == session->ed25519Algorithm;
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

  case CKA_DECAPSULATE: {
    CK_BBOOL value = key_type == CKK_ML_KEM ? CK_TRUE : CK_FALSE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_PARAMETER_SET: {
    CK_ULONG parameterSet;
    if (key_type == CKK_ML_DSA)
      parameterSet = CKP_ML_DSA_65;
    else if (key_type == CKK_ML_KEM)
      parameterSet = CKP_ML_KEM_768;
    else {
      rv = CKR_ATTRIBUTE_TYPE_INVALID;
      break;
    }
    rv = setSingleAttributeValue(attribute, &parameterSet, sizeof(parameterSet));
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

  case CKA_SEED:
    rv = (key_type == CKK_ML_DSA || key_type == CKK_ML_KEM) ? CKR_ATTRIBUTE_SENSITIVE : CKR_ATTRIBUTE_TYPE_INVALID;
    break;

  case CKA_VALUE:
    rv = CKR_ATTRIBUTE_SENSITIVE;
    break;

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
    CK_BBOOL value = CNK_PivPrivateKeyCanDerive(algorithm_type) ||
                     (session->x25519Algorithm != 0 && algorithm_type == session->x25519Algorithm);
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_EC_PARAMS:
    if (key_type == CKK_EC || key_type == CKK_EC_EDWARDS || key_type == CKK_EC_MONTGOMERY)
      rv = setEcParamsAttribute(session, attribute, algorithm_type);
    break;

  default:
    rv = CKR_ATTRIBUTE_TYPE_INVALID;
    break;
  }

  return rv;
}
