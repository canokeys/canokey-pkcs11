/**
 * @file pkcs11_object.c
 * @brief PKCS#11 object management implementation
 *
 * This module implements the PKCS#11 object management functions for the CanoKey PKCS#11 module.
 * It handles the creation, manipulation, and querying of cryptographic objects like keys and certificates.
 */

#include "pkcs11_object.h"
#include "logging.h"
#include "pcsc_backend.h"
#include "pkcs11.h"
#include "pkcs11_macros.h"
#include "pkcs11_mutex.h"
#include "utils.h"

#include <mbedtls/asn1write.h>
#include <mbedtls/oid.h>
#include <stddef.h> // For size_t
#include <string.h>

// Maximum size for certificate data buffer
#define MAX_CERTIFICATE_SIZE 4096

// Maximum size for public key buffer
#define MAX_PUBLIC_KEY_SIZE 512

// Object handle bit field masks
#define OBJECT_SLOT_MASK 0xFFFF0000
#define OBJECT_CLASS_MASK 0x0000FF00
#define OBJECT_ID_MASK 0x000000FF

// Object handle bit shifts
#define OBJECT_SLOT_SHIFT 16
#define OBJECT_CLASS_SHIFT 8

// PIV slot to tag mapping
typedef struct {
  CK_BYTE objId;
  CK_BYTE pivTag;
} PivSlotMapping;

static const PivSlotMapping PIV_SLOT_MAPPING[] = {
    {PIV_SLOT_9A, 0x9A}, {PIV_SLOT_9C, 0x9C}, {PIV_SLOT_9D, 0x9D},
    {PIV_SLOT_9E, 0x9E}, {PIV_SLOT_82, 0x82}, {PIV_SLOT_83, 0x83},
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
 * @return CK_RV CKR_OK on success, error code otherwise
 */
static CK_RV handlePrivateKeyAttribute(CK_ATTRIBUTE_PTR attribute, CK_BYTE algorithmType);

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

/**
 * @brief Map a PIV object ID to its corresponding PIV tag
 *
 * @param objId The PIV object ID to map
 * @param pivTag [out] Pointer to store the resulting PIV tag
 * @return CK_RV CKR_OK on success, CKR_OBJECT_HANDLE_INVALID if the object ID is unknown
 */
CK_RV C_CNK_ObjIdToPivTag(CK_BYTE objId, CK_BYTE *pivTag) {
  if (!pivTag) {
    CNK_ERROR("piv_tag cannot be NULL");
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
  extractObjectInfo(hObject, &slot_id, &obj_class, objId);

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

  return CKR_OK;
}

// Object operation implementations
CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                     CK_OBJECT_HANDLE_PTR phObject) {
  CNK_LOG_FUNC(": hSession: %lu, pTempate: %p, ulCount: %lu, phObject: %p", hSession, pTemplate, ulCount, phObject);
  CNK_ENSURE_INITIALIZED();

  CNK_RET_UNIMPL;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                   CK_OBJECT_HANDLE_PTR phNewObject) {
  CNK_LOG_FUNC(": hSession: %lu, hObject: %lu, pTemplate: %p, ulCount: %lu, phNewObject: %p", hSession, hObject,
               pTemplate, ulCount, phNewObject);
  CNK_ENSURE_INITIALIZED();

  CNK_RET_UNIMPL;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
  CNK_LOG_FUNC(": hSession: %lu, hObject: %lu", hSession, hObject);
  CNK_ENSURE_INITIALIZED();
  CNK_RET_UNIMPL;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) {
  CNK_LOG_FUNC(": hSession: %lu, hObject: %lu, pulSize: %p", hSession, hObject, pulSize);
  CNK_ENSURE_INITIALIZED();

  CNK_RET_UNIMPL;
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
  CK_BYTE abPublicKey[512];
  CK_ULONG cbPublicKey = sizeof(abPublicKey);

  switch (objClass) {
  case CKO_PUBLIC_KEY:
  case CKO_PRIVATE_KEY: {
    CK_RV rvMeta = cnk_get_metadata(session->slotId, bPivSlot, &bAlgorithmType, abPublicKey, &cbPublicKey);
    if (rvMeta != CKR_OK) {
      CNK_DEBUG("Failed to get metadata for PIV slot 0x%02X: %lu", bPivSlot, rvMeta);
    } else {
      CNK_DEBUG("Retrieved algorithm type %u for PIV slot 0x%02X with public key size %lu", bAlgorithmType, bPivSlot,
                cbPublicKey);
    }
    break;
  }

  case CKO_CERTIFICATE:
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
      rv = handlePublicKeyAttribute(&pTemplate[i], bAlgorithmType, abPublicKey, cbPublicKey);
      break;

    case CKO_PRIVATE_KEY:
      rv = handlePrivateKeyAttribute(&pTemplate[i], bAlgorithmType);
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

  CNK_RET_UNIMPL;
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

  // If no class is specified, we can't search
  if (!session->findClassSpecified) {
    session->findActive = CK_FALSE;
    cnk_mutex_unlock(&session->lock);
    CNK_RET_OK; // Return OK but with no results
  }

  // Check if the specified class is supported
  if (session->findClassSpecified && session->findObjectClass != CKO_CERTIFICATE &&
      session->findObjectClass != CKO_PUBLIC_KEY && session->findObjectClass != CKO_PRIVATE_KEY &&
      session->findObjectClass != CKO_DATA) {
    session->findActive = CK_FALSE;
    cnk_mutex_unlock(&session->lock);
    CNK_RET_OK; // Return OK but with no results
  }

  // If an ID is specified, we only need to check that specific ID
  if (session->findIdSpecified) {
    CNK_DEBUG("ID specified: %d", session->findObjectId);

    // Check if the ID is valid (1-6)
    if (session->findObjectId < 1 || session->findObjectId > 6) {
      session->findActive = CK_FALSE;
      cnk_mutex_unlock(&session->lock);
      CNK_RET_OK; // Return OK but with no results
    }

    // Map CKA_ID to PIV tag
    CK_BYTE piv_tag;
    rv = C_CNK_ObjIdToPivTag(session->findObjectId, &piv_tag);
    if (rv != CKR_OK) {
      session->findActive = CK_FALSE;
      cnk_mutex_unlock(&session->lock);
      CNK_RET_OK; // Return OK but with no results
    }

    // Try to get the data for this tag
    rv = cnk_get_piv_data(session->slotId, piv_tag, NULL, NULL, CK_FALSE); // Just check existence
    if (rv != CKR_OK && rv != CKR_DATA_INVALID) {
      session->findActive = CK_FALSE;
      cnk_mutex_unlock(&session->lock);
      return rv;
    }

    // If data exists, add this object to the results
    if (rv == CKR_OK) {
      // Create a handle for this object: slot_id | object_class | object_id
      // This will allow us to identify the object in future operations
      CK_OBJECT_HANDLE handle = (session->slotId << 16) | (session->findObjectClass << 8) | session->findObjectId;
      session->findObjects[session->findObjectsCount++] = handle;
    }
  } else {
    CNK_DEBUG("ID not specified");

    // No ID specified, check all possible IDs (1-6)
    for (CK_BYTE id = 1; id <= 6; id++) {
      CK_OBJECT_HANDLE hObject = (session->slotId << 16) | (session->findObjectClass << 8) | id;
      if (matchTemplate(hSession, hObject, pTemplate, ulCount)) {
        session->findObjects[session->findObjectsCount++] = hObject;
      }
    }
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
    // Public keys can be used for verification
    CK_BBOOL value = CK_TRUE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_ENCRYPT: {
    // Only RSA public keys can encrypt
    CK_BBOOL value = (keyType == CKK_RSA) ? CK_TRUE : CK_FALSE;
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
      char *oid = NULL;
      switch (algorithm_type) {
      case PIV_ALG_ECC_256:
        oid = MBEDTLS_OID_EC_GRP_SECP256R1;
        break;
      case PIV_ALG_ECC_384:
        oid = MBEDTLS_OID_EC_GRP_SECP384R1;
        break;
      case PIV_ALG_SECP256K1:
        oid = MBEDTLS_OID_EC_GRP_SECP256K1;
        break;
      default:
        CNK_ERROR("Should not be reached");
        break;
      }
      CK_BYTE_PTR pbEcParams = abEcParams + sizeof(abEcParams);
      cbEcParams = mbedtls_asn1_write_oid(&pbEcParams, abEcParams, oid, sizeof(oid));
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

// Handle private key specific attributes
static CK_RV handlePrivateKeyAttribute(CK_ATTRIBUTE_PTR attribute, CK_BYTE algorithm_type) {
  CNK_LOG_FUNC(" attribute = %d, algorithm_type = %d", attribute->type, algorithm_type);

  CK_RV rv = CKR_ATTRIBUTE_TYPE_INVALID;
  CK_KEY_TYPE key_type = algoType2KeyType(algorithm_type);

  switch (attribute->type) {
  case CKA_KEY_TYPE:
    rv = setSingleAttributeValue(attribute, &key_type, sizeof(key_type));
    break;

  case CKA_SIGN: {
    // Private keys can be used for signing
    CK_BBOOL value = CK_TRUE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_DECRYPT: {
    // Only RSA private keys can decrypt
    CK_BBOOL value = (key_type == CKK_RSA) ? CK_TRUE : CK_FALSE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  case CKA_ENCRYPT: {
    // Private keys cannot encrypt
    CK_BBOOL value = CK_FALSE;
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

  case CKA_DERIVE: {
    // Only EC private keys can derive
    CK_BBOOL value = (key_type == CKK_EC) ? CK_TRUE : CK_FALSE;
    rv = setSingleAttributeValue(attribute, &value, sizeof(value));
    break;
  }

  default:
    rv = CKR_ATTRIBUTE_TYPE_INVALID;
    break;
  }

  return rv;
}
