#include "pkcs11_object.h"
#include "logging.h"
#include "pcsc_backend.h"
#include "pkcs11.h"
#include "pkcs11_macros.h"
#include "pkcs11_mutex.h"
#include "utils.h"

#include <mbedtls/asn1write.h>
#include <mbedtls/oid.h>
#include <string.h>

static CK_RV setSingleAttributeValue(CK_ATTRIBUTE_PTR attribute, const void *value, CK_ULONG value_size);
static void extractObjectInfo(CK_OBJECT_HANDLE hObject, CK_SLOT_ID *slot_id, CK_OBJECT_CLASS *obj_class,
                              CK_BYTE *obj_id);
static CK_KEY_TYPE algoType2KeyType(CK_BYTE algorithm_type);
static CK_RV handleCertificateAttribute(CK_ATTRIBUTE_PTR attribute, CK_BYTE_PTR data, CK_ULONG data_len);
static CK_RV handlePublicKeyAttribute(CK_ATTRIBUTE_PTR attribute, CK_BYTE algorithm_type, CK_BYTE_PTR pbPublicKey,
                                      CK_ULONG cbPublicKey);
static CK_RV handlePrivateKeyAttribute(CK_ATTRIBUTE_PTR attribute, CK_BYTE algorithm_type);
static CK_BBOOL matchTemplate(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                              CK_ULONG ulCount);

// Helper function to map object ID to PIV tag
CK_RV C_CNK_ObjIdToPivTag(CK_BYTE obj_id, CK_BYTE *piv_tag) {
  switch (obj_id) {
  case PIV_SLOT_9A:
    *piv_tag = 0x9A;
    break;
  case PIV_SLOT_9C:
    *piv_tag = 0x9C;
    break;
  case PIV_SLOT_9D:
    *piv_tag = 0x9D;
    break;
  case PIV_SLOT_9E:
    *piv_tag = 0x9E;
    break;
  case PIV_SLOT_82:
    *piv_tag = 0x82;
    break;
  case PIV_SLOT_83:
    *piv_tag = 0x83;
    break;
  default:
    return CKR_OBJECT_HANDLE_INVALID;
  }
  CNK_RET_OK;
}

// Helper function to validate an object handle against a session and expected class
CK_RV CNK_ValidateObject(CK_OBJECT_HANDLE hObject, CNK_PKCS11_SESSION *session, CK_OBJECT_CLASS expected_class,
                         CK_BYTE *obj_id) {
  // Extract object information from the handle
  CK_SLOT_ID slot_id;
  CK_OBJECT_CLASS obj_class;

  extractObjectInfo(hObject, &slot_id, &obj_class, obj_id);

  // Verify the slot ID matches the session's slot ID
  if (slot_id != session->slot_id) {
    CNK_RETURN(CKR_OBJECT_HANDLE_INVALID, "slot ID mismatch");
  }

  // Verify the object class if expected_class is not 0
  if (expected_class != 0 && obj_class != expected_class) {
    CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "object class mismatch");
  }

  CNK_RET_OK;
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
  CNK_DEBUG("Object handle: slot %lu, class %lu, id %lu", session->slot_id, objClass, objId);

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
    CK_RV rvMeta = cnk_get_metadata(session->slot_id, bPivSlot, &bAlgorithmType, abPublicKey, &cbPublicKey);
    if (rvMeta != CKR_OK) {
      CNK_DEBUG("Failed to get metadata for PIV slot 0x%02X: %lu", bPivSlot, rvMeta);
    } else {
      CNK_DEBUG("Retrieved algorithm type %u for PIV slot 0x%02X with public key size %lu", bAlgorithmType, bPivSlot,
                cbPublicKey);
    }
    break;
  }

  case CKO_CERTIFICATE:
    CNK_ENSURE_OK(cnk_get_piv_data(session->slot_id, bPivSlot, data, &cbData, CK_TRUE));
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
    rv = cnk_get_piv_data(session->slot_id, piv_tag, NULL, NULL, CK_FALSE); // Just check existence
    if (rv != CKR_OK && rv != CKR_DATA_INVALID) {
      session->findActive = CK_FALSE;
      cnk_mutex_unlock(&session->lock);
      return rv;
    }

    // If data exists, add this object to the results
    if (rv == CKR_OK) {
      // Create a handle for this object: slot_id | object_class | object_id
      // This will allow us to identify the object in future operations
      CK_OBJECT_HANDLE handle = (session->slot_id << 16) | (session->findObjectClass << 8) | session->findObjectId;
      session->findObjects[session->findObjectsCount++] = handle;
    }
  } else {
    CNK_DEBUG("ID not specified");

    // No ID specified, check all possible IDs (1-6)
    for (CK_BYTE id = 1; id <= 6; id++) {
      CK_OBJECT_HANDLE hObject = (session->slot_id << 16) | (session->findObjectClass << 8) | id;
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

  // free memory
  for (CK_ULONG i = 0; i < ulCount; i++) {
    ck_free(attrs[i].pValue);
  }
  ck_free(attrs);

  CNK_RETURN(matched, "Template matching finished");
}

// Helper function to set attribute values with proper buffer checking
static CK_RV setSingleAttributeValue(CK_ATTRIBUTE_PTR attribute, const void *value, CK_ULONG value_size) {
  attribute->ulValueLen = value_size;

  if (attribute->pValue) {
    if (attribute->ulValueLen >= value_size) {
      memcpy(attribute->pValue, value, value_size);
    } else {
      return CKR_BUFFER_TOO_SMALL;
    }
  }

  CNK_RET_OK;
}

// Helper function to extract object information from a handle
// Object handle format: slot_id (16 bits) | object_class (8 bits) | object_id (8 bits)
static void extractObjectInfo(CK_OBJECT_HANDLE hObject, CK_SLOT_ID *slot_id, CK_OBJECT_CLASS *obj_class,
                              CK_BYTE *obj_id) {
  if (slot_id) {
    *slot_id = (hObject >> 16) & 0xFFFF;
  }
  if (obj_class) {
    *obj_class = (hObject >> 8) & 0xFF;
  }
  if (obj_id) {
    *obj_id = hObject & 0xFF;
  }
}

static CK_KEY_TYPE algoType2KeyType(CK_BYTE algorithm_type) {
  switch (algorithm_type) {
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
  case PIV_ALG_X25519:
    return CKK_EC_EDWARDS;

  default:
    return CKK_VENDOR_DEFINED;
  }
}

// Handle certificate-specific attributes
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
