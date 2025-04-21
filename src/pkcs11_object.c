#include "logging.h"
#include "pcsc_backend.h"
#include "pkcs11.h"
#include "pkcs11_macros.h"
#include "pkcs11_mutex.h"
#include "pkcs11_session.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>

// Helper function to extract object information from a handle
// Object handle format: slot_id (16 bits) | object_class (8 bits) | object_id (8 bits)
void cnk_extract_object_info(CK_OBJECT_HANDLE hObject, CK_SLOT_ID *slot_id, CK_OBJECT_CLASS *obj_class,
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

// Helper function to map object ID to PIV tag
CK_RV cnk_obj_id_to_piv_tag(CK_BYTE obj_id, CK_BYTE *piv_tag) {
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

// Helper function to set attribute values with proper buffer checking
static CK_RV cnk_set_single_attribute_value(CK_ATTRIBUTE_PTR attribute, const void *value, CK_ULONG value_size) {
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

// Helper function to validate an object handle against a session and expected class
CK_RV cnk_validate_object(CK_OBJECT_HANDLE hObject, CNK_PKCS11_SESSION *session, CK_OBJECT_CLASS expected_class,
                          CK_BYTE *obj_id) {
  // Extract object information from the handle
  CK_SLOT_ID slot_id;
  CK_OBJECT_CLASS obj_class;

  cnk_extract_object_info(hObject, &slot_id, &obj_class, obj_id);

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

CK_KEY_TYPE cnk_algo_type_to_key_type(CK_BYTE algorithm_type) {
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
static CK_RV cnk_handle_certificate_attribute(CK_ATTRIBUTE_PTR attribute, CK_BYTE_PTR data, CK_ULONG data_len) {
  CNK_LOG_FUNC(" attribute = %d", attribute->type);

  CK_RV rv = CKR_ATTRIBUTE_TYPE_INVALID;

  switch (attribute->type) {
  case CKA_CERTIFICATE_TYPE: {
    CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
    rv = cnk_set_single_attribute_value(attribute, &cert_type, sizeof(cert_type));
    break;
  }

  case CKA_VALUE:
    // For certificates, return the raw certificate data
    rv = cnk_set_single_attribute_value(attribute, data, data_len);
    break;

    // Add other certificate attributes as needed
    // CKA_SUBJECT, CKA_ISSUER, CKA_SERIAL_NUMBER would require parsing the certificate

  default:
    rv = CKR_ATTRIBUTE_TYPE_INVALID;
    break;
  }

  return rv;
}

// Handle public key specific attributes
static CK_RV cnk_handle_public_key_attribute(CK_ATTRIBUTE_PTR attribute, CK_BYTE algorithm_type, CK_BYTE_PTR modulus,
                                             CK_ULONG modulus_len) {
  CNK_LOG_FUNC(" attribute = 0x%x, algorithm_type = 0x%x", attribute->type, algorithm_type);

  CK_RV rv = CKR_ATTRIBUTE_TYPE_INVALID;
  CK_KEY_TYPE key_type = cnk_algo_type_to_key_type(algorithm_type);

  switch (attribute->type) {
  case CKA_KEY_TYPE:
    rv = cnk_set_single_attribute_value(attribute, &key_type, sizeof(key_type));
    break;

  case CKA_VERIFY: {
    // Public keys can be used for verification
    CK_BBOOL value = CK_TRUE;
    rv = cnk_set_single_attribute_value(attribute, &value, sizeof(value));
    break;
  }

  case CKA_ENCRYPT: {
    // Only RSA public keys can encrypt
    CK_BBOOL value = (key_type == CKK_RSA) ? CK_TRUE : CK_FALSE;
    rv = cnk_set_single_attribute_value(attribute, &value, sizeof(value));
    break;
  }

  case CKA_MODULUS_BITS:
    if (key_type == CKK_RSA) {
      CK_ULONG modulus_bits = modulus_len * 8;
      rv = cnk_set_single_attribute_value(attribute, &modulus_bits, sizeof(modulus_bits));
    } else {
      // Not applicable for non-RSA keys
      rv = CKR_ATTRIBUTE_TYPE_INVALID;
    }
    break;

  case CKA_MODULUS:
    if (key_type == CKK_RSA) {
      rv = cnk_set_single_attribute_value(attribute, modulus, modulus_len);
    } else {
      // Not applicable for non-RSA keys
      rv = CKR_ATTRIBUTE_TYPE_INVALID;
    }
    break;

    // TODO: Add other public key attributes

  default:
    rv = CKR_ATTRIBUTE_TYPE_INVALID;
    break;
  }

  return rv;
}

// Handle private key specific attributes
static CK_RV cnk_handle_private_key_attribute(CK_ATTRIBUTE_PTR attribute, CK_BYTE algorithm_type) {
  CK_RV rv = CKR_ATTRIBUTE_TYPE_INVALID;
  CK_KEY_TYPE key_type = cnk_algo_type_to_key_type(algorithm_type);

  switch (attribute->type) {
  case CKA_KEY_TYPE:
    rv = cnk_set_single_attribute_value(attribute, &key_type, sizeof(key_type));
    break;

  case CKA_SIGN: {
    // Private keys can be used for signing
    CK_BBOOL value = CK_TRUE;
    rv = cnk_set_single_attribute_value(attribute, &value, sizeof(value));
    break;
  }

  case CKA_DECRYPT: {
    // Only RSA private keys can decrypt
    CK_BBOOL value = (key_type == CKK_RSA) ? CK_TRUE : CK_FALSE;
    rv = cnk_set_single_attribute_value(attribute, &value, sizeof(value));
    break;
  }

  case CKA_SENSITIVE:
  case CKA_ALWAYS_SENSITIVE: {
    // Private keys are always sensitive
    CK_BBOOL value = CK_TRUE;
    rv = cnk_set_single_attribute_value(attribute, &value, sizeof(value));
    break;
  }

  case CKA_EXTRACTABLE: {
    // Private keys on PIV are never extractable
    CK_BBOOL value = CK_FALSE;
    rv = cnk_set_single_attribute_value(attribute, &value, sizeof(value));
    break;
  }

    // Add other private key attributes as needed

  default:
    rv = CKR_ATTRIBUTE_TYPE_INVALID;
    break;
  }

  return rv;
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
  CK_OBJECT_CLASS obj_class;
  CK_BYTE obj_id;
  CNK_ENSURE_OK(cnk_validate_object(hObject, session, 0, &obj_id));

  // Get object class from handle
  cnk_extract_object_info(hObject, NULL, &obj_class, NULL);
  CNK_DEBUG("Object handle: slot %lu, class %lu, id %lu", session->slot_id, obj_class, obj_id);

  // Map object ID to PIV tag
  CK_BYTE piv_tag;
  CNK_ENSURE_OK(cnk_obj_id_to_piv_tag(obj_id, &piv_tag));

  // Fetch the PIV data for this object
  CK_ULONG data_len = 0;
  CK_BYTE_PTR data = NULL;

  CNK_ENSURE_OK(cnk_get_piv_data(session->slot_id, piv_tag, &data, &data_len, CK_FALSE));

  // If no data was found, the object doesn't exist
  if (data_len == 0) {
    CNK_RETURN(CKR_OBJECT_HANDLE_INVALID, "No data found for PIV tag");
  }

  // Get key metadata if this is a key object
  CK_BYTE algorithm_type;
  CK_BYTE modulus[512];
  CK_ULONG modulus_len = sizeof(modulus);

  if (obj_class == CKO_PUBLIC_KEY || obj_class == CKO_PRIVATE_KEY) {
    CK_RV rv = cnk_get_metadata(session->slot_id, piv_tag, &algorithm_type, modulus, &modulus_len);
    if (rv != CKR_OK) {
      CNK_DEBUG("Failed to get metadata for PIV tag 0x%02X: %lu", piv_tag, rv);
      // Continue anyway, we'll use default values
    } else {
      CNK_DEBUG("Retrieved algorithm type %u for PIV tag 0x%02X", algorithm_type, piv_tag);
    }
  }

  // Process each attribute in the template
  CK_RV return_rv = CKR_OK; // Final return value

  for (CK_ULONG i = 0; i < ulCount; i++) {
    CK_RV rv = CKR_ATTRIBUTE_TYPE_INVALID; // Default to attribute not found
    CK_BBOOL bbool;

    // Common attributes for all object types
    switch (pTemplate[i].type) {
    case CKA_CLASS:
      rv = cnk_set_single_attribute_value(&pTemplate[i], &obj_class, sizeof(obj_class));
      break;

    case CKA_TOKEN:
      bbool = CK_TRUE;
      rv = cnk_set_single_attribute_value(&pTemplate[i], &bbool, sizeof(bbool));
      break;

    case CKA_PRIVATE:
      bbool = (obj_class == CKO_PRIVATE_KEY) ? CK_TRUE : CK_FALSE;
      rv = cnk_set_single_attribute_value(&pTemplate[i], &bbool, sizeof(bbool));
      break;

    case CKA_ID:
      rv = cnk_set_single_attribute_value(&pTemplate[i], &obj_id, sizeof(obj_id));
      break;

    case CKA_LABEL: {
      // Create a label based on the object type and ID
      char label[32];
      const char *type_str = "Unknown";

      switch (obj_class) {
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

      snprintf(label, sizeof(label), "PIV %s %02X", type_str, piv_tag);
      CK_ULONG label_len = (CK_ULONG)strlen(label);
      rv = cnk_set_single_attribute_value(&pTemplate[i], label, label_len);
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
    switch (obj_class) {
    case CKO_CERTIFICATE:
      rv = cnk_handle_certificate_attribute(&pTemplate[i], data, data_len);
      break;

    case CKO_PUBLIC_KEY:
      rv = cnk_handle_public_key_attribute(&pTemplate[i], algorithm_type, modulus, modulus_len);
      break;

    case CKO_PRIVATE_KEY:
      rv = cnk_handle_private_key_attribute(&pTemplate[i], algorithm_type);
      break;

    default:
      // Unsupported object class
      rv = CKR_ATTRIBUTE_TYPE_INVALID;
      break;
    }

    if (rv != CKR_OK) {
      pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
      if (return_rv == CKR_OK) {
        return_rv = rv;
      }
    }
  }

  // Free the PIV data if it was allocated
  if (data != NULL) {
    ck_free(data);
  }

  CNK_RETURN(return_rv, "Finished");
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
  if (session->find_active) {
    cnk_mutex_unlock(&session->lock);
    return CKR_OPERATION_ACTIVE;
  }

  // Reset find operation state
  session->find_active = CK_TRUE;
  session->find_objects_count = 0;
  session->find_objects_position = 0;
  session->find_id_specified = CK_FALSE;
  session->find_class_specified = CK_FALSE;

  // Parse the template
  for (CK_ULONG i = 0; i < ulCount; i++) {
    if (pTemplate[i].type == CKA_CLASS && pTemplate[i].pValue != NULL &&
        pTemplate[i].ulValueLen == sizeof(CK_OBJECT_CLASS)) {
      session->find_object_class = *((CK_OBJECT_CLASS *)pTemplate[i].pValue);
      session->find_class_specified = CK_TRUE;
    } else if (pTemplate[i].type == CKA_ID && pTemplate[i].pValue != NULL &&
               pTemplate[i].ulValueLen == sizeof(CK_BYTE)) {
      session->find_object_id = *((CK_BYTE *)pTemplate[i].pValue);
      session->find_id_specified = CK_TRUE;
    }
  }

  // If no class is specified, we can't search
  if (!session->find_class_specified) {
    session->find_active = CK_FALSE;
    cnk_mutex_unlock(&session->lock);
    CNK_RET_OK; // Return OK but with no results
  }

  // Check if the specified class is supported
  if (session->find_class_specified && session->find_object_class != CKO_CERTIFICATE &&
      session->find_object_class != CKO_PUBLIC_KEY && session->find_object_class != CKO_PRIVATE_KEY &&
      session->find_object_class != CKO_DATA) {
    session->find_active = CK_FALSE;
    cnk_mutex_unlock(&session->lock);
    CNK_RET_OK; // Return OK but with no results
  }

  // If an ID is specified, we only need to check that specific ID
  if (session->find_id_specified) {
    // Check if the ID is valid (1-6)
    if (session->find_object_id < 1 || session->find_object_id > 6) {
      session->find_active = CK_FALSE;
      cnk_mutex_unlock(&session->lock);
      CNK_RET_OK; // Return OK but with no results
    }

    // Map CKA_ID to PIV tag
    CK_BYTE piv_tag;
    rv = cnk_obj_id_to_piv_tag(session->find_object_id, &piv_tag);
    if (rv != CKR_OK) {
      session->find_active = CK_FALSE;
      cnk_mutex_unlock(&session->lock);
      CNK_RET_OK; // Return OK but with no results
    }

    // Try to get the data for this tag
    CK_BYTE_PTR data = NULL;
    CK_ULONG data_len = 0;
    rv = cnk_get_piv_data(session->slot_id, piv_tag, &data, &data_len, CK_FALSE); // Just check existence

    if (rv != CKR_OK) {
      session->find_active = CK_FALSE;
      cnk_mutex_unlock(&session->lock);
      return rv;
    }

    // If data exists, add this object to the results
    if (data_len > 0) {
      // Create a handle for this object: slot_id | object_class | object_id
      // This will allow us to identify the object in future operations
      CK_OBJECT_HANDLE handle =
          (session->slot_id << 16) | ((CK_ULONG)session->find_object_class << 8) | session->find_object_id;
      session->find_objects[session->find_objects_count++] = handle;
      ck_free(data);
    }
  } else {
    // No ID specified, check all possible IDs (1-6)
    for (CK_BYTE id = 1; id <= 6; id++) {
      // Map ID to PIV tag
      CK_BYTE piv_tag;
      if (cnk_obj_id_to_piv_tag(id, &piv_tag) != CKR_OK) {
        continue;
      }

      // Try to get the data for this tag
      CK_BYTE_PTR data = NULL;
      CK_ULONG data_len = 0;
      rv = cnk_get_piv_data(session->slot_id, piv_tag, &data, &data_len, CK_FALSE); // Just check existence

      if (rv != CKR_OK) {
        session->find_active = CK_FALSE;
        cnk_mutex_unlock(&session->lock);
        return rv;
      }

      // If data exists, add this object to the results
      if (data_len > 0) {
        // Create a handle for this object: slot_id | object_class | object_id
        CK_OBJECT_HANDLE handle = (session->slot_id << 16) | ((CK_ULONG)session->find_object_class << 8) | id;
        session->find_objects[session->find_objects_count++] = handle;
        ck_free(data);
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
  if (!session->find_active) {
    cnk_mutex_unlock(&session->lock);
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  // Calculate how many objects to return
  CK_ULONG remaining = session->find_objects_count - session->find_objects_position;
  CK_ULONG count = (remaining < ulMaxObjectCount) ? remaining : ulMaxObjectCount;

  // Copy the object handles
  for (CK_ULONG i = 0; i < count; i++) {
    phObject[i] = session->find_objects[session->find_objects_position + i];
  }

  // Update the position
  session->find_objects_position += count;

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
  if (!session->find_active) {
    cnk_mutex_unlock(&session->lock);
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  // End the find operation
  session->find_active = CK_FALSE;
  session->find_objects_count = 0;
  session->find_objects_position = 0;

  cnk_mutex_unlock(&session->lock);
  CNK_RET_OK;
}
