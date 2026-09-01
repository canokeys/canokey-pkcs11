#include "api/object.h"
#include "api/session.h"
#include "backend/pcsc.h"
#include "internal/logging.h"
#include "internal/macros.h"
#include "internal/mlkem.h"
#include "internal/template.h"
#include "pkcs11.h"

#include <mbedtls/platform_util.h>
#include <string.h>

static CK_RV createSharedSecret(CNK_PKCS11_SESSION *session, CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount,
                                const CK_BYTE value[CNK_MLKEM768_SHARED_SECRET_BYTES], CK_OBJECT_HANDLE_PTR key) {
  // Encapsulation and decapsulation converge here so both produce identical
  // session-object defaults, policy validation, and handle allocation.
  CK_OBJECT_CLASS objectClass = CKO_SECRET_KEY;
  CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
  CK_ULONG valueLen = CNK_MLKEM768_SHARED_SECRET_BYTES;
  CK_BBOOL token = CK_FALSE;
  CK_BBOOL privateObject = CK_TRUE;
  CK_BBOOL sensitive = CK_FALSE;
  CK_BBOOL extractable = CK_TRUE;
  CK_BBOOL encrypt = CK_FALSE, decrypt = CK_FALSE, sign = CK_FALSE, verify = CK_FALSE;
  CK_BBOOL wrap = CK_FALSE, unwrap = CK_FALSE, derive = CK_FALSE;
  const CK_BYTE *label = NULL;
  CK_ULONG labelLen = 0;

  for (CK_ULONG i = 0; i < attributeCount; i++) {
    CK_ATTRIBUTE_PTR attribute = &attributes[i];
    switch (attribute->type) {
    case CKA_CLASS:
      if (attribute->pValue == NULL || attribute->ulValueLen != sizeof(objectClass))
        return CKR_ATTRIBUTE_VALUE_INVALID;
      objectClass = *(CK_OBJECT_CLASS *)attribute->pValue;
      break;
    case CKA_KEY_TYPE:
      if (attribute->pValue == NULL || attribute->ulValueLen != sizeof(keyType))
        return CKR_ATTRIBUTE_VALUE_INVALID;
      keyType = *(CK_KEY_TYPE *)attribute->pValue;
      break;
    case CKA_VALUE_LEN:
      if (attribute->pValue == NULL || attribute->ulValueLen != sizeof(valueLen))
        return CKR_ATTRIBUTE_VALUE_INVALID;
      valueLen = *(CK_ULONG *)attribute->pValue;
      break;
    case CKA_TOKEN:
      CNK_ENSURE_OK(cnk_attribute_get_bool(attribute, &token));
      break;
    case CKA_PRIVATE:
      CNK_ENSURE_OK(cnk_attribute_get_bool(attribute, &privateObject));
      break;
    case CKA_SENSITIVE:
      CNK_ENSURE_OK(cnk_attribute_get_bool(attribute, &sensitive));
      break;
    case CKA_EXTRACTABLE:
      CNK_ENSURE_OK(cnk_attribute_get_bool(attribute, &extractable));
      break;
    case CKA_ENCRYPT:
      CNK_ENSURE_OK(cnk_attribute_get_bool(attribute, &encrypt));
      break;
    case CKA_DECRYPT:
      CNK_ENSURE_OK(cnk_attribute_get_bool(attribute, &decrypt));
      break;
    case CKA_SIGN:
      CNK_ENSURE_OK(cnk_attribute_get_bool(attribute, &sign));
      break;
    case CKA_VERIFY:
      CNK_ENSURE_OK(cnk_attribute_get_bool(attribute, &verify));
      break;
    case CKA_WRAP:
      CNK_ENSURE_OK(cnk_attribute_get_bool(attribute, &wrap));
      break;
    case CKA_UNWRAP:
      CNK_ENSURE_OK(cnk_attribute_get_bool(attribute, &unwrap));
      break;
    case CKA_DERIVE:
      CNK_ENSURE_OK(cnk_attribute_get_bool(attribute, &derive));
      break;
    case CKA_LABEL:
      if (attribute->pValue == NULL && attribute->ulValueLen != 0)
        return CKR_ATTRIBUTE_VALUE_INVALID;
      label = attribute->pValue;
      labelLen = attribute->ulValueLen;
      break;
    default:
      return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }

  if (objectClass != CKO_SECRET_KEY || (keyType != CKK_GENERIC_SECRET && keyType != CKK_AES) || token)
    return CKR_TEMPLATE_INCONSISTENT;
  if (valueLen != CNK_MLKEM768_SHARED_SECRET_BYTES)
    return CKR_KEY_SIZE_RANGE;
  if (labelLen > sizeof(session->secretKeys[0].label))
    return CKR_ATTRIBUTE_VALUE_INVALID;
  if (privateObject && !cnk_token_pin_is_cached(session))
    return CKR_USER_NOT_LOGGED_IN;

  CNK_PKCS11_SECRET_KEY_OBJECT prototype = {0};
  prototype.keyType = keyType;
  prototype.valueLen = valueLen;
  prototype.extractable = extractable;
  prototype.sensitive = sensitive;
  prototype.private = privateObject;
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
  prototype.keyGenMechanism = CKM_ML_KEM;
  memcpy(prototype.value, value, valueLen);
  if (label != NULL && labelLen > 0) {
    prototype.labelLen = labelLen;
    memcpy(prototype.label, label, labelLen);
  } else {
    static const char defaultLabel[] = "ML-KEM Shared Secret";
    prototype.labelLen = sizeof(defaultLabel) - 1;
    memcpy(prototype.label, defaultLabel, prototype.labelLen);
  }

  CK_RV rv = CNK_CreateSessionSecretKey(session, &prototype, key);
  // The allocator owns its copy; remove the second plaintext copy immediately.
  mbedtls_platform_zeroize(&prototype, sizeof(prototype));
  return rv;
}

CK_RV C_EncapsulateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE publicKey,
                       CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_BYTE_PTR ciphertext,
                       CK_ULONG_PTR ciphertextLen, CK_OBJECT_HANDLE_PTR key) {
  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(mechanism);
  CNK_ENSURE_NONNULL(ciphertextLen, key);
  if (attributeCount > 0)
    CNK_ENSURE_NONNULL(attributes);
  if (mechanism->mechanism != CKM_ML_KEM || mechanism->pParameter != NULL || mechanism->ulParameterLen != 0)
    return CKR_MECHANISM_INVALID;
  if (ciphertext == NULL) {
    *ciphertextLen = CNK_MLKEM768_CIPHERTEXT_BYTES;
    *key = CK_INVALID_HANDLE;
    return CKR_OK;
  }
  if (*ciphertextLen < CNK_MLKEM768_CIPHERTEXT_BYTES) {
    *ciphertextLen = CNK_MLKEM768_CIPHERTEXT_BYTES;
    return CKR_BUFFER_TOO_SMALL;
  }

  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  CK_BYTE objectId, pivSlot, algorithmType;
  CNK_ENSURE_OK(CNK_ValidateObject(publicKey, session, CKO_PUBLIC_KEY, &objectId));
  CNK_ENSURE_OK(C_CNK_ObjIdToPivTag(objectId, &pivSlot));
  CNK_ENSURE_OK(cnk_get_metadata(session->slotId, pivSlot, &algorithmType, NULL, NULL, NULL, NULL));
  if (session->mlkem768Algorithm == 0 || algorithmType != session->mlkem768Algorithm)
    return CKR_KEY_TYPE_INCONSISTENT;
  CK_BYTE encodedPublicKey[CNK_MLKEM768_PUBLIC_KEY_BYTES];
  CK_ATTRIBUTE valueAttribute = {CKA_VALUE, encodedPublicKey, sizeof(encodedPublicKey)};
  CK_RV rv = C_GetAttributeValue(hSession, publicKey, &valueAttribute, 1);
  if (rv != CKR_OK)
    return rv;
  if (valueAttribute.ulValueLen != sizeof(encodedPublicKey))
    return CKR_KEY_TYPE_INCONSISTENT;

  CK_BYTE sharedSecret[CNK_MLKEM768_SHARED_SECRET_BYTES];
  rv = cnk_mlkem768_encapsulate(encodedPublicKey, ciphertext, sharedSecret);
  if (rv == CKR_OK)
    rv = createSharedSecret(session, attributes, attributeCount, sharedSecret, key);
  mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
  if (rv == CKR_OK)
    *ciphertextLen = CNK_MLKEM768_CIPHERTEXT_BYTES;
  return rv;
}

CK_RV C_DecapsulateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE privateKey,
                       CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_BYTE_PTR ciphertext,
                       CK_ULONG ciphertextLen, CK_OBJECT_HANDLE_PTR key) {
  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(mechanism);
  CNK_ENSURE_NONNULL(ciphertext, key);
  if (attributeCount > 0)
    CNK_ENSURE_NONNULL(attributes);
  if (mechanism->mechanism != CKM_ML_KEM || mechanism->pParameter != NULL || mechanism->ulParameterLen != 0)
    return CKR_MECHANISM_INVALID;
  if (ciphertextLen != CNK_MLKEM768_CIPHERTEXT_BYTES)
    return CKR_ENCRYPTED_DATA_LEN_RANGE;

  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CK_BYTE objectId, pivSlot;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  CNK_ENSURE_OK(CNK_ValidateObject(privateKey, session, CKO_PRIVATE_KEY, &objectId));
  CNK_ENSURE_OK(C_CNK_ObjIdToPivTag(objectId, &pivSlot));
  CK_BYTE algorithmType, pinPolicy = CNK_DefaultPinPolicyForPivObjectId(objectId);
  CK_BYTE publicKey[2048];
  CK_ULONG publicKeyLen = sizeof(publicKey);
  CNK_ENSURE_OK(cnk_get_metadata(session->slotId, pivSlot, &algorithmType, publicKey, &publicKeyLen, &pinPolicy, NULL));
  if (algorithmType != session->mlkem768Algorithm)
    return CKR_KEY_TYPE_INCONSISTENT;

  CK_BYTE sharedSecret[CNK_MLKEM768_SHARED_SECRET_BYTES];
  CK_ULONG sharedSecretLen = sizeof(sharedSecret);
  CK_RV rv = cnk_piv_mlkem_decapsulate(session->slotId, session, algorithmType, pivSlot, pinPolicy, ciphertext,
                                       ciphertextLen, sharedSecret, &sharedSecretLen);
  if (rv == CKR_OK && sharedSecretLen != sizeof(sharedSecret))
    rv = CKR_DEVICE_ERROR;
  if (rv == CKR_OK)
    rv = createSharedSecret(session, attributes, attributeCount, sharedSecret, key);
  mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
  return rv;
}
