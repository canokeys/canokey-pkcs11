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

CK_RV C_EncapsulateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE publicKey,
                       CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_BYTE_PTR ciphertext,
                       CK_ULONG_PTR ciphertextLen, CK_OBJECT_HANDLE_PTR key) {
  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(mechanism);
  CNK_ENSURE_NONNULL(ciphertextLen, key);
  if (attributeCount > 0)
    CNK_ENSURE_NONNULL(attributes);
  if (mechanism->mechanism != CKM_ML_KEM)
    return CKR_MECHANISM_INVALID;
  if (mechanism->pParameter != NULL || mechanism->ulParameterLen != 0)
    return CKR_MECHANISM_PARAM_INVALID;

  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  CK_BYTE objectId, pivSlot;
  uint32_t algorithmType;
  CNK_ENSURE_OK(CNK_ValidateObject(publicKey, session, CKO_PUBLIC_KEY, &objectId));
  CNK_ENSURE_OK(C_CNK_ObjIdToPivTag(objectId, &pivSlot));
  CNK_ENSURE_OK(cnk_get_metadata_cached(session, pivSlot, &algorithmType, NULL, NULL, NULL));
  if (algorithmType != CNK_ALGORITHM_MLKEM768)
    return CKR_KEY_TYPE_INCONSISTENT;
  CNK_PKCS11_SECRET_KEY_OBJECT prototype;
  CK_RV rv =
      CNK_BuildSharedSecretPrototype(session, attributes, attributeCount, CKM_ML_KEM, CNK_MLKEM768_SHARED_SECRET_BYTES,
                                     CNK_MLKEM768_SHARED_SECRET_BYTES, &prototype);
  if (rv != CKR_OK)
    return rv;
  if (ciphertext == NULL) {
    *ciphertextLen = CNK_MLKEM768_CIPHERTEXT_BYTES;
    *key = CK_INVALID_HANDLE;
    mbedtls_platform_zeroize(&prototype, sizeof(prototype));
    return CKR_OK;
  }
  if (*ciphertextLen < CNK_MLKEM768_CIPHERTEXT_BYTES) {
    *ciphertextLen = CNK_MLKEM768_CIPHERTEXT_BYTES;
    *key = CK_INVALID_HANDLE;
    mbedtls_platform_zeroize(&prototype, sizeof(prototype));
    return CKR_BUFFER_TOO_SMALL;
  }
  CK_BBOOL reservationHeld = CK_FALSE;
  if (prototype.private) {
    rv = cnk_token_begin_user_operation(session);
    if (rv != CKR_OK) {
      mbedtls_platform_zeroize(&prototype, sizeof(prototype));
      return rv;
    }
    reservationHeld = CK_TRUE;
  }
  CK_BYTE encodedPublicKey[CNK_MLKEM768_PUBLIC_KEY_BYTES];
  CK_ATTRIBUTE valueAttribute = {CKA_VALUE, encodedPublicKey, sizeof(encodedPublicKey)};
  rv = C_GetAttributeValue(hSession, publicKey, &valueAttribute, 1);
  if (rv != CKR_OK || valueAttribute.ulValueLen != sizeof(encodedPublicKey)) {
    if (reservationHeld)
      cnk_token_end_management_operation(session);
    mbedtls_platform_zeroize(&prototype, sizeof(prototype));
    return rv == CKR_OK ? CKR_KEY_TYPE_INCONSISTENT : rv;
  }

  CK_BYTE sharedSecret[CNK_MLKEM768_SHARED_SECRET_BYTES];
  CK_BYTE temporaryCiphertext[CNK_MLKEM768_CIPHERTEXT_BYTES] = {0};
  rv = cnk_mlkem768_encapsulate(encodedPublicKey, temporaryCiphertext, sharedSecret);
  if (rv == CKR_OK) {
    memcpy(prototype.value, sharedSecret, sizeof(sharedSecret));
    rv = CNK_CreateSessionSecretKey(session, &prototype, key);
  }
  if (rv == CKR_OK)
    memcpy(ciphertext, temporaryCiphertext, sizeof(temporaryCiphertext));
  if (reservationHeld)
    cnk_token_end_management_operation(session);
  mbedtls_platform_zeroize(temporaryCiphertext, sizeof(temporaryCiphertext));
  mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
  mbedtls_platform_zeroize(&prototype, sizeof(prototype));
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
  if (mechanism->mechanism != CKM_ML_KEM)
    return CKR_MECHANISM_INVALID;
  if (mechanism->pParameter != NULL || mechanism->ulParameterLen != 0)
    return CKR_MECHANISM_PARAM_INVALID;
  if (ciphertextLen != CNK_MLKEM768_CIPHERTEXT_BYTES)
    return CKR_ENCRYPTED_DATA_LEN_RANGE;

  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CK_BYTE objectId, pivSlot;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  CNK_ENSURE_OK(CNK_ValidateObject(privateKey, session, CKO_PRIVATE_KEY, &objectId));
  CNK_ENSURE_OK(C_CNK_ObjIdToPivTag(objectId, &pivSlot));
  uint32_t algorithmType;
  CK_BYTE pinPolicy = CNK_DefaultPinPolicyForPivObjectId(objectId);
  CNK_ENSURE_OK(cnk_get_metadata_cached(session, pivSlot, &algorithmType, NULL, &pinPolicy, NULL));
  if (algorithmType != CNK_ALGORITHM_MLKEM768)
    return CKR_KEY_TYPE_INCONSISTENT;
  // C_DecapsulateKey has no context-specific PIN parameter. Do not satisfy a
  // PIN-always policy with the token-wide USER PIN cache.
  if (pinPolicy == CNK_PIV_PIN_POLICY_ALWAYS)
    return CKR_USER_NOT_LOGGED_IN;
  CNK_PKCS11_SECRET_KEY_OBJECT prototype;
  CK_RV rv =
      CNK_BuildSharedSecretPrototype(session, attributes, attributeCount, CKM_ML_KEM, CNK_MLKEM768_SHARED_SECRET_BYTES,
                                     CNK_MLKEM768_SHARED_SECRET_BYTES, &prototype);
  if (rv != CKR_OK)
    return rv;

  CK_BYTE sharedSecret[CNK_MLKEM768_SHARED_SECRET_BYTES];
  CK_ULONG sharedSecretLen = sizeof(sharedSecret);
  CK_BBOOL operationReserved = CK_FALSE;
  // Private decapsulation must reserve USER authorization atomically with
  // the operation; otherwise logout could complete between the prototype
  // check and card reservation.
  rv = prototype.private ? cnk_token_begin_user_operation(session) : cnk_token_begin_card_operation(session);
  if (rv != CKR_OK)
    goto cleanup;
  operationReserved = CK_TRUE;
  rv = cnk_piv_mlkem_decapsulate(session->slotId, session, algorithmType, pivSlot, pinPolicy, ciphertext, ciphertextLen,
                                 sharedSecret, &sharedSecretLen);
  if (rv == CKR_OK && sharedSecretLen != sizeof(sharedSecret))
    rv = CKR_DEVICE_ERROR;
  if (rv == CKR_OK) {
    memcpy(prototype.value, sharedSecret, sizeof(sharedSecret));
    rv = CNK_CreateSessionSecretKey(session, &prototype, key);
  }
cleanup:
  if (operationReserved)
    cnk_token_end_management_operation(session);
  mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
  mbedtls_platform_zeroize(&prototype, sizeof(prototype));
  return rv;
}
