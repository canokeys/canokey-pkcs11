#include "backend/pcsc.h"
#include "backend/piv_operation.h"

#include "api/object.h"
#include "api/session.h"
#include "internal/logging.h"
#include "internal/piv_object.h"
#include "internal/util.h"

#include <mbedtls/platform_util.h>
#include <string.h>

static CK_RV cnk_libcanokey_sign_status(uint32_t status) {
  return cnk_piv_operation_status(status, NULL, CKR_KEY_HANDLE_INVALID);
}

static CK_RV cnk_libcanokey_status_with_error(uint32_t status, const cnk_error_v1 *error) {
  return cnk_piv_operation_status(status, error, CKR_KEY_HANDLE_INVALID);
}

static uint32_t signing_input_kind(uint32_t algorithm) {
  // The PKCS#11 layer prepares an encoded RSA block, an EC digest or an
  // Ed/ML-DSA message. Wire-ID resolution belongs to the libcanokey profile.
  switch (algorithm) {
  case CNK_ALGORITHM_RSA2048:
  case CNK_ALGORITHM_RSA3072:
  case CNK_ALGORITHM_RSA4096:
    return CNK_SIGN_RSA_BLOCK;
  case CNK_ALGORITHM_P256:
  case CNK_ALGORITHM_P384:
  case CNK_ALGORITHM_P521:
  case CNK_ALGORITHM_SECP256K1:
    return CNK_SIGN_DIGEST;
  case CNK_ALGORITHM_ED25519:
  case CNK_ALGORITHM_MLDSA65:
    return CNK_SIGN_MESSAGE;
  default:
    return 0;
  }
}

typedef enum {
  CNK_PRIVATE_DECRYPT,
  CNK_PRIVATE_DERIVE,
  CNK_PRIVATE_DECAPSULATE,
} CNK_PRIVATE_OPERATION;

static CK_RV cnk_piv_private_libcanokey(CK_SLOT_ID slotId, CNK_PKCS11_SESSION *session, uint32_t algorithmType,
                                        CK_BYTE pivSlot, CK_BYTE pinPolicy, CNK_PRIVATE_OPERATION operationKind,
                                        CK_BYTE_PTR input, CK_ULONG inputLen, const CK_BYTE *contextPin,
                                        CK_ULONG contextPinLen, CK_BYTE_PTR output, CK_ULONG_PTR outputLen,
                                        const char *operationName) {
  cnk_operation_t *operation = NULL;
  CNK_ENSURE_NONNULL(session, output, outputLen, input);
  uint32_t algorithm = algorithmType;
  CNK_ENSURE_OK(cnk_piv_require_algorithm(session, algorithm));

  SCARDHANDLE card = 0;
  CK_RV rv = cnk_connect_for_private_key_operation(slotId, session, pinPolicy, contextPin, contextPinLen, &card,
                                                   operationName);
  if (rv != CKR_OK)
    return rv;

  cnk_error_v1 error = {.struct_size = sizeof(error)};
  uint32_t status = CNK_OK;

  switch (operationKind) {
  case CNK_PRIVATE_DECRYPT:
    rv = CNK_PIV_CREATE(session, cnk_piv_decrypt_new, &operation, &error, pivSlot, algorithm, input, inputLen, NULL);
    break;
  case CNK_PRIVATE_DERIVE:
    rv = CNK_PIV_CREATE(session, cnk_piv_derive_new, &operation, &error, pivSlot, algorithm, input, inputLen, NULL);
    break;
  case CNK_PRIVATE_DECAPSULATE:
    rv = CNK_PIV_CREATE(session, cnk_piv_decapsulate_new, &operation, &error, pivSlot, input, inputLen, NULL);
    break;
  }
  if (rv != CKR_OK)
    goto cleanup;
  rv = cnk_run_piv_operation(card, operation, CKR_KEY_HANDLE_INVALID, NULL);
  if (rv != CKR_OK)
    goto cleanup;

  size_t required = 0;
  status = CNK_EXTERNAL_CALL(cnk_operation_result_copy_bytes, operation, NULL, &required);
  if (status != CNK_OK) {
    rv = cnk_libcanokey_status_with_error(status, &error);
    goto cleanup;
  }
  CK_ULONG capacity = *outputLen;
  *outputLen = (CK_ULONG)required;
  if (capacity < required) {
    rv = CKR_BUFFER_TOO_SMALL;
    goto cleanup;
  }
  status = CNK_EXTERNAL_CALL(cnk_operation_result_copy_bytes, operation, output, &required);
  rv = cnk_libcanokey_sign_status(status);

cleanup:
  if (operation != NULL)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  cnk_disconnect_card(card);
  return rv;
}

static CK_RV cnk_piv_sign_libcanokey(CK_SLOT_ID slotId, CNK_PKCS11_SESSION *session, CK_BYTE_PTR data, CK_ULONG dataLen,
                                     CK_BYTE_PTR signature, CK_ULONG_PTR signatureLen) {
  CNK_ENSURE_NONNULL(session, signature, signatureLen, data);
  uint32_t algorithm = session->signingContext.algorithmType;
  CNK_ENSURE_OK(cnk_piv_require_algorithm(session, algorithm));
  uint32_t kind = signing_input_kind(algorithm);
  if (kind == 0)
    return CKR_FUNCTION_NOT_SUPPORTED;
  CK_BBOOL streaming = algorithm == CNK_ALGORITHM_MLDSA65;

  SCARDHANDLE card = 0;
  CK_RV rv = cnk_connect_for_private_key_operation(slotId, session, session->signingContext.pinPolicy,
                                                   session->signingContext.contextPin,
                                                   session->signingContext.contextPinLen, &card, "sign");
  if (rv != CKR_OK)
    return rv;

  cnk_operation_t *operation = NULL;
  cnk_error_v1 error = {.struct_size = sizeof(error)};
  uint32_t status = CNK_OK;

  rv = streaming ? CNK_PIV_CREATE(session, cnk_piv_sign_streaming_new, &operation, &error,
                                  session->signingContext.pivSlot, 1, data, dataLen, NULL, 0, NULL)
                 : CNK_PIV_CREATE(session, cnk_piv_sign_new, &operation, &error, session->signingContext.pivSlot,
                                  algorithm, kind, data, dataLen, NULL);
  if (rv != CKR_OK)
    goto cleanup;
  rv = cnk_run_piv_operation(card, operation, CKR_KEY_HANDLE_INVALID, NULL);
  if (rv != CKR_OK)
    goto cleanup;

  size_t required = 0;
  status = !streaming && kind == CNK_SIGN_DIGEST
               ? CNK_EXTERNAL_CALL(cnk_operation_signature_p1363, operation, NULL, &required)
               : CNK_EXTERNAL_CALL(cnk_operation_result_copy_bytes, operation, NULL, &required);
  if (status != CNK_OK) {
    rv = cnk_libcanokey_status_with_error(status, &error);
    goto cleanup;
  }
  CK_ULONG capacity = *signatureLen;
  *signatureLen = (CK_ULONG)required;
  if (capacity < required) {
    rv = CKR_BUFFER_TOO_SMALL;
    goto cleanup;
  }
  status = !streaming && kind == CNK_SIGN_DIGEST
               ? CNK_EXTERNAL_CALL(cnk_operation_signature_p1363, operation, signature, &required)
               : CNK_EXTERNAL_CALL(cnk_operation_result_copy_bytes, operation, signature, &required);
  rv = cnk_libcanokey_sign_status(status);

cleanup:
  if (operation != NULL)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  cnk_disconnect_card(card);
  return rv;
}

CK_RV cnk_piv_decrypt(CK_SLOT_ID slotId, CNK_PKCS11_SESSION *pSession, CK_BYTE_PTR pEncryptedData,
                      CK_ULONG cbEncryptedData, CK_BYTE_PTR pRawData, CK_ULONG_PTR pcbRawData) {
  return cnk_piv_private_libcanokey(slotId, pSession, pSession->decryptingContext.algorithmType,
                                    pSession->decryptingContext.pivSlot, pSession->decryptingContext.pinPolicy,
                                    CNK_PRIVATE_DECRYPT, pEncryptedData, cbEncryptedData,
                                    pSession->decryptingContext.contextPin, pSession->decryptingContext.contextPinLen,
                                    pRawData, pcbRawData, "decrypt");
}

CK_RV cnk_piv_ecdh(CK_SLOT_ID slotId, CNK_PKCS11_SESSION *pSession, uint32_t algorithmType, CK_BYTE pivSlot,
                   CK_BYTE pinPolicy, CK_BYTE_PTR pPublicData, CK_ULONG cbPublicData, CK_BYTE_PTR pSharedSecret,
                   CK_ULONG_PTR pcbSharedSecret) {
  // C_DeriveKey has no context-specific authentication parameter. Refuse
  // PIN-always keys rather than silently reusing the token-wide USER PIN.
  if (pinPolicy == CNK_PIV_PIN_POLICY_ALWAYS)
    CNK_RETURN(CKR_USER_NOT_LOGGED_IN, "PIN-always ECDH requires context-specific authentication");
  return cnk_piv_private_libcanokey(slotId, pSession, algorithmType, pivSlot, pinPolicy, CNK_PRIVATE_DERIVE,
                                    pPublicData, cbPublicData, NULL, 0, pSharedSecret, pcbSharedSecret, "ECDH");
}

CK_RV cnk_piv_mlkem_decapsulate(CK_SLOT_ID slotId, CNK_PKCS11_SESSION *pSession, uint32_t algorithmType,
                                CK_BYTE pivSlot, CK_BYTE pinPolicy, CK_BYTE_PTR pCiphertext, CK_ULONG cbCiphertext,
                                CK_BYTE_PTR pSharedSecret, CK_ULONG_PTR pcbSharedSecret) {
  if (pinPolicy == CNK_PIV_PIN_POLICY_ALWAYS)
    CNK_RETURN(CKR_USER_NOT_LOGGED_IN, "PIN-always ML-KEM requires context-specific authentication");
  return cnk_piv_private_libcanokey(slotId, pSession, algorithmType, pivSlot, pinPolicy, CNK_PRIVATE_DECAPSULATE,
                                    pCiphertext, cbCiphertext, NULL, 0, pSharedSecret, pcbSharedSecret,
                                    "ML-KEM decapsulate");
}

// Sign data using typed libcanokey PIV operations, including streaming ML-DSA.
CK_RV cnk_piv_sign(CK_SLOT_ID slotId, CNK_PKCS11_SESSION *pSession, CK_BYTE_PTR pData, CK_ULONG cbDataLen,
                   CK_BYTE_PTR pSignature, CK_ULONG_PTR pcbSignature) {
  return cnk_piv_sign_libcanokey(slotId, pSession, pData, cbDataLen, pSignature, pcbSignature);
}

CK_RV cnk_piv_generate_keypair(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, uint32_t algorithmType, CK_BYTE pivSlot,
                               CK_BYTE pinPolicy, CK_BYTE touchPolicy) {
  cnk_operation_t *operation = NULL;
  CNK_ENSURE_NONNULL(session);
  uint32_t algorithm = algorithmType;
  CNK_ENSURE_OK(cnk_piv_require_algorithm(session, algorithm));
  CK_RV rv;
  CK_BBOOL attempted = CK_FALSE;
  SCARDHANDLE card = 0;
  rv = cnk_begin_key_write(slotID, session, pivSlot, &card);
  if (rv != CKR_OK)
    return rv;
  cnk_error_v1 error = {.struct_size = sizeof(error)};
  cnk_piv_key_parameters_v1 params = {.struct_size = sizeof(params),
                                      .slot = pivSlot,
                                      .algorithm = algorithm,
                                      .pin_policy = pinPolicy,
                                      .touch_policy = touchPolicy};

  rv = CNK_PIV_CREATE(session, cnk_piv_generate_key_new, &operation, &error, &params, NULL);
  if (rv != CKR_OK)
    goto cleanup;
  rv = cnk_run_piv_operation(card, operation, CKR_KEY_HANDLE_INVALID, &attempted);
  if (rv != CKR_OK)
    goto cleanup;

cleanup:
  if (attempted)
    cnk_piv_public_cache_invalidate(session);
  if (operation)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  cnk_disconnect_card(card);
  return rv;
}

CK_RV cnk_piv_import_key(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, const CNK_PIV_IMPORT *material) {
  cnk_operation_t *operation = NULL;
  CNK_ENSURE_NONNULL(session, material);
  CNK_ENSURE_OK(cnk_piv_require_algorithm(session, material->parameters.algorithm));
  CK_BBOOL attempted = CK_FALSE;
  SCARDHANDLE card = 0;
  CK_RV rv = cnk_begin_key_write(slotID, session, (CK_BYTE)material->parameters.slot, &card);
  if (rv != CKR_OK)
    return rv;
  cnk_error_v1 error = {.struct_size = sizeof(error)};

  rv = CNK_PIV_CREATE(session, cnk_piv_import_key_new, &operation, &error, &material->parameters, material->components,
                      material->count, NULL);
  if (rv != CKR_OK)
    goto import_cleanup;
  rv = cnk_run_piv_operation(card, operation, CKR_KEY_HANDLE_INVALID, &attempted);
  if (rv != CKR_OK)
    goto import_cleanup;

import_cleanup:
  if (attempted)
    cnk_piv_public_cache_invalidate(session);
  if (operation)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  cnk_disconnect_card(card);
  return rv;
}
