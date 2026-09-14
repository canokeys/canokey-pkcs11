#include "backend/pcsc.h"
#include "backend/piv_operation.h"

#include "api/object.h"
#include "api/session.h"
#include "internal/logging.h"
#include "internal/piv_object.h"
#include "internal/util.h"

#include <mbedtls/platform_util.h>
#include <string.h>

#define CNK_PIV_MAX_PUBLIC_KEY_RESPONSE 4096
static CK_RV cnk_libcanokey_sign_status(uint32_t status) {
  return cnk_piv_operation_status(status, NULL, CKR_KEY_HANDLE_INVALID);
}

static CK_RV cnk_libcanokey_status_with_error(uint32_t status, const CNK_LIBCANO_ERROR *error) {
  return cnk_piv_operation_status(status, error, CKR_KEY_HANDLE_INVALID);
}

static CK_RV cnk_libcanokey_sign_algorithm(CK_BYTE algorithmType, uint32_t *algorithm, uint32_t *kind) {
  CNK_ENSURE_NONNULL(algorithm, kind);
  switch (algorithmType) {
  case PIV_ALG_RSA_2048:
    *algorithm = CNK_LIBCANO_ALG_RSA_2048;
    *kind = CNK_LIBCANO_SIGN_RSA_BLOCK;
    return CKR_OK;
  case PIV_ALG_RSA_3072:
    *algorithm = CNK_LIBCANO_ALG_RSA_3072;
    *kind = CNK_LIBCANO_SIGN_RSA_BLOCK;
    return CKR_OK;
  case PIV_ALG_RSA_4096:
    *algorithm = CNK_LIBCANO_ALG_RSA_4096;
    *kind = CNK_LIBCANO_SIGN_RSA_BLOCK;
    return CKR_OK;
  case PIV_ALG_ECC_256:
    *algorithm = CNK_LIBCANO_ALG_P256;
    *kind = CNK_LIBCANO_SIGN_DIGEST;
    return CKR_OK;
  case PIV_ALG_ECC_384:
    *algorithm = CNK_LIBCANO_ALG_P384;
    *kind = CNK_LIBCANO_SIGN_DIGEST;
    return CKR_OK;
  case PIV_ALG_ECC_521:
    *algorithm = CNK_LIBCANO_ALG_P521;
    *kind = CNK_LIBCANO_SIGN_DIGEST;
    return CKR_OK;
  case PIV_ALG_SECP256K1:
    *algorithm = CNK_LIBCANO_ALG_SECP256K1;
    *kind = CNK_LIBCANO_SIGN_DIGEST;
    return CKR_OK;
  case PIV_ALG_ED25519:
    *algorithm = CNK_LIBCANO_ALG_ED25519;
    *kind = CNK_LIBCANO_SIGN_MESSAGE;
    return CKR_OK;
  case PIV_ALG_MLDSA65:
    *algorithm = CNK_LIBCANO_ALG_MLDSA65;
    *kind = CNK_LIBCANO_SIGN_MESSAGE;
    return CKR_OK;
  default:
    return CKR_FUNCTION_NOT_SUPPORTED;
  }
}

static CK_RV cnk_libcanokey_private_algorithm(CK_BYTE algorithmType, uint32_t *algorithm) {
  if (algorithmType == PIV_ALG_X25519) {
    *algorithm = CNK_LIBCANO_ALG_X25519;
    return CKR_OK;
  }
  uint32_t kind = 0;
  return cnk_libcanokey_sign_algorithm(algorithmType, algorithm, &kind);
}

typedef enum {
  CNK_PRIVATE_DECRYPT,
  CNK_PRIVATE_DERIVE,
  CNK_PRIVATE_DECAPSULATE,
} CNK_PRIVATE_OPERATION;

static CK_RV cnk_piv_private_libcanokey(CK_SLOT_ID slotId, CNK_PKCS11_SESSION *session, CK_BYTE algorithmType,
                                        CK_BYTE pivSlot, CK_BYTE pinPolicy, CNK_PRIVATE_OPERATION operationKind,
                                        CK_BYTE_PTR input, CK_ULONG inputLen, const CK_BYTE *contextPin,
                                        CK_ULONG contextPinLen, CK_BYTE_PTR output, CK_ULONG_PTR outputLen,
                                        const char *operationName) {
  CNK_LIBCANO_CONTEXT *context = NULL;
  CNK_LIBCANO_OPERATION *operation = NULL;
  CNK_ENSURE_NONNULL(session, output, outputLen, input);
  CNK_ENSURE_OK(cnk_ensure_libcanokey_profile(session));
  uint32_t algorithm = 0;
  if (operationKind != CNK_PRIVATE_DECAPSULATE)
    CNK_ENSURE_OK(cnk_libcanokey_private_algorithm(algorithmType, &algorithm));

  SCARDHANDLE card = 0;
  CK_RV rv = cnk_connect_for_private_key_operation(slotId, session, pinPolicy, contextPin, contextPinLen, &card,
                                                   operationName);
  if (rv != CKR_OK)
    return rv;

  CNK_LIBCANO_ERROR error = {.struct_size = sizeof(error)};
  uint32_t status = CNK_LIBCANO_OK;
  uint32_t contextState =
      pinPolicy == CNK_PIV_PIN_POLICY_NEVER ? CNK_LIBCANO_CONTEXT_SELECTED : CNK_LIBCANO_CONTEXT_PIN_VERIFIED;

  rv = cnk_piv_context_for_session(session, contextState, &context);
  if (rv != CKR_OK)
    goto cleanup;

  switch (operationKind) {
  case CNK_PRIVATE_DECRYPT:
    status = cnk_piv_decrypt_in_context_new(context, pivSlot, algorithm, input, inputLen, NULL, &operation, &error);
    break;
  case CNK_PRIVATE_DERIVE:
    status = cnk_piv_derive_in_context_new(context, pivSlot, algorithm, input, inputLen, NULL, &operation, &error);
    break;
  case CNK_PRIVATE_DECAPSULATE:
    status = cnk_piv_decapsulate_in_context_new(context, pivSlot, input, inputLen, NULL, &operation, &error);
    break;
  }
  if (status != CNK_LIBCANO_OK) {
    rv = cnk_libcanokey_status_with_error(status, &error);
    goto cleanup;
  }
  rv = cnk_run_piv_operation(card, operation, CKR_KEY_HANDLE_INVALID, NULL);
  if (rv != CKR_OK)
    goto cleanup;

  size_t required = 0;
  status = cnk_operation_result_copy_bytes(operation, NULL, &required);
  if (status != CNK_LIBCANO_OK) {
    rv = cnk_libcanokey_status_with_error(status, &error);
    goto cleanup;
  }
  CK_ULONG capacity = *outputLen;
  *outputLen = (CK_ULONG)required;
  if (capacity < required) {
    rv = CKR_BUFFER_TOO_SMALL;
    goto cleanup;
  }
  status = cnk_operation_result_copy_bytes(operation, output, &required);
  rv = cnk_libcanokey_sign_status(status);

cleanup:
  if (operation != NULL)
    cnk_operation_free(operation);
  if (context != NULL)
    cnk_piv_context_free(context);
  cnk_disconnect_card(card);
  return rv;
}

static CK_RV cnk_piv_sign_libcanokey(CK_SLOT_ID slotId, CNK_PKCS11_SESSION *session, CK_BYTE_PTR data, CK_ULONG dataLen,
                                     CK_BYTE_PTR signature, CK_ULONG_PTR signatureLen) {
  CNK_ENSURE_NONNULL(session, signature, signatureLen, data);
  CNK_ENSURE_OK(cnk_ensure_libcanokey_profile(session));

  uint32_t algorithm = 0, kind = 0;
  CNK_ENSURE_OK(cnk_libcanokey_sign_algorithm(session->signingContext.algorithmType, &algorithm, &kind));
  CK_BBOOL streaming = session->signingContext.algorithmType == session->mldsa65Algorithm;

  SCARDHANDLE card = 0;
  CK_RV rv = cnk_connect_for_private_key_operation(slotId, session, session->signingContext.pinPolicy,
                                                   session->signingContext.contextPin,
                                                   session->signingContext.contextPinLen, &card, "sign");
  if (rv != CKR_OK)
    return rv;

  CNK_LIBCANO_CONTEXT *context = NULL;
  CNK_LIBCANO_OPERATION *operation = NULL;
  CNK_LIBCANO_ERROR error = {.struct_size = sizeof(error)};
  uint32_t contextState = session->signingContext.pinPolicy == CNK_PIV_PIN_POLICY_NEVER
                              ? CNK_LIBCANO_CONTEXT_SELECTED
                              : CNK_LIBCANO_CONTEXT_PIN_VERIFIED;
  uint32_t status = CNK_LIBCANO_OK;

  rv = cnk_piv_context_for_session(session, contextState, &context);
  if (rv != CKR_OK)
    goto cleanup;

  status = streaming ? cnk_piv_sign_streaming_in_context_new(context, session->signingContext.pivSlot, 1, data, dataLen,
                                                             NULL, 0, NULL, &operation, &error)
                     : cnk_piv_sign_in_context_new(context, session->signingContext.pivSlot, algorithm, kind, data,
                                                   dataLen, NULL, &operation, &error);
  if (status != CNK_LIBCANO_OK) {
    rv = cnk_libcanokey_status_with_error(status, &error);
    goto cleanup;
  }
  rv = cnk_run_piv_operation(card, operation, CKR_KEY_HANDLE_INVALID, NULL);
  if (rv != CKR_OK)
    goto cleanup;

  size_t required = 0;
  status = !streaming && kind == CNK_LIBCANO_SIGN_DIGEST ? cnk_operation_signature_p1363(operation, NULL, &required)
                                                         : cnk_operation_result_copy_bytes(operation, NULL, &required);
  if (status != CNK_LIBCANO_OK) {
    rv = cnk_libcanokey_status_with_error(status, &error);
    goto cleanup;
  }
  CK_ULONG capacity = *signatureLen;
  *signatureLen = (CK_ULONG)required;
  if (capacity < required) {
    rv = CKR_BUFFER_TOO_SMALL;
    goto cleanup;
  }
  status = !streaming && kind == CNK_LIBCANO_SIGN_DIGEST
               ? cnk_operation_signature_p1363(operation, signature, &required)
               : cnk_operation_result_copy_bytes(operation, signature, &required);
  rv = cnk_libcanokey_sign_status(status);

cleanup:
  if (operation != NULL)
    cnk_operation_free(operation);
  if (context != NULL)
    cnk_piv_context_free(context);
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

CK_RV cnk_piv_ecdh(CK_SLOT_ID slotId, CNK_PKCS11_SESSION *pSession, CK_BYTE algorithmType, CK_BYTE pivSlot,
                   CK_BYTE pinPolicy, CK_BYTE_PTR pPublicData, CK_ULONG cbPublicData, CK_BYTE_PTR pSharedSecret,
                   CK_ULONG_PTR pcbSharedSecret) {
  // C_DeriveKey has no context-specific authentication parameter. Refuse
  // PIN-always keys rather than silently reusing the token-wide USER PIN.
  if (pinPolicy == CNK_PIV_PIN_POLICY_ALWAYS)
    CNK_RETURN(CKR_USER_NOT_LOGGED_IN, "PIN-always ECDH requires context-specific authentication");
  return cnk_piv_private_libcanokey(slotId, pSession, algorithmType, pivSlot, pinPolicy, CNK_PRIVATE_DERIVE,
                                    pPublicData, cbPublicData, NULL, 0, pSharedSecret, pcbSharedSecret, "ECDH");
}

CK_RV cnk_piv_mlkem_decapsulate(CK_SLOT_ID slotId, CNK_PKCS11_SESSION *pSession, CK_BYTE algorithmType, CK_BYTE pivSlot,
                                CK_BYTE pinPolicy, CK_BYTE_PTR pCiphertext, CK_ULONG cbCiphertext,
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

static CK_RV cnk_piv_generation_algorithm(CK_BYTE wire, uint32_t *algorithm) {
  switch (wire) {
  case PIV_ALG_RSA_2048:
    *algorithm = CNK_LIBCANO_ALG_RSA_2048;
    return CKR_OK;
  case PIV_ALG_RSA_3072:
    *algorithm = CNK_LIBCANO_ALG_RSA_3072;
    return CKR_OK;
  case PIV_ALG_RSA_4096:
    *algorithm = CNK_LIBCANO_ALG_RSA_4096;
    return CKR_OK;
  case PIV_ALG_ECC_256:
    *algorithm = CNK_LIBCANO_ALG_P256;
    return CKR_OK;
  case PIV_ALG_ECC_384:
    *algorithm = CNK_LIBCANO_ALG_P384;
    return CKR_OK;
  case PIV_ALG_ECC_521:
    *algorithm = CNK_LIBCANO_ALG_P521;
    return CKR_OK;
  case PIV_ALG_SECP256K1:
    *algorithm = CNK_LIBCANO_ALG_SECP256K1;
    return CKR_OK;
  case PIV_ALG_ED25519:
    *algorithm = CNK_LIBCANO_ALG_ED25519;
    return CKR_OK;
  case PIV_ALG_X25519:
    *algorithm = CNK_LIBCANO_ALG_X25519;
    return CKR_OK;
  case PIV_ALG_MLDSA65:
    *algorithm = CNK_LIBCANO_ALG_MLDSA65;
    return CKR_OK;
  case PIV_ALG_MLKEM768:
    *algorithm = CNK_LIBCANO_ALG_MLKEM768;
    return CKR_OK;
  default:
    return CKR_MECHANISM_INVALID;
  }
}

CK_RV cnk_piv_generate_keypair(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_BYTE algorithmType, CK_BYTE pivSlot,
                               CK_BYTE pinPolicy, CK_BYTE touchPolicy, CK_BYTE_PTR pbPublicKey,
                               CK_ULONG_PTR pcbPublicKey) {
  CNK_LIBCANO_CONTEXT *context = NULL;
  CNK_LIBCANO_OPERATION *operation = NULL;
  CNK_ENSURE_NONNULL(session, pbPublicKey, pcbPublicKey);
  uint32_t algorithm = 0;
  CNK_ENSURE_OK(cnk_piv_generation_algorithm(algorithmType, &algorithm));
  CK_BBOOL attempted = CK_FALSE;
  SCARDHANDLE card = 0;
  CK_RV rv = cnk_begin_key_write(slotID, session, pivSlot, &card);
  if (rv != CKR_OK)
    return rv;
  CNK_LIBCANO_ERROR error = {.struct_size = sizeof(error)};
  CNK_LIBCANO_KEY_PARAMETERS params = {.struct_size = sizeof(params),
                                       .slot = pivSlot,
                                       .algorithm = algorithm,
                                       .pin_policy = pinPolicy,
                                       .touch_policy = touchPolicy};
  uint32_t status = CNK_LIBCANO_OK;
  rv = cnk_piv_context_for_session(session, CNK_LIBCANO_CONTEXT_MANAGEMENT_AUTHORIZED, &context);
  if (rv != CKR_OK)
    goto cleanup;

  status = cnk_piv_generate_key_in_context_new(context, &params, NULL, &operation, &error);
  if (status != CNK_LIBCANO_OK) {
    rv = cnk_libcanokey_status_with_error(status, &error);
    goto cleanup;
  }
  rv = cnk_run_piv_operation(card, operation, CKR_KEY_HANDLE_INVALID, &attempted);
  if (rv != CKR_OK)
    goto cleanup;

  rv = cnk_copy_piv_public_key(operation, algorithmType, pbPublicKey, pcbPublicKey);

cleanup:
  if (attempted)
    cnk_piv_public_cache_invalidate(session);
  if (operation)
    cnk_operation_free(operation);
  if (context)
    cnk_piv_context_free(context);
  cnk_disconnect_card(card);
  return rv;
}

CK_RV cnk_piv_import_key(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, const CNK_PIV_IMPORT *material) {
  CNK_LIBCANO_CONTEXT *context = NULL;
  CNK_LIBCANO_OPERATION *operation = NULL;
  CNK_ENSURE_NONNULL(session, material);
  CK_BBOOL attempted = CK_FALSE;
  SCARDHANDLE card = 0;
  CK_RV rv = cnk_begin_key_write(slotID, session, (CK_BYTE)material->parameters.slot, &card);
  if (rv != CKR_OK)
    return rv;
  CNK_LIBCANO_ERROR error = {.struct_size = sizeof(error)};
  uint32_t status = CNK_LIBCANO_OK;
  rv = cnk_piv_context_for_session(session, CNK_LIBCANO_CONTEXT_MANAGEMENT_AUTHORIZED, &context);
  if (rv != CKR_OK)
    goto import_cleanup;

  status = cnk_piv_import_key_in_context_new(context, &material->parameters, material->components, material->count,
                                             NULL, &operation, &error);
  if (status != CNK_LIBCANO_OK) {
    rv = cnk_libcanokey_status_with_error(status, &error);
    goto import_cleanup;
  }
  rv = cnk_run_piv_operation(card, operation, CKR_KEY_HANDLE_INVALID, &attempted);
  if (rv != CKR_OK)
    goto import_cleanup;

import_cleanup:
  if (attempted)
    cnk_piv_public_cache_invalidate(session);
  if (operation)
    cnk_operation_free(operation);
  if (context)
    cnk_piv_context_free(context);
  cnk_disconnect_card(card);
  return rv;
}
