#include "backend/libcanokey.h"
#include "backend/pcsc.h"

#include "api/object.h"
#include "api/session.h"
#include "internal/logging.h"
#include "internal/util.h"

#include <mbedtls/platform_util.h>
#include <string.h>

#define CNK_PIV_MAX_PUBLIC_KEY_RESPONSE 4096
static CK_RV cnk_libcanokey_sign_status(uint32_t status) {
  switch (status) {
  case CNK_LIBCANO_OK:
    return CKR_OK;
  case CNK_LIBCANO_INVALID_ARGUMENT:
    return CKR_ARGUMENTS_BAD;
  case CNK_LIBCANO_BUFFER_TOO_SMALL:
    return CKR_BUFFER_TOO_SMALL;
  case CNK_LIBCANO_PROTOCOL_ERROR:
    return CKR_DEVICE_ERROR;
  default:
    return CKR_FUNCTION_NOT_SUPPORTED;
  }
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

static CK_RV cnk_encode_generated_public_key(const CNK_LIBCANO_OPERATION *operation, CK_BYTE algorithmType,
                                             CK_BYTE_PTR output, CK_ULONG_PTR outputLen) {
  CNK_ENSURE_NONNULL(operation, outputLen);
  CK_BBOOL rsa =
      algorithmType == PIV_ALG_RSA_2048 || algorithmType == PIV_ALG_RSA_3072 || algorithmType == PIV_ALG_RSA_4096;
  uint32_t field = rsa ? CNK_LIBCANO_PUBLIC_MODULUS : CNK_LIBCANO_PUBLIC_POINT_OR_RAW;
  size_t firstLen = 0;
  if (cnk_operation_public_key_copy(operation, field, NULL, &firstLen) != CNK_LIBCANO_OK || firstLen > 4096)
    return CKR_DEVICE_ERROR;
  CK_BYTE first[4096];
  if (cnk_operation_public_key_copy(operation, field, first, &firstLen) != CNK_LIBCANO_OK)
    return CKR_DEVICE_ERROR;
  CK_BYTE second[8] = {0};
  size_t secondLen = 0;
  if (rsa &&
      (cnk_operation_public_key_copy(operation, CNK_LIBCANO_PUBLIC_EXPONENT, NULL, &secondLen) != CNK_LIBCANO_OK ||
       secondLen > sizeof(second) ||
       cnk_operation_public_key_copy(operation, CNK_LIBCANO_PUBLIC_EXPONENT, second, &secondLen) != CNK_LIBCANO_OK))
    return CKR_DEVICE_ERROR;
  CK_ULONG required = (rsa ? 2 : 1) + (firstLen < 128 ? 1 : firstLen <= 255 ? 2 : 3) + firstLen;
  if (rsa)
    required += 2 + (secondLen < 128 ? 1 : secondLen <= 255 ? 2 : 3) + secondLen;
  CK_ULONG capacity = *outputLen;
  *outputLen = required;
  if (output == NULL)
    return CKR_OK;
  if (capacity < required)
    return CKR_BUFFER_TOO_SMALL;
  const CK_BYTE tags[2] = {rsa ? 0x81 : 0x86, 0x82};
  const CK_BYTE *values[2] = {first, second};
  const size_t lengths[2] = {firstLen, secondLen};
  CK_ULONG offset = 0;
  CK_ULONG count = rsa ? 2 : 1;
  for (CK_ULONG i = 0; i < count; i++) {
    output[offset++] = tags[i];
    if (lengths[i] < 128)
      output[offset++] = (CK_BYTE)lengths[i];
    else if (lengths[i] <= 255) {
      output[offset++] = 0x81;
      output[offset++] = (CK_BYTE)lengths[i];
    } else {
      output[offset++] = 0x82;
      output[offset++] = (CK_BYTE)(lengths[i] >> 8);
      output[offset++] = (CK_BYTE)lengths[i];
    }
    memcpy(output + offset, values[i], lengths[i]);
    offset += (CK_ULONG)lengths[i];
  }
  return CKR_OK;
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
  uint32_t step = 0;
  uint32_t status = CNK_LIBCANO_OK;
  CK_BYTE response[8192] = {0};
  uint32_t contextState =
      pinPolicy == CNK_PIV_PIN_POLICY_NEVER ? CNK_LIBCANO_CONTEXT_SELECTED : CNK_LIBCANO_CONTEXT_PIN_VERIFIED;

  rv = cnk_mutex_lock(&session->token->lock);
  if (rv != CKR_OK)
    goto cleanup;
  CNK_LIBCANO_PROFILE *profile = session->token->libcanokeyProfile;
  uint32_t contextStatus =
      profile == NULL ? CNK_LIBCANO_INVALID_STATE : cnk_piv_context_new(profile, contextState, &context, &error);
  cnk_mutex_unlock(&session->token->lock);
  if (contextStatus != CNK_LIBCANO_OK) {
    rv = CKR_DEVICE_ERROR;
    goto cleanup;
  }

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
    rv = cnk_libcanokey_sign_status(status);
    goto cleanup;
  }
  if (cnk_operation_start(operation, &step, &error) != CNK_LIBCANO_OK) {
    rv = CKR_DEVICE_ERROR;
    goto cleanup;
  }

  while (step == CNK_LIBCANO_STEP_EXCHANGE) {
    size_t commandLen = 0;
    status = cnk_operation_command(operation, NULL, &commandLen);
    if (status != CNK_LIBCANO_OK) {
      rv = cnk_libcanokey_sign_status(status);
      goto cleanup;
    }
    if (commandLen == 0 || commandLen > 2048) {
      rv = CKR_DEVICE_ERROR;
      goto cleanup;
    }
    CK_BYTE command[2048];
    status = cnk_operation_command(operation, command, &commandLen);
    if (status != CNK_LIBCANO_OK) {
      rv = cnk_libcanokey_sign_status(status);
      goto cleanup;
    }
    DWORD responseLen = sizeof(response);
    if (cnk_transceive_apdu(card, command, (CK_ULONG)commandLen, response, &responseLen, CK_FALSE) != SCARD_S_SUCCESS) {
      rv = CKR_DEVICE_ERROR;
      goto cleanup;
    }
    status = cnk_operation_advance(operation, response, responseLen, &step, &error);
    if (status != CNK_LIBCANO_OK) {
      rv = cnk_libcanokey_sign_status(status);
      goto cleanup;
    }
  }
  if (step != CNK_LIBCANO_STEP_DONE) {
    rv = CKR_DEVICE_ERROR;
    goto cleanup;
  }
  size_t required = 0;
  status = cnk_operation_result_copy_bytes(operation, NULL, &required);
  if (status != CNK_LIBCANO_OK) {
    rv = cnk_libcanokey_sign_status(status);
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
  mbedtls_platform_zeroize(response, sizeof(response));
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

  CNK_LIBCANO_PROFILE *profile = NULL;
  CNK_LIBCANO_CONTEXT *context = NULL;
  CNK_LIBCANO_OPERATION *operation = NULL;
  rv = cnk_mutex_lock(&session->token->lock);
  if (rv != CKR_OK)
    goto cleanup;
  profile = session->token->libcanokeyProfile;

  CNK_LIBCANO_ERROR error = {.struct_size = sizeof(error)};
  uint32_t contextState = session->signingContext.pinPolicy == CNK_PIV_PIN_POLICY_NEVER
                              ? CNK_LIBCANO_CONTEXT_SELECTED
                              : CNK_LIBCANO_CONTEXT_PIN_VERIFIED;
  uint32_t status = CNK_LIBCANO_OK;
  uint32_t step = 0;
  CK_BYTE response[8192] = {0};

  uint32_t contextStatus =
      profile == NULL ? CNK_LIBCANO_INVALID_STATE : cnk_piv_context_new(profile, contextState, &context, &error);
  cnk_mutex_unlock(&session->token->lock);
  if (contextStatus != CNK_LIBCANO_OK) {
    rv = CKR_DEVICE_ERROR;
    goto cleanup;
  }
  status = streaming ? cnk_piv_sign_streaming_in_context_new(context, session->signingContext.pivSlot, 1, data, dataLen,
                                                             NULL, 0, NULL, &operation, &error)
                     : cnk_piv_sign_in_context_new(context, session->signingContext.pivSlot, algorithm, kind, data,
                                                   dataLen, NULL, &operation, &error);
  if (status != CNK_LIBCANO_OK) {
    rv = cnk_libcanokey_sign_status(status);
    goto cleanup;
  }
  if (cnk_operation_start(operation, &step, &error) != CNK_LIBCANO_OK) {
    rv = CKR_DEVICE_ERROR;
    goto cleanup;
  }

  while (step == CNK_LIBCANO_STEP_EXCHANGE) {
    size_t commandLen = 0;
    status = cnk_operation_command(operation, NULL, &commandLen);
    if (status != CNK_LIBCANO_OK) {
      rv = cnk_libcanokey_sign_status(status);
      goto cleanup;
    }
    if (commandLen == 0 || commandLen > 2048) {
      rv = CKR_DEVICE_ERROR;
      goto cleanup;
    }
    CK_BYTE command[2048];
    status = cnk_operation_command(operation, command, &commandLen);
    if (status != CNK_LIBCANO_OK) {
      rv = cnk_libcanokey_sign_status(status);
      goto cleanup;
    }
    DWORD responseLen = sizeof(response);
    if (cnk_transceive_apdu(card, command, (CK_ULONG)commandLen, response, &responseLen, CK_FALSE) != SCARD_S_SUCCESS) {
      rv = CKR_DEVICE_ERROR;
      goto cleanup;
    }
    status = cnk_operation_advance(operation, response, responseLen, &step, &error);
    if (status != CNK_LIBCANO_OK) {
      rv = cnk_libcanokey_sign_status(status);
      goto cleanup;
    }
  }
  if (step != CNK_LIBCANO_STEP_DONE) {
    rv = CKR_DEVICE_ERROR;
    goto cleanup;
  }

  size_t required = 0;
  status = !streaming && kind == CNK_LIBCANO_SIGN_DIGEST ? cnk_operation_signature_p1363(operation, NULL, &required)
                                                         : cnk_operation_result_copy_bytes(operation, NULL, &required);
  if (status != CNK_LIBCANO_OK) {
    rv = cnk_libcanokey_sign_status(status);
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
  mbedtls_platform_zeroize(response, sizeof(response));
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
  SCARDHANDLE card = 0;
  CK_RV rv = cnk_begin_key_write(slotID, session, pivSlot, &card);
  if (rv != CKR_OK)
    return rv;
  rv = cnk_ensure_libcanokey_profile(session);
  if (rv != CKR_OK)
    goto cleanup;
  CNK_LIBCANO_ERROR error = {.struct_size = sizeof(error)};
  CNK_LIBCANO_KEY_PARAMETERS params = {.struct_size = sizeof(params),
                                       .slot = pivSlot,
                                       .algorithm = algorithm,
                                       .pin_policy = pinPolicy,
                                       .touch_policy = touchPolicy};
  uint32_t step = 0;
  uint32_t status = CNK_LIBCANO_OK;
  CK_BYTE response[8192] = {0};
  rv = cnk_mutex_lock(&session->token->lock);
  if (rv != CKR_OK)
    goto cleanup;
  CNK_LIBCANO_PROFILE *profile = session->token->libcanokeyProfile;
  uint32_t contextStatus =
      profile == NULL ? CNK_LIBCANO_INVALID_STATE
                      : cnk_piv_context_new(profile, CNK_LIBCANO_CONTEXT_MANAGEMENT_AUTHORIZED, &context, &error);
  cnk_mutex_unlock(&session->token->lock);
  if (contextStatus != CNK_LIBCANO_OK) {
    rv = CKR_DEVICE_ERROR;
    goto cleanup;
  }
  status = cnk_piv_generate_key_in_context_new(context, &params, NULL, &operation, &error);
  if (status != CNK_LIBCANO_OK) {
    rv = cnk_libcanokey_sign_status(status);
    goto cleanup;
  }
  if (cnk_operation_start(operation, &step, &error) != CNK_LIBCANO_OK) {
    rv = CKR_DEVICE_ERROR;
    goto cleanup;
  }
  while (step == CNK_LIBCANO_STEP_EXCHANGE) {
    size_t commandLen = 0;
    status = cnk_operation_command(operation, NULL, &commandLen);
    if (status != CNK_LIBCANO_OK) {
      rv = cnk_libcanokey_sign_status(status);
      goto cleanup;
    }
    if (commandLen == 0 || commandLen > 2048) {
      rv = CKR_DEVICE_ERROR;
      goto cleanup;
    }
    CK_BYTE command[2048];
    status = cnk_operation_command(operation, command, &commandLen);
    if (status != CNK_LIBCANO_OK) {
      rv = cnk_libcanokey_sign_status(status);
      goto cleanup;
    }
    DWORD responseLen = sizeof(response);
    if (cnk_transceive_apdu(card, command, (CK_ULONG)commandLen, response, &responseLen, CK_FALSE) != SCARD_S_SUCCESS)
      goto cleanup;
    status = cnk_operation_advance(operation, response, responseLen, &step, &error);
    if (status != CNK_LIBCANO_OK) {
      rv = cnk_libcanokey_sign_status(status);
      goto cleanup;
    }
  }
  if (step != CNK_LIBCANO_STEP_DONE) {
    rv = CKR_DEVICE_ERROR;
    goto cleanup;
  }
  rv = cnk_encode_generated_public_key(operation, algorithmType, pbPublicKey, pcbPublicKey);
  if (rv == CKR_OK)
    cnk_piv_public_cache_invalidate(session);

cleanup:
  if (operation)
    cnk_operation_free(operation);
  if (context)
    cnk_piv_context_free(context);
  cnk_disconnect_card(card);
  mbedtls_platform_zeroize(response, sizeof(response));
  return rv;
}

CK_RV cnk_piv_import_key(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_BYTE algorithmType, CK_BYTE pivSlot,
                         CK_BYTE_PTR keyData, CK_ULONG keyDataLen) {
  CNK_LIBCANO_CONTEXT *context = NULL;
  CNK_LIBCANO_OPERATION *operation = NULL;
  CNK_LOG_FUNC(": slotID: %ld, algorithmType: 0x%02X, pivSlot: 0x%02X, keyData: %p, keyDataLen: %lu", slotID,
               algorithmType, pivSlot, keyData, keyDataLen);
  CNK_ENSURE_NONNULL(keyData);

  uint32_t algorithm = 0;
  CNK_ENSURE_OK(cnk_piv_generation_algorithm(algorithmType, &algorithm));
  CNK_LIBCANO_BYTES components[5] = {0};
  size_t componentCount = 0;
  CK_BYTE pinPolicy = 0;
  CK_BYTE touchPolicy = 0;
  CK_BBOOL rsa =
      algorithmType == PIV_ALG_RSA_2048 || algorithmType == PIV_ALG_RSA_3072 || algorithmType == PIV_ALG_RSA_4096;
  CK_ULONG offset = 0;
  while (offset < keyDataLen) {
    CK_BYTE tag = keyData[offset++];
    CK_LONG fail = 0;
    CK_ULONG lengthSize = 0;
    CK_ULONG length = tlvGetLengthSafe(keyData + offset, keyDataLen - offset, &fail, &lengthSize);
    if (fail || lengthSize > keyDataLen - offset || length > keyDataLen - offset - lengthSize)
      return CKR_DATA_INVALID;
    offset += lengthSize;
    const CK_BYTE *value = keyData + offset;
    if (tag >= 1 && tag <= 5 && rsa) {
      if (componentCount >= 5)
        return CKR_DATA_INVALID;
      components[componentCount++] = (CNK_LIBCANO_BYTES){value, length};
    } else if (tag == 0x06 || tag == 0x07 || tag == 0x08 || tag == 0x09 || tag == 0x0A) {
      components[0] = (CNK_LIBCANO_BYTES){value, length};
      componentCount = 1;
    } else if (tag == 0xAA && length == 1) {
      pinPolicy = value[0];
    } else if (tag == 0xAB && length == 1) {
      touchPolicy = value[0];
    }
    offset += length;
  }
  if (componentCount != (rsa ? 5 : 1))
    return CKR_DATA_INVALID;

  SCARDHANDLE card = 0;
  CK_RV rv = cnk_begin_key_write(slotID, session, pivSlot, &card);
  if (rv != CKR_OK)
    return rv;
  rv = cnk_ensure_libcanokey_profile(session);
  if (rv != CKR_OK)
    goto import_cleanup;
  CNK_LIBCANO_ERROR error = {.struct_size = sizeof(error)};
  CNK_LIBCANO_KEY_PARAMETERS params = {.struct_size = sizeof(params),
                                       .slot = pivSlot,
                                       .algorithm = algorithm,
                                       .pin_policy = pinPolicy,
                                       .touch_policy = touchPolicy};
  uint32_t step = 0;
  uint32_t status = CNK_LIBCANO_OK;
  CK_BYTE response[8192] = {0};
  rv = cnk_mutex_lock(&session->token->lock);
  if (rv != CKR_OK)
    goto import_cleanup;
  CNK_LIBCANO_PROFILE *profile = session->token->libcanokeyProfile;
  uint32_t contextStatus =
      profile == NULL ? CNK_LIBCANO_INVALID_STATE
                      : cnk_piv_context_new(profile, CNK_LIBCANO_CONTEXT_MANAGEMENT_AUTHORIZED, &context, &error);
  cnk_mutex_unlock(&session->token->lock);
  if (contextStatus != CNK_LIBCANO_OK) {
    rv = CKR_DEVICE_ERROR;
    goto import_cleanup;
  }
  status = cnk_piv_import_key_in_context_new(context, &params, components, componentCount, NULL, &operation, &error);
  if (status != CNK_LIBCANO_OK) {
    rv = cnk_libcanokey_sign_status(status);
    goto import_cleanup;
  }
  if (cnk_operation_start(operation, &step, &error) != CNK_LIBCANO_OK) {
    rv = CKR_DEVICE_ERROR;
    goto import_cleanup;
  }
  while (step == CNK_LIBCANO_STEP_EXCHANGE) {
    size_t commandLen = 0;
    status = cnk_operation_command(operation, NULL, &commandLen);
    if (status != CNK_LIBCANO_OK || commandLen == 0 || commandLen > 2048)
      goto import_cleanup;
    CK_BYTE command[2048];
    status = cnk_operation_command(operation, command, &commandLen);
    if (status != CNK_LIBCANO_OK)
      goto import_cleanup;
    DWORD responseLen = sizeof(response);
    if (cnk_transceive_apdu(card, command, (CK_ULONG)commandLen, response, &responseLen, CK_FALSE) != SCARD_S_SUCCESS)
      goto import_cleanup;
    status = cnk_operation_advance(operation, response, responseLen, &step, &error);
    if (status != CNK_LIBCANO_OK)
      goto import_cleanup;
  }
  rv = step == CNK_LIBCANO_STEP_DONE ? CKR_OK : CKR_DEVICE_ERROR;
  if (rv == CKR_OK)
    cnk_piv_public_cache_invalidate(session);

import_cleanup:
  if (operation)
    cnk_operation_free(operation);
  if (context)
    cnk_piv_context_free(context);
  cnk_disconnect_card(card);
  mbedtls_platform_zeroize(response, sizeof(response));
  return rv;
}
