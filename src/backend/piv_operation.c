#include "backend/piv_operation.h"
#include "api/session.h"
#include "internal/logging.h"

#include <mbedtls/platform_util.h>

static const char *code_name(uint32_t value, const char *const *names, size_t count) {
  return value < count ? names[value] : "Unknown";
}

static void log_libcanokey_error(uint32_t status, const CNK_LIBCANO_ERROR *error) {
  static const char *const statuses[] = {
      "OK", "InvalidArgument", "InvalidState", "BufferTooSmall", "ResultTypeMismatch", "ProtocolError", "Panic"};
  static const char *const kinds[] = {"None",
                                      "InvalidArgument",
                                      "InvalidPin",
                                      "InvalidResponse",
                                      "ProtocolViolation",
                                      "LimitExceeded",
                                      "AuthenticationFailed",
                                      "PinBlocked",
                                      "SecurityStatusNotSatisfied",
                                      "ConditionsNotSatisfied",
                                      "NotFound",
                                      "UnsupportedDevice",
                                      "UnsupportedFeature",
                                      "UnsupportedAlgorithm",
                                      "CapabilityUnknown",
                                      "UnsupportedProtocolVersion",
                                      "UnexpectedStatusWord",
                                      "OperationStateError",
                                      "DeviceAuthenticationFailed"};
  static const char *const phases[] = {"Construction",   "Select",  "Command",
                                       "Authentication", "Parsing", "Conversation"};
  static const char *const references[] = {
      "None",       "PIN",      "PUK", "ManagementKey", "AdminPIN", "OATHAccess", "OpenPGPPW1Sign", "OpenPGPPW1Other",
      "OpenPGPPW3", "ResetCode"};
  if (status == CNK_LIBCANO_OK)
    return;
  if (error == NULL || error->kind == 0) {
    CNK_DEBUG("libcanokey ABI failure: %s (%u)", code_name(status, statuses, sizeof(statuses) / sizeof(statuses[0])),
              status);
    return;
  }
  char sw[16] = "absent", retries[16] = "absent";
  if (error->presence_flags & 1)
    snprintf(sw, sizeof(sw), "%04X", (unsigned)error->status_word);
  if (error->presence_flags & 2)
    snprintf(retries, sizeof(retries), "%u", (unsigned)error->retries_remaining);
  CNK_DEBUG("libcanokey failure: ABI=%s (%u), kind=%s (%u), phase=%s (%u), reference=%s (%u), SW=%s, retries=%s",
            code_name(status, statuses, sizeof(statuses) / sizeof(statuses[0])), status,
            code_name(error->kind, kinds, sizeof(kinds) / sizeof(kinds[0])), error->kind,
            code_name(error->phase, phases, sizeof(phases) / sizeof(phases[0])), error->phase,
            code_name(error->reference, references, sizeof(references) / sizeof(references[0])), error->reference, sw,
            retries);
}

CK_RV cnk_piv_operation_status(uint32_t status, const CNK_LIBCANO_ERROR *error, CK_RV absent) {
  log_libcanokey_error(status, error);
  if (status == CNK_LIBCANO_OK)
    return CKR_OK;
  if (status == CNK_LIBCANO_BUFFER_TOO_SMALL)
    return CKR_BUFFER_TOO_SMALL;
  if (status == CNK_LIBCANO_INVALID_ARGUMENT)
    return CKR_ARGUMENTS_BAD;
  if (status == CNK_LIBCANO_PROTOCOL_ERROR && error != NULL) {
    switch (error->kind) {
    case CNK_LIBCANO_ERROR_NOT_FOUND:
      return absent;
    case CNK_LIBCANO_ERROR_AUTHENTICATION_FAILED:
      return error->reference == 3 ? CKR_PIN_INCORRECT : CKR_USER_NOT_LOGGED_IN;
    case CNK_LIBCANO_ERROR_SECURITY_STATUS:
      return CKR_USER_NOT_LOGGED_IN;
    case CNK_LIBCANO_ERROR_PIN_BLOCKED:
      return CKR_PIN_LOCKED;
    case CNK_LIBCANO_ERROR_UNSUPPORTED_FEATURE:
      return CKR_FUNCTION_NOT_SUPPORTED;
    case CNK_LIBCANO_ERROR_LIMIT_EXCEEDED:
      return CKR_DATA_LEN_RANGE;
    default:
      break;
    }
  }
  return CKR_DEVICE_ERROR;
}

CK_RV cnk_piv_context_for_session(CNK_PKCS11_SESSION *session, uint32_t state, CNK_LIBCANO_CONTEXT **context) {
  if (context == NULL)
    return CKR_ARGUMENTS_BAD;
  *context = NULL;
  if (session == NULL || session->token == NULL)
    return CKR_ARGUMENTS_BAD;
  CK_RV rv = cnk_mutex_lock(&session->token->lock);
  if (rv != CKR_OK)
    return rv;
  CNK_LIBCANO_ERROR error = {.struct_size = sizeof(error)};
  uint32_t status = CNK_LIBCANO_INVALID_STATE;
  if (session->token->libcanokeyProfile != NULL &&
      session->token->libcanokeyProfileEpoch == atomic_load(&g_cnk_managed_binding_epoch))
    status = cnk_piv_context_new(session->token->libcanokeyProfile, state, context, &error);
  cnk_mutex_unlock(&session->token->lock);
  return cnk_piv_operation_status(status, &error, CKR_DEVICE_ERROR);
}

CK_RV cnk_run_piv_operation(SCARDHANDLE card, CNK_LIBCANO_OPERATION *operation, CK_RV absent, CK_BBOOL *attempted) {
  CK_BYTE command[2048] = {0};
  CK_BYTE response[8192] = {0};
  CNK_LIBCANO_ERROR error = {.struct_size = sizeof(error)};
  uint32_t step = 0;
  CK_RV rv = CKR_DEVICE_ERROR;
  size_t exchanges = 0, totalResponse = 0;
  if (attempted != NULL)
    *attempted = CK_FALSE;
  if (card == 0 || operation == NULL) {
    rv = CKR_ARGUMENTS_BAD;
    goto cleanup;
  }
  rv = cnk_piv_operation_status(cnk_operation_start(operation, &step, &error), &error, absent);
  if (rv != CKR_OK)
    goto cleanup;
  while (step == CNK_LIBCANO_STEP_EXCHANGE) {
    if (exchanges++ == 4096) {
      rv = CKR_DATA_LEN_RANGE;
      goto cleanup;
    }
    size_t required = 0;
    rv = cnk_piv_operation_status(cnk_operation_command(operation, NULL, &required), NULL, absent);
    if (rv != CKR_OK)
      goto cleanup;
    if (required == 0 || required > sizeof(command)) {
      rv = CKR_DEVICE_ERROR;
      goto cleanup;
    }
    size_t commandLen = sizeof(command);
    rv = cnk_piv_operation_status(cnk_operation_command(operation, command, &commandLen), NULL, absent);
    if (rv != CKR_OK)
      goto cleanup;
    if (commandLen != required) {
      rv = CKR_DEVICE_ERROR;
      goto cleanup;
    }
    DWORD responseLen = sizeof(response);
    if (attempted != NULL)
      *attempted = CK_TRUE;
    LONG transport = cnk_transceive_apdu(card, command, (CK_ULONG)commandLen, response, &responseLen, CK_FALSE);
    mbedtls_platform_zeroize(command, sizeof(command));
    if (transport != SCARD_S_SUCCESS || responseLen < 2 || responseLen > sizeof(response)) {
      CNK_DEBUG("PIV exchange failure: exchange=%zu PCSC=0x%08lx response_bytes=%lu", exchanges,
                (unsigned long)transport, (unsigned long)responseLen);
      rv = CKR_DEVICE_ERROR;
      goto cleanup;
    }
    if (responseLen > 1024 * 1024 - totalResponse) {
      rv = CKR_DATA_LEN_RANGE;
      goto cleanup;
    }
    totalResponse += responseLen;
    rv = cnk_piv_operation_status(cnk_operation_advance(operation, response, responseLen, &step, &error), &error,
                                  absent);
    mbedtls_platform_zeroize(response, sizeof(response));
    if (rv != CKR_OK)
      goto cleanup;
  }
  rv = step == CNK_LIBCANO_STEP_DONE ? CKR_OK : CKR_DEVICE_ERROR;
cleanup:
  mbedtls_platform_zeroize(command, sizeof(command));
  mbedtls_platform_zeroize(response, sizeof(response));
  return rv;
}

/* Compatibility encoding for the existing C public-key consumers. Both
 * metadata and generation must report precisely the bytes they write. */
CK_RV cnk_copy_piv_public_key(const CNK_LIBCANO_OPERATION *operation, CK_BYTE algorithmType, CK_BYTE_PTR output,
                              CK_ULONG_PTR outputLen) {
  if (operation == NULL || outputLen == NULL)
    return CKR_ARGUMENTS_BAD;
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
  CK_ULONG required = 1 + (firstLen < 128 ? 1 : firstLen <= 255 ? 2 : 3) + firstLen;
  if (rsa)
    required += 1 + (secondLen < 128 ? 1 : secondLen <= 255 ? 2 : 3) + secondLen;
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
