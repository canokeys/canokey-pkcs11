#include "backend/piv_operation.h"
#include "api/session.h"
#include "internal/logging.h"

#include <mbedtls/platform_util.h>

static const char *code_name(uint32_t value, const char *const *names, size_t count) {
  return value < count ? names[value] : "Unknown";
}

static void log_libcanokey_error(uint32_t status, const cnk_error_v1 *error) {
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
  if (status == CNK_OK)
    return;
  if (error == NULL || error->kind == 0) {
    CNK_DEBUG("libcanokey ABI failure: %s (%u)", code_name(status, statuses, sizeof(statuses) / sizeof(statuses[0])),
              status);
    return;
  }
  char sw[16] = "absent", retries[16] = "absent", appStatus[16] = "absent";
  if (error->presence_flags & CNK_ERROR_HAS_SW)
    snprintf(sw, sizeof(sw), "%04X", (unsigned)error->status_word);
  if (error->presence_flags & CNK_ERROR_HAS_RETRIES)
    snprintf(retries, sizeof(retries), "%u", (unsigned)error->retries_remaining);
  if (error->presence_flags & CNK_ERROR_HAS_APP_STATUS)
    snprintf(appStatus, sizeof(appStatus), "%02X", (unsigned)error->application_status);
  CNK_DEBUG("libcanokey failure: ABI=%s (%u), kind=%s (%u), phase=%s (%u), reference=%s (%u), SW=%s, retries=%s, "
            "app_status=%s",
            code_name(status, statuses, sizeof(statuses) / sizeof(statuses[0])), status,
            code_name(error->kind, kinds, sizeof(kinds) / sizeof(kinds[0])), error->kind,
            code_name(error->phase, phases, sizeof(phases) / sizeof(phases[0])), error->phase,
            code_name(error->reference, references, sizeof(references) / sizeof(references[0])), error->reference, sw,
            retries, appStatus);
}

CK_RV cnk_piv_operation_status(uint32_t status, const cnk_error_v1 *error, CK_RV absent) {
  log_libcanokey_error(status, error);
  if (status == CNK_OK)
    return CKR_OK;
  if (status == CNK_BUFFER_TOO_SMALL)
    return CKR_BUFFER_TOO_SMALL;
  if (status == CNK_INVALID_ARGUMENT)
    return CKR_ARGUMENTS_BAD;
  if (status == CNK_PROTOCOL_ERROR && error != NULL) {
    switch (error->kind) {
    case CNK_ERROR_NOT_FOUND:
      return absent;
    case CNK_ERROR_AUTHENTICATION_FAILED:
      return error->reference == 3 ? CKR_PIN_INCORRECT : CKR_USER_NOT_LOGGED_IN;
    case CNK_ERROR_SECURITY_STATUS:
      return CKR_USER_NOT_LOGGED_IN;
    case CNK_ERROR_PIN_BLOCKED:
      return CKR_PIN_LOCKED;
    case CNK_ERROR_UNSUPPORTED_FEATURE:
      return CKR_FUNCTION_NOT_SUPPORTED;
    case CNK_ERROR_LIMIT_EXCEEDED:
      return CKR_DATA_LEN_RANGE;
    default:
      break;
    }
  }
  return CKR_DEVICE_ERROR;
}

const cnk_operation_options_v1 cnk_piv_existing_options = {
    sizeof(cnk_operation_options_v1), CNK_PIV_USE_EXISTING, 261, 258, 1024 * 1024, 4096};

CK_RV cnk_piv_profile_begin(CNK_PKCS11_SESSION *session, const cnk_profile_t **profile) {
  CNK_ENSURE_NONNULL(session, session->token, profile);
  *profile = NULL;
  CNK_ENSURE_OK(cnk_mutex_lock(&session->token->lock));
  if (!session->token->libcanokeyProfile ||
      session->token->libcanokeyProfileEpoch != atomic_load(&g_cnk_managed_binding_epoch)) {
    cnk_mutex_unlock(&session->token->lock);
    return CKR_DEVICE_ERROR;
  }
  *profile = session->token->libcanokeyProfile;
  return CKR_OK;
}
CK_RV cnk_piv_profile_end(CNK_PKCS11_SESSION *session, cnk_operation_t **operation, uint32_t status,
                          const cnk_error_v1 *error) {
  CK_RV unlock = cnk_mutex_unlock(&session->token->lock);
  CK_RV rv = cnk_piv_operation_status(status, error, CKR_DEVICE_ERROR);
  if (rv == CKR_OK)
    rv = unlock;
  if (rv != CKR_OK && *operation) {
    CNK_EXTERNAL_VOID(cnk_operation_free, *operation);
    *operation = NULL;
  }
  return rv;
}

CK_RV cnk_piv_require_algorithm(CNK_PKCS11_SESSION *session, uint32_t algorithm) {
  CNK_ENSURE_NONNULL(session, session->token);
  CNK_ENSURE_OK(cnk_ensure_libcanokey_profile(session));
  CNK_ENSURE_OK(cnk_mutex_lock(&session->token->lock));
  CK_RV rv = CKR_DEVICE_ERROR;
  if (session->token->libcanokeyProfile != NULL &&
      session->token->libcanokeyProfileEpoch == atomic_load(&g_cnk_managed_binding_epoch)) {
    cnk_error_v1 error = {.struct_size = sizeof(error)};
    uint32_t status =
        CNK_EXTERNAL_CALL(cnk_profile_piv_require_algorithm, session->token->libcanokeyProfile, algorithm, &error);
    rv = cnk_piv_operation_status(status, &error, CKR_DEVICE_ERROR);
    if (status == CNK_INVALID_ARGUMENT || error.kind == CNK_ERROR_UNSUPPORTED_FEATURE ||
        error.kind == CNK_ERROR_UNSUPPORTED_ALGORITHM)
      rv = CKR_MECHANISM_INVALID;
  }
  CK_RV unlockRv = cnk_mutex_unlock(&session->token->lock);
  return rv == CKR_OK ? unlockRv : rv;
}

CK_RV cnk_run_piv_operation(SCARDHANDLE card, cnk_operation_t *operation, CK_RV absent, CK_BBOOL *attempted) {
  CK_BYTE command[2048] = {0};
  CK_BYTE response[8192] = {0};
  cnk_error_v1 error = {.struct_size = sizeof(error)};
  uint32_t step = 0;
  CK_RV rv = CKR_DEVICE_ERROR;
  size_t exchanges = 0, totalResponse = 0;
  if (attempted != NULL)
    *attempted = CK_FALSE;
  if (card == 0 || operation == NULL) {
    rv = CKR_ARGUMENTS_BAD;
    goto cleanup;
  }
  rv = cnk_piv_operation_status(CNK_EXTERNAL_CALL(cnk_operation_start, operation, &step, &error), &error, absent);
  if (rv != CKR_OK)
    goto cleanup;
  while (step == CNK_STEP_EXCHANGE) {
    if (exchanges++ == 4096) {
      rv = CKR_DATA_LEN_RANGE;
      goto cleanup;
    }
    size_t required = 0;
    rv = cnk_piv_operation_status(CNK_EXTERNAL_CALL(cnk_operation_command, operation, NULL, &required), NULL, absent);
    if (rv != CKR_OK)
      goto cleanup;
    if (required == 0 || required > sizeof(command)) {
      rv = CKR_DEVICE_ERROR;
      goto cleanup;
    }
    size_t commandLen = sizeof(command);
    rv = cnk_piv_operation_status(CNK_EXTERNAL_CALL(cnk_operation_command, operation, command, &commandLen), NULL,
                                  absent);
    if (rv != CKR_OK)
      goto cleanup;
    if (commandLen != required) {
      rv = CKR_DEVICE_ERROR;
      goto cleanup;
    }
    DWORD responseLen = sizeof(response);
    if (attempted != NULL)
      *attempted = CK_TRUE;
    LONG transport = cnk_transceive_apdu(card, command, (CK_ULONG)commandLen, response, &responseLen);
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
    rv = cnk_piv_operation_status(
        CNK_EXTERNAL_CALL(cnk_operation_advance, operation, response, responseLen, &step, &error), &error, absent);
    mbedtls_platform_zeroize(response, sizeof(response));
    if (rv != CKR_OK)
      goto cleanup;
  }
  rv = step == CNK_STEP_DONE ? CKR_OK : CKR_DEVICE_ERROR;
cleanup:
  mbedtls_platform_zeroize(command, sizeof(command));
  mbedtls_platform_zeroize(response, sizeof(response));
  return rv;
}

CK_RV cnk_piv_read_metadata_fields(CNK_PKCS11_SESSION *session, SCARDHANDLE card, CK_BYTE reference,
                                   cnk_metadata_v1 *metadata, CK_RV absent) {
  cnk_operation_t *operation = NULL;
  cnk_error_v1 error = {.struct_size = sizeof(error)};
  CK_RV rv;
  uint32_t status;
  rv = CNK_PIV_CREATE(session, cnk_piv_get_metadata_new, &operation, &error, reference, NULL);
  if (rv == CKR_OK)
    rv = cnk_run_piv_operation(card, operation, absent, NULL);
  if (rv == CKR_OK) {
    status = CNK_EXTERNAL_CALL(cnk_operation_metadata, operation, metadata);
    rv = cnk_piv_operation_status(status, NULL, absent);
  }
  if (operation)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  return rv;
}

// Copy all components before publishing the snapshot; no partial key escapes
// an ABI failure. The result getters never advance or access the card.
CK_RV cnk_copy_piv_public_key(const cnk_operation_t *operation, CNK_PIV_PUBLIC_KEY *output) {
  CNK_ENSURE_NONNULL(operation, output);
  CNK_PIV_PUBLIC_KEY key = {0};
  if (CNK_EXTERNAL_CALL(cnk_operation_key_algorithm, operation, &key.algorithm) != CNK_OK)
    return CKR_DEVICE_ERROR;
  CK_BBOOL rsa = key.algorithm >= CNK_ALGORITHM_RSA1024 && key.algorithm <= CNK_ALGORITHM_RSA4096;
  size_t length = sizeof(key.value);
  uint32_t field = rsa ? CNK_PUBLIC_MODULUS : CNK_PUBLIC_POINT_OR_RAW;
  if (CNK_EXTERNAL_CALL(cnk_operation_public_key_copy, operation, field, key.value, &length) != CNK_OK || length == 0 ||
      length > sizeof(key.value))
    return CKR_DEVICE_ERROR;
  key.valueLen = (CK_ULONG)length;
  if (rsa) {
    length = sizeof(key.exponent);
    if (CNK_EXTERNAL_CALL(cnk_operation_public_key_copy, operation, CNK_PUBLIC_EXPONENT, key.exponent, &length) !=
            CNK_OK ||
        length == 0 || length > sizeof(key.exponent))
      return CKR_DEVICE_ERROR;
    key.exponentLen = (CK_ULONG)length;
  }
  *output = key;
  return CKR_OK;
}
