#include "api/session.h"
#include "backend/pcsc.h"
#include "backend/piv_operation.h"
#include "internal/logging.h"
#include "internal/util.h"
#include <mbedtls/platform_util.h>
#include <string.h>

#define PIV_PADDED_PIN_LEN 8
#define PIV_ALG_TDEA 0x03
#define PIV_ALG_AES_192 0x0A
#define PIV_MANAGEMENT_KEY_SLOT 0x9B
#define PIV_MANAGEMENT_KEY_LEN 24

static CK_RV verify_piv_pin_selected(CNK_PKCS11_SESSION *session, SCARDHANDLE card, CK_UTF8CHAR_PTR pin,
                                     CK_ULONG pinLen, CK_BYTE_PTR tries);

CK_RV cnk_connect_for_private_key_operation(CK_SLOT_ID slotId, CNK_PKCS11_SESSION *session, CK_BYTE pinPolicy,
                                            const CK_BYTE *contextPin, CK_ULONG contextPinLen, SCARDHANDLE *hCard,
                                            const char *operationName) {
  CNK_ENSURE_NONNULL(session, hCard);

  CNK_ENSURE_OK(cnk_mutex_lock(&session->token->lock));
  CK_BBOOL logoutPending = session->token->logoutPending;
  cnk_mutex_unlock(&session->token->lock);
  if (logoutPending)
    CNK_RETURN(CKR_OPERATION_ACTIVE, "Token logout is in progress");

  if (pinPolicy == CNK_PIV_PIN_POLICY_NEVER) {
    CNK_ENSURE_OK(cnk_begin_piv_transaction(slotId, hCard));
    CNK_RET_OK;
  }

  if (pinPolicy == CNK_PIV_PIN_POLICY_ALWAYS) {
    if (contextPin == NULL || contextPinLen == 0)
      CNK_RETURN(CKR_USER_NOT_LOGGED_IN, "context-specific PIN verification required");
    CNK_ENSURE_OK(cnk_begin_piv_transaction(slotId, hCard));
    CK_RV rv = verify_piv_pin_selected(session, *hCard, (CK_UTF8CHAR_PTR)contextPin, contextPinLen, NULL);
    if (rv != CKR_OK) {
      cnk_disconnect_card(*hCard);
      *hCard = 0;
    }
    return rv;
  }

  CK_BYTE pin[PIV_PADDED_PIN_LEN];
  CK_ULONG pinLen = 0;
  CK_RV rv = cnk_token_copy_pin(session, pin, &pinLen);
  if (rv != CKR_OK)
    CNK_RETURN(rv, "PIN verification required before private-key operation");
  rv = cnk_verify_piv_pin_with_session_ex(slotId, session, pin, pinLen, NULL, hCard);
  mbedtls_platform_zeroize(pin, sizeof(pin));
  if (rv != CKR_OK) {
    CNK_ERROR("Failed to verify PIN before %s", operationName ? operationName : "private-key operation");
    if (*hCard != 0)
      cnk_disconnect_card(*hCard);
    *hCard = 0;
    return rv;
  }

  CNK_RET_OK;
}

CK_RV cnk_select_piv_application(SCARDHANDLE card) {
  if (card == 0)
    return CKR_DEVICE_ERROR;
  CNK_LIBCANO_OPERATION *operation = NULL;
  CNK_LIBCANO_ERROR error = {.struct_size = sizeof(error)};
  uint32_t status = CNK_EXTERNAL_CALL(cnk_piv_select_application_new, NULL, &operation, &error);
  CK_RV rv = cnk_piv_operation_status(status, &error, CKR_DEVICE_ERROR);
  if (rv == CKR_OK)
    rv = cnk_run_piv_operation(card, operation, CKR_DEVICE_ERROR, NULL);
  if (operation)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  return rv;
}

static CK_RV validate_piv_pin_len(CK_ULONG pinLen) {
  return pinLen >= 1 && pinLen <= PIV_PADDED_PIN_LEN ? CKR_OK : CKR_PIN_LEN_RANGE;
}

// Caller owns the already selected transaction and any token reservation.
// Encoded credentials and command-specific status parsing belong to Rust.
CK_RV cnk_piv_credential_on_card(CNK_PKCS11_SESSION *session, SCARDHANDLE card, uint32_t action, const CK_BYTE *old,
                                 CK_ULONG oldLen, const CK_BYTE *replacement, CK_ULONG newLen, CK_BYTE *tries) {
  CNK_LIBCANO_CONTEXT *context = NULL;
  CNK_LIBCANO_OPERATION *operation = NULL;
  CNK_LIBCANO_ERROR error = {.struct_size = sizeof(error)};
  CK_RV rv = cnk_piv_context_for_session(session, CNK_LIBCANO_CONTEXT_SELECTED, &context);
  if (rv != CKR_OK)
    return rv;
  uint32_t status = CNK_EXTERNAL_CALL(cnk_piv_credential_in_context_new, context, action, old, oldLen, replacement,
                                      newLen, NULL, &operation, &error);
  rv = cnk_piv_operation_status(status, &error, CKR_DEVICE_ERROR);
  if (rv == CKR_OK) {
    rv = cnk_run_piv_operation(card, operation, CKR_DEVICE_ERROR, NULL);
    if (rv != CKR_OK)
      CNK_EXTERNAL_CALL(cnk_operation_error, operation, &error);
  }
  if (tries != NULL && (error.presence_flags & 2))
    *tries = error.retries_remaining;
  if (rv != CKR_OK) {
    if (action == CNK_LIBCANO_CREDENTIAL_LOGOUT)
      rv = CKR_DEVICE_ERROR;
    else if (error.kind == CNK_LIBCANO_ERROR_AUTHENTICATION_FAILED)
      rv = CKR_PIN_INCORRECT;
    else if (error.kind == CNK_LIBCANO_ERROR_INVALID_PIN ||
             ((error.presence_flags & 1) && ((error.status_word >> 8) == 0x67 || error.status_word == 0x6A80)))
      rv = CKR_PIN_LEN_RANGE;
  }
  if (operation)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  CNK_EXTERNAL_VOID(cnk_piv_context_free, context);
  CNK_DEBUG("PIV credential action=%u completed: CK_RV=0x%lx", action, rv);
  return rv;
}

static CK_RV verify_piv_pin_selected(CNK_PKCS11_SESSION *session, SCARDHANDLE card, CK_UTF8CHAR_PTR pin,
                                     CK_ULONG pinLen, CK_BYTE_PTR tries) {
  return cnk_piv_credential_on_card(session, card, CNK_LIBCANO_CREDENTIAL_VERIFY_PIN, pin, pinLen, NULL, 0, tries);
}

CK_RV cnk_verify_piv_pin_with_session_ex(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_UTF8CHAR_PTR pin,
                                         CK_ULONG pinLen, CK_BYTE_PTR tries, SCARDHANDLE *outCard) {
  CNK_ENSURE_NONNULL(session, pin);
  if (outCard)
    *outCard = 0;
  CNK_ENSURE_OK(validate_piv_pin_len(pinLen));
  CNK_ENSURE_OK(cnk_ensure_libcanokey_profile(session));
  SCARDHANDLE card = 0;
  CNK_ENSURE_OK(cnk_begin_piv_transaction(slotID, &card));
  CK_RV rv = verify_piv_pin_selected(session, card, pin, pinLen, tries);
  if (rv == CKR_OK)
    rv = cnk_token_cache_pin(session, pin, pinLen);
  if (rv == CKR_OK && outCard) {
    *outCard = card;
    return CKR_OK;
  }
  cnk_disconnect_card(card);
  return rv;
}

CK_RV cnk_verify_piv_pin_with_session(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_UTF8CHAR_PTR pin,
                                      CK_ULONG pinLen, CK_BYTE_PTR tries) {
  return cnk_verify_piv_pin_with_session_ex(slotID, session, pin, pinLen, tries, NULL);
}

CK_RV cnk_verify_piv_pin_for_context(CNK_PKCS11_SESSION *session, CK_UTF8CHAR_PTR pin, CK_ULONG pinLen,
                                     CK_BYTE_PTR tries) {
  CNK_ENSURE_NONNULL(session, pin);
  CNK_ENSURE_OK(validate_piv_pin_len(pinLen));
  CNK_ENSURE_OK(cnk_ensure_libcanokey_profile(session));
  SCARDHANDLE card = 0;
  CNK_ENSURE_OK(cnk_begin_piv_transaction(session->slotId, &card));
  CK_RV rv = verify_piv_pin_selected(session, card, pin, pinLen, tries);
  cnk_disconnect_card(card);
  return rv;
}

CK_RV cnk_logout_piv_pin_with_session(CNK_PKCS11_SESSION *session) {
  CNK_ENSURE_NONNULL(session);
  CNK_ENSURE_OK(cnk_ensure_libcanokey_profile(session));
  SCARDHANDLE card = 0;
  CNK_ENSURE_OK(cnk_begin_piv_transaction(session->slotId, &card));
  CK_RV rv = cnk_piv_credential_on_card(session, card, CNK_LIBCANO_CREDENTIAL_LOGOUT, NULL, 0, NULL, 0, NULL);
  cnk_disconnect_card(card);
  return rv;
}

CK_RV cnk_change_piv_secret_with_session(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_BYTE reference,
                                         CK_UTF8CHAR_PTR old, CK_ULONG oldLen, CK_UTF8CHAR_PTR replacement,
                                         CK_ULONG newLen, CK_BYTE_PTR tries) {
  CNK_ENSURE_NONNULL(session, old, replacement);
  if (reference != CNK_PIV_PIN_TYPE_PIN && reference != CNK_PIV_PIN_TYPE_PUK)
    return CKR_ARGUMENTS_BAD;
  CNK_ENSURE_OK(validate_piv_pin_len(oldLen));
  CNK_ENSURE_OK(validate_piv_pin_len(newLen));
  CNK_ENSURE_OK(cnk_ensure_libcanokey_profile(session));
  SCARDHANDLE card = 0;
  CNK_ENSURE_OK(cnk_begin_piv_transaction(slotID, &card));
  CK_RV rv = cnk_piv_credential_on_card(session, card,
                                        reference == CNK_PIV_PIN_TYPE_PIN ? CNK_LIBCANO_CREDENTIAL_CHANGE_PIN
                                                                          : CNK_LIBCANO_CREDENTIAL_CHANGE_PUK,
                                        old, oldLen, replacement, newLen, tries);
  if (rv == CKR_OK && reference == CNK_PIV_PIN_TYPE_PIN)
    rv = cnk_token_update_cached_pin(session, old, oldLen, replacement, newLen);
  cnk_disconnect_card(card);
  return rv;
}

CK_RV cnk_unblock_piv_pin_on_card(CNK_PKCS11_SESSION *session, SCARDHANDLE card, CK_UTF8CHAR_PTR puk, CK_ULONG pukLen,
                                  CK_UTF8CHAR_PTR pin, CK_ULONG pinLen, CK_BYTE_PTR tries) {
  CNK_ENSURE_NONNULL(session, puk, pin);
  CNK_ENSURE_OK(validate_piv_pin_len(pukLen));
  CNK_ENSURE_OK(validate_piv_pin_len(pinLen));
  CK_RV rv =
      cnk_piv_credential_on_card(session, card, CNK_LIBCANO_CREDENTIAL_UNBLOCK_PIN, puk, pukLen, pin, pinLen, tries);
  if (rv == CKR_OK)
    rv = cnk_token_cache_pin(session, pin, pinLen);
  if (rv == CKR_OK) {
    rv = cnk_mutex_lock(&session->token->lock);
    if (rv == CKR_OK) {
      session->token->loginState = TOKEN_LOGIN_USER;
      rv = cnk_mutex_unlock(&session->token->lock);
    }
  }
  return rv;
}

static CK_RV getManagementKeyAlgorithmOnCard(CNK_PKCS11_SESSION *session, SCARDHANDLE card, CK_BYTE *algorithm) {
  CNK_LIBCANO_METADATA metadata = {.struct_size = sizeof(metadata)};
  CK_RV rv =
      cnk_piv_read_metadata_fields(session, card, PIV_MANAGEMENT_KEY_SLOT, &metadata, CKR_FUNCTION_NOT_SUPPORTED);
  if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
    *algorithm = PIV_ALG_TDEA;
    return CKR_OK;
  }
  if (rv != CKR_OK)
    return rv;
  if (!(metadata.presence_flags & CNK_LIBCANO_METADATA_HAS_ALGORITHM))
    return CKR_DEVICE_ERROR;
  *algorithm = metadata.algorithm_id;
  return *algorithm == PIV_ALG_TDEA || *algorithm == PIV_ALG_AES_192 ? CKR_OK : CKR_MECHANISM_INVALID;
}

static CK_RV authenticateManagementKeyOnCard(CNK_PKCS11_SESSION *session, SCARDHANDLE card,
                                             const CK_BYTE key[PIV_MANAGEMENT_KEY_LEN]) {
  CNK_LIBCANO_CONTEXT *context = NULL;
  CNK_LIBCANO_OPERATION *operation = NULL;
  CNK_LIBCANO_ERROR error = {.struct_size = sizeof(error)};
  CK_BYTE algorithm = 0;
  CK_RV rv = getManagementKeyAlgorithmOnCard(session, card, &algorithm);
  if (rv != CKR_OK)
    return rv;
  CNK_LIBCANO_MANAGEMENT management = {
      .struct_size = sizeof(management),
      .algorithm = algorithm == PIV_ALG_AES_192 ? CNK_LIBCANO_MANAGEMENT_AES192 : CNK_LIBCANO_MANAGEMENT_TDES,
      .mode = CNK_LIBCANO_AUTH_EXTERNAL,
      .key = key,
      .key_len = PIV_MANAGEMENT_KEY_LEN,
  };
  rv = cnk_piv_context_for_session(session, CNK_LIBCANO_CONTEXT_SELECTED, &context);
  if (rv != CKR_OK)
    goto cleanup;
  uint32_t status =
      CNK_EXTERNAL_CALL(cnk_piv_authenticate_management_in_context_new, context, &management, NULL, &operation, &error);
  rv = cnk_piv_operation_status(status, &error, CKR_DEVICE_ERROR);
  if (rv != CKR_OK)
    goto cleanup;
  rv = cnk_run_piv_operation(card, operation, CKR_DEVICE_ERROR, NULL);
cleanup:
  if (operation)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  if (context)
    CNK_EXTERNAL_VOID(cnk_piv_context_free, context);
  return rv;
}

CK_RV cnk_authenticate_admin_for_write(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, SCARDHANDLE *hCard) {
  CNK_ENSURE_NONNULL(session, hCard);
  *hCard = 0;
  // Profile probing may select Admin/PIV; finish it before authorization.
  CK_RV rv = cnk_ensure_libcanokey_profile(session);
  if (rv != CKR_OK)
    return rv;
  CK_BYTE managementKey[PIV_MANAGEMENT_KEY_LEN] = {0};
  rv = cnk_token_copy_management_key(session, managementKey);
  if (rv != CKR_OK)
    goto cleanup;
  rv = cnk_begin_piv_transaction(slotID, hCard);
  if (rv != CKR_OK)
    goto cleanup;
  rv = authenticateManagementKeyOnCard(session, *hCard, managementKey);
cleanup:
  mbedtls_platform_zeroize(managementKey, sizeof(managementKey));
  if (rv != CKR_OK && *hCard != 0) {
    cnk_disconnect_card(*hCard);
    *hCard = 0;
  }
  return rv;
}

CK_RV cnkVerifyManagementKey(CNK_PKCS11_SESSION *session, CK_BYTE_PTR pKey) {
  CNK_ENSURE_NONNULL(session, pKey);
  CNK_ENSURE_OK(cnk_ensure_libcanokey_profile(session));
  SCARDHANDLE hCard;
  CK_RV rv;

  // Select PIV before management authentication and keep the same transaction
  // through the challenge-response APDUs.
  CNK_ENSURE_OK(cnk_begin_piv_transaction(session->slotId, &hCard));

  rv = authenticateManagementKeyOnCard(session, hCard, pKey);
  cnk_disconnect_card(hCard);
  CNK_RETURN(rv, "");
}
