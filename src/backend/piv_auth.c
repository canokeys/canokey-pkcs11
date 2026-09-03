#include "backend/pcsc.h"

#include "api/session.h"
#include "internal/crypto.h"
#include "internal/des.h"
#include "internal/logging.h"
#include "internal/util.h"

#include <mbedtls/platform_util.h>
#include <string.h>

#define PIV_PADDED_PIN_LEN 8
#define PIV_ALG_TDEA 0x03
#define PIV_ALG_AES_192 0x0A
#define PIV_MANAGEMENT_KEY_SLOT 0x9B
#define PIV_MANAGEMENT_KEY_LEN 24
#define PIV_MAX_MANAGEMENT_CHALLENGE_LEN 16

// Verify a PIN after the caller has selected PIV in the same card transaction.
// CanoKey's PIV SELECT resets PIN/admin status, so this variant must not select
// the applet again after a preceding SELECT.
static CK_RV verify_piv_pin_selected(SCARDHANDLE hCard, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_BYTE_PTR pPinTries);

// Function pointer type for card operations
typedef CK_RV (*CardOperationFunc)(SCARDHANDLE hCard, void *context);

// Utility for operations that choose their own applet. The callback owns
// applet selection; the card transaction remains held until it returns.
static CK_RV cnk_with_card(CK_SLOT_ID slotID, CardOperationFunc operation, void *context, SCARDHANDLE *out_card) {
  if (!operation)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "operation is NULL");

  SCARDHANDLE hCard;

  // Connect to card
  CK_RV rv = cnk_begin_card_transaction(slotID, &hCard);
  if (rv != CKR_OK)
    CNK_RETURN(rv, "Failed to connect to card");

  // Return the card handle if requested
  if (out_card != NULL) {
    *out_card = hCard;
    // Don't disconnect - caller is responsible
    return operation(hCard, context);
  }

  // Perform the operation
  rv = operation(hCard, context);

  // Disconnect when done
  cnk_disconnect_card(hCard);

  return rv;
}

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
    CK_RV rv = verify_piv_pin_selected(*hCard, (CK_UTF8CHAR_PTR)contextPin, contextPinLen, NULL);
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

static CK_RV validate_piv_pin_len(CK_ULONG pinLen) {
  if (pinLen < 1 || pinLen > PIV_PADDED_PIN_LEN)
    CNK_RETURN(CKR_PIN_LEN_RANGE, "Invalid PIN length");

  CNK_RET_OK;
}

static CK_RV validate_piv_secret_reference(CK_BYTE pinReference) {
  if (pinReference != CNK_PIV_PIN_TYPE_PIN && pinReference != CNK_PIV_PIN_TYPE_PUK)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "Invalid PIV PIN reference");

  CNK_RET_OK;
}

static CK_RV pad_piv_pin(CK_UTF8CHAR_PTR pin, CK_ULONG pinLen, CK_BYTE output[PIV_PADDED_PIN_LEN]) {
  CNK_ENSURE_NONNULL(pin, output);
  CNK_ENSURE_OK(validate_piv_pin_len(pinLen));

  memset(output, 0xFF, PIV_PADDED_PIN_LEN);
  memcpy(output, pin, pinLen);
  CNK_RET_OK;
}

static CK_RV handle_pin_status(CK_BYTE sw1, CK_BYTE sw2, CK_BYTE_PTR pPinTries, const char *operationName) {
  if (sw1 == 0x90 && sw2 == 0x00)
    CNK_RET_OK;

  if (sw1 == 0x63) {
    CK_BYTE attempts = sw2 & 0x0F;
    if (pPinTries != NULL)
      *pPinTries = attempts;
    CNK_RETURN(CKR_PIN_INCORRECT, operationName);
  }

  if (sw1 == 0x69 && sw2 == 0x83)
    CNK_RETURN(CKR_PIN_LOCKED, operationName);

  if (sw1 == 0x67 || (sw1 == 0x6A && sw2 == 0x80))
    CNK_RETURN(CKR_PIN_LEN_RANGE, operationName);

  CNK_RETURN(CKR_DEVICE_ERROR, operationName);
}

// PIV application functions

// Select the PIV application using AID A000000308
CK_RV cnk_select_piv_application(SCARDHANDLE hCard) {
  if (hCard == 0)
    CNK_RETURN(CKR_DEVICE_ERROR, "Card handle is invalid");

  // PIV AID: A0 00 00 03 08
  CK_BYTE select_apdu[10] = {0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08};

  // Prepare response buffer
  CK_BYTE response[258];
  DWORD response_len = sizeof(response);

  // Send the SELECT command using the transceive function
  LONG rv = cnk_transceive_apdu(hCard, select_apdu, sizeof(select_apdu), response, &response_len, CK_FALSE);

  if (rv != SCARD_S_SUCCESS) {
    CNK_RETURN(CKR_DEVICE_ERROR, "Failed to select PIV application");
  }

  // Check if the command was successful (status words 90 00)
  if (response_len < 2 || response[response_len - 2] != 0x90 || response[response_len - 1] != 0x00) {
    CNK_RETURN(CKR_DEVICE_ERROR, "Select PIV application failed");
  }

  CNK_RET_OK;
}

// Verify the PIV PIN
CK_RV cnk_verify_piv_pin(SCARDHANDLE hCard, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_BYTE_PTR pPinTries) {
  if (hCard == 0 || pPin == NULL) {
    CNK_RETURN(CKR_ARGUMENTS_BAD, "Invalid arguments");
  }

  CNK_ENSURE_OK(validate_piv_pin_len(ulPinLen));

  // First select the PIV application
  CK_RV rv = cnk_select_piv_application(hCard);
  if (rv != CKR_OK) {
    CNK_RETURN(rv, "Failed to select PIV application");
  }

  return verify_piv_pin_selected(hCard, pPin, ulPinLen, pPinTries);
}

static CK_RV verify_piv_pin_selected(SCARDHANDLE hCard, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
                                     CK_BYTE_PTR pPinTries) {
  if (hCard == 0 || pPin == NULL) {
    CNK_RETURN(CKR_ARGUMENTS_BAD, "Invalid arguments");
  }

  CNK_ENSURE_OK(validate_piv_pin_len(ulPinLen));

  // Prepare the VERIFY command: 00 20 00 80 08 [PIN padded with 0xFF]
  CK_BYTE verify_apdu[5 + PIV_PADDED_PIN_LEN] = {0x00, 0x20, 0x00, CNK_PIV_PIN_TYPE_PIN, PIV_PADDED_PIN_LEN};
  CNK_ENSURE_OK(pad_piv_pin(pPin, ulPinLen, verify_apdu + 5));

  // Prepare response buffer
  CK_BYTE response[258];
  DWORD response_len = sizeof(response);

  // Send the VERIFY command using the transceive function
  LONG pcsc_rv = cnk_transceive_apdu(hCard, verify_apdu, sizeof(verify_apdu), response, &response_len, CK_FALSE);

  if (pcsc_rv != SCARD_S_SUCCESS) {
    CNK_RETURN(CKR_DEVICE_ERROR, "Failed to verify PIV PIN");
  }

  // Check if the command was successful (status words 90 00)
  if (response_len < 2) {
    CNK_RETURN(CKR_DEVICE_ERROR, "Failed to verify PIV PIN");
  }

  const CK_BYTE sw1 = response[response_len - 2];
  const CK_BYTE sw2 = response[response_len - 1];

  CNK_ENSURE_OK(handle_pin_status(sw1, sw2, pPinTries, "PIV PIN verification failed"));
  CNK_RETURN(CKR_OK, "PIV PIN verified");
}

// Logout PIV PIN using APDU 00 20 FF 80
CK_RV cnk_logout_piv_pin(SCARDHANDLE hCard) {
  if (hCard == 0) {
    CNK_RETURN(CKR_DEVICE_ERROR, "Card handle is invalid");
  }

  // First select the PIV application
  CK_RV rv = cnk_select_piv_application(hCard);
  if (rv != CKR_OK) {
    CNK_RETURN(rv, "Failed to select PIV application");
  }

  // Prepare the LOGOUT command: 00 20 FF 80 00
  CK_BYTE logout_apdu[] = {0x00, 0x20, 0xFF, CNK_PIV_PIN_TYPE_PIN, 0x00};

  // Prepare response buffer
  CK_BYTE response[258];
  DWORD response_len = sizeof(response);

  // Send the LOGOUT command using the transceive function
  LONG pcsc_rv = cnk_transceive_apdu(hCard, logout_apdu, sizeof(logout_apdu), response, &response_len, CK_FALSE);

  if (pcsc_rv != SCARD_S_SUCCESS) {
    CNK_RETURN(CKR_DEVICE_ERROR, "Failed to logout PIV PIN");
  }

  // Check if the command was successful (status words 90 00)
  if (response_len < 2) {
    CNK_RETURN(CKR_DEVICE_ERROR, "Failed to logout PIV PIN");
  }

  // Check status words
  if (response[response_len - 2] == 0x90 && response[response_len - 1] == 0x00) {
    CNK_RETURN(CKR_OK, "PIV PIN logged out");
  }

  CNK_RETURN(CKR_DEVICE_ERROR, "Failed to logout PIV PIN");
}

static CK_RV cnk_update_piv_pin(SCARDHANDLE hCard, CK_BYTE ins, CK_BYTE pinReference, CK_UTF8CHAR_PTR pCurrentSecret,
                                CK_ULONG ulCurrentSecretLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewPinLen,
                                CK_BYTE_PTR pPinTries, const char *operationName) {
  if (hCard == 0 || pCurrentSecret == NULL || pNewPin == NULL)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "Invalid arguments");

  CNK_ENSURE_OK(validate_piv_secret_reference(pinReference));
  CNK_ENSURE_OK(validate_piv_pin_len(ulCurrentSecretLen));
  CNK_ENSURE_OK(validate_piv_pin_len(ulNewPinLen));

  CK_RV rv = cnk_select_piv_application(hCard);
  if (rv != CKR_OK)
    CNK_RETURN(rv, "Failed to select PIV application");

  CK_BYTE apdu[5 + PIV_PADDED_PIN_LEN * 2] = {0x00, ins, 0x00, pinReference, (CK_BYTE)(PIV_PADDED_PIN_LEN * 2)};
  CNK_ENSURE_OK(pad_piv_pin(pCurrentSecret, ulCurrentSecretLen, apdu + 5));
  CNK_ENSURE_OK(pad_piv_pin(pNewPin, ulNewPinLen, apdu + 5 + PIV_PADDED_PIN_LEN));

  CK_BYTE response[258];
  DWORD response_len = sizeof(response);
  LONG pcsc_rv = cnk_transceive_apdu(hCard, apdu, sizeof(apdu), response, &response_len, CK_FALSE);
  if (pcsc_rv != SCARD_S_SUCCESS)
    CNK_RETURN(CKR_DEVICE_ERROR, operationName);
  if (response_len < 2)
    CNK_RETURN(CKR_DEVICE_ERROR, operationName);

  CK_BYTE sw1 = response[response_len - 2];
  CK_BYTE sw2 = response[response_len - 1];
  CNK_ENSURE_OK(handle_pin_status(sw1, sw2, pPinTries, operationName));
  CNK_RET_OK;
}

typedef struct {
  CNK_PKCS11_SESSION *session;
  CK_BYTE pin_reference;
  CK_UTF8CHAR_PTR old_pin;
  CK_ULONG old_pin_len;
  CK_UTF8CHAR_PTR new_pin;
  CK_ULONG new_pin_len;
  CK_BYTE_PTR pin_tries;
} ChangePinContext;

static CK_RV change_pin_card_operation(SCARDHANDLE hCard, void *context) {
  ChangePinContext *ctx = (ChangePinContext *)context;
  const char *operationName =
      ctx->pin_reference == CNK_PIV_PIN_TYPE_PUK ? "PIV PUK change failed" : "PIV PIN change failed";
  CK_RV rv = cnk_update_piv_pin(hCard, 0x24, ctx->pin_reference, ctx->old_pin, ctx->old_pin_len, ctx->new_pin,
                                ctx->new_pin_len, ctx->pin_tries, operationName);
  if (rv == CKR_OK && ctx->pin_reference == CNK_PIV_PIN_TYPE_PIN)
    rv = cnk_token_update_cached_pin(ctx->session, ctx->old_pin, ctx->old_pin_len, ctx->new_pin, ctx->new_pin_len);
  return rv;
}

CK_RV cnk_change_piv_secret_with_session(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_BYTE pinReference,
                                         CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldPinLen, CK_UTF8CHAR_PTR pNewPin,
                                         CK_ULONG ulNewPinLen, CK_BYTE_PTR pPinTries) {
  if (session == NULL || pOldPin == NULL || pNewPin == NULL)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "Invalid arguments");

  CNK_ENSURE_OK(validate_piv_secret_reference(pinReference));
  CNK_ENSURE_OK(validate_piv_pin_len(ulOldPinLen));
  CNK_ENSURE_OK(validate_piv_pin_len(ulNewPinLen));

  ChangePinContext ctx = {.session = session,
                          .pin_reference = pinReference,
                          .old_pin = pOldPin,
                          .old_pin_len = ulOldPinLen,
                          .new_pin = pNewPin,
                          .new_pin_len = ulNewPinLen,
                          .pin_tries = pPinTries};
  return cnk_with_card(slotID, change_pin_card_operation, &ctx, NULL);
}

typedef struct {
  CNK_PKCS11_SESSION *session;
  CK_UTF8CHAR_PTR puk;
  CK_ULONG puk_len;
  CK_UTF8CHAR_PTR new_pin;
  CK_ULONG new_pin_len;
  CK_BYTE_PTR pin_tries;
} UnblockPinContext;

static CK_RV unblock_pin_card_operation(SCARDHANDLE hCard, void *context) {
  UnblockPinContext *ctx = (UnblockPinContext *)context;
  CK_RV rv = cnk_update_piv_pin(hCard, 0x2C, CNK_PIV_PIN_TYPE_PIN, ctx->puk, ctx->puk_len, ctx->new_pin,
                                ctx->new_pin_len, ctx->pin_tries, "PIV PIN unblock failed");
  if (rv == CKR_OK) {
    CNK_ENSURE_OK(cnk_token_cache_pin(ctx->session, ctx->new_pin, ctx->new_pin_len));
    CNK_ENSURE_OK(cnk_mutex_lock(&ctx->session->token->lock));
    ctx->session->token->loginState = TOKEN_LOGIN_USER;
    cnk_mutex_unlock(&ctx->session->token->lock);
  }
  return rv;
}

CK_RV cnk_unblock_piv_pin_with_session(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_UTF8CHAR_PTR pPuk,
                                       CK_ULONG ulPukLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewPinLen,
                                       CK_BYTE_PTR pPinTries) {
  if (session == NULL || pPuk == NULL || pNewPin == NULL)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "Invalid arguments");

  CNK_ENSURE_OK(validate_piv_pin_len(ulPukLen));
  CNK_ENSURE_OK(validate_piv_pin_len(ulNewPinLen));

  UnblockPinContext ctx = {.session = session,
                           .puk = pPuk,
                           .puk_len = ulPukLen,
                           .new_pin = pNewPin,
                           .new_pin_len = ulNewPinLen,
                           .pin_tries = pPinTries};
  return cnk_with_card(slotID, unblock_pin_card_operation, &ctx, NULL);
}

static CK_RV getManagementKeyAlgorithmOnCard(SCARDHANDLE hCard, CK_BYTE *algorithm) {
  CNK_ENSURE_NONNULL(algorithm);

  CK_BYTE metadataApdu[] = {0x00, 0xF7, 0x00, PIV_MANAGEMENT_KEY_SLOT, 0x00};
  CK_BYTE response[258];
  DWORD responseLen = sizeof(response);
  LONG pcscRv = cnk_transceive_apdu(hCard, metadataApdu, sizeof(metadataApdu), response, &responseLen, CK_TRUE);
  if (pcscRv != SCARD_S_SUCCESS || responseLen < 2)
    CNK_RETURN(CKR_DEVICE_ERROR, "Failed to read management key metadata");

  CK_BYTE sw1 = response[responseLen - 2];
  CK_BYTE sw2 = response[responseLen - 1];
  if (sw1 != 0x90 || sw2 != 0x00) {
    // Firmware predating GET METADATA used a 3DES management key.
    if ((sw1 == 0x6A && (sw2 == 0x81 || sw2 == 0x88)) || sw1 == 0x6D) {
      *algorithm = PIV_ALG_TDEA;
      CNK_RET_OK;
    }
    CNK_RETURN(CKR_DEVICE_ERROR, "Failed to read management key metadata");
  }

  CK_ULONG dataLen = responseLen - 2;
  for (CK_ULONG offset = 0; offset + 2 <= dataLen;) {
    CK_BYTE tag = response[offset++];
    CK_BYTE length = response[offset++];
    if (offset + length > dataLen)
      CNK_RETURN(CKR_DEVICE_ERROR, "Malformed management key metadata");
    if (tag == 0x01) {
      if (length != 1)
        CNK_RETURN(CKR_DEVICE_ERROR, "Malformed management key algorithm metadata");
      *algorithm = response[offset];
      if (*algorithm != PIV_ALG_TDEA && *algorithm != PIV_ALG_AES_192)
        CNK_RETURN(CKR_MECHANISM_INVALID, "Unsupported management key algorithm");
      CNK_RET_OK;
    }
    offset += length;
  }

  CNK_RETURN(CKR_DEVICE_ERROR, "Management key algorithm metadata is missing");
}

static CK_RV authenticateManagementKeyOnCard(SCARDHANDLE hCard, const CK_BYTE key[PIV_MANAGEMENT_KEY_LEN]) {
  CK_BYTE algorithm;
  CNK_ENSURE_OK(getManagementKeyAlgorithmOnCard(hCard, &algorithm));

  CK_ULONG challengeLen = algorithm == PIV_ALG_AES_192 ? 16 : 8;
  CK_BYTE capdu[9 + PIV_MAX_MANAGEMENT_CHALLENGE_LEN];
  CK_BYTE rapdu[4 + PIV_MAX_MANAGEMENT_CHALLENGE_LEN + 2];
  CK_BYTE hostCryptogram[PIV_MAX_MANAGEMENT_CHALLENGE_LEN];
  DWORD rapduLen = sizeof(rapdu);

  memcpy(capdu, (CK_BYTE[]){0x00, 0x87, algorithm, PIV_MANAGEMENT_KEY_SLOT, 0x04, 0x7C, 0x02, 0x81, 0x00}, 9);
  LONG pcscRv = cnk_transceive_apdu(hCard, capdu, 9, rapdu, &rapduLen, CK_TRUE);
  if (pcscRv != SCARD_S_SUCCESS || rapduLen != 4 + challengeLen + 2 || rapdu[0] != 0x7C ||
      rapdu[1] != 2 + challengeLen || rapdu[2] != 0x81 || rapdu[3] != challengeLen || rapdu[rapduLen - 2] != 0x90 ||
      rapdu[rapduLen - 1] != 0x00) {
    CNK_RETURN(CKR_DEVICE_ERROR, "Failed to get management key challenge");
  }

  CK_RV rv = algorithm == PIV_ALG_AES_192 ? cnk_aes192_encrypt_block(key, rapdu + 4, hostCryptogram)
                                          : cnk_des3_encrypt_block(key, rapdu + 4, hostCryptogram);
  if (rv != CKR_OK) {
    mbedtls_platform_zeroize(hostCryptogram, sizeof(hostCryptogram));
    return rv;
  }

  capdu[0] = 0x00;
  capdu[1] = 0x87;
  capdu[2] = algorithm;
  capdu[3] = PIV_MANAGEMENT_KEY_SLOT;
  capdu[4] = (CK_BYTE)(4 + challengeLen);
  capdu[5] = 0x7C;
  capdu[6] = (CK_BYTE)(2 + challengeLen);
  capdu[7] = 0x82;
  capdu[8] = (CK_BYTE)challengeLen;
  memcpy(capdu + 9, hostCryptogram, challengeLen);
  mbedtls_platform_zeroize(hostCryptogram, sizeof(hostCryptogram));

  rapduLen = sizeof(rapdu);
  pcscRv = cnk_transceive_apdu(hCard, capdu, 9 + challengeLen, rapdu, &rapduLen, CK_TRUE);
  mbedtls_platform_zeroize(capdu, sizeof(capdu));
  if (pcscRv != SCARD_S_SUCCESS || rapduLen != 2 || rapdu[0] != 0x90 || rapdu[1] != 0x00)
    CNK_RETURN(CKR_PIN_INCORRECT, "Management key authentication failed");

  CNK_RET_OK;
}

CK_RV cnk_authenticate_admin_for_write(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, SCARDHANDLE *hCard) {
  CNK_ENSURE_NONNULL(session, hCard);

  CK_BYTE managementKey[PIV_MANAGEMENT_KEY_LEN] = {0};
  CK_BBOOL connected = CK_FALSE;
  *hCard = 0;
  CK_RV rv = cnk_token_copy_management_key(session, managementKey);
  if (rv != CKR_OK) {
    rv = CKR_USER_NOT_LOGGED_IN;
    goto cleanup;
  }
  rv = cnk_begin_piv_transaction(slotID, hCard);
  if (rv != CKR_OK)
    goto cleanup;
  connected = CK_TRUE;
  rv = authenticateManagementKeyOnCard(*hCard, managementKey);

cleanup:
  mbedtls_platform_zeroize(managementKey, sizeof(managementKey));
  if (rv != CKR_OK) {
    if (connected)
      cnk_disconnect_card(*hCard);
    *hCard = 0;
    return rv;
  }

  CNK_RET_OK;
}

// Card operation function for logout
static CK_RV logout_card_operation(SCARDHANDLE hCard, void *context) {
  // Unused parameter
  (void)context;

  // Logout the PIN
  return cnk_logout_piv_pin(hCard);
}

// Logout PIV PIN with session - handles card connection
CK_RV cnk_logout_piv_pin_with_session(CK_SLOT_ID slotID) {
  // Use the card operation utility function
  return cnk_with_card(slotID, logout_card_operation, NULL, NULL);
}

// Context structure for PIN verification
typedef struct {
  CNK_PKCS11_SESSION *session;
  CK_UTF8CHAR_PTR pin;
  CK_ULONG pin_len;
  CK_BYTE_PTR pin_tries;
} VerifyPinContext;

// Card operation function for PIN verification
static CK_RV verify_pin_card_operation(SCARDHANDLE hCard, void *context) {
  VerifyPinContext *ctx = (VerifyPinContext *)context;

  CNK_ENSURE_NONNULL(ctx);
  CNK_ENSURE_NONNULL(ctx->session);

  // Verify the PIN
  CNK_ENSURE_OK(cnk_verify_piv_pin(hCard, ctx->pin, ctx->pin_len, ctx->pin_tries));

  CNK_ENSURE_OK(cnk_token_cache_pin(ctx->session, ctx->pin, ctx->pin_len));

  CNK_RET_OK;
}

// Extended version of verify PIN with option to control card disconnection
CK_RV cnk_verify_piv_pin_with_session_ex(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_UTF8CHAR_PTR pPin,
                                         CK_ULONG ulPinLen, CK_BYTE_PTR pPinTries, SCARDHANDLE *out_card) {
  if (session == NULL || (pPin == NULL && ulPinLen > 0)) {
    CNK_RETURN(CKR_ARGUMENTS_BAD, "Invalid arguments");
  }

  CNK_ENSURE_OK(validate_piv_pin_len(ulPinLen));

  // Set up the context for the operation
  VerifyPinContext ctx = {.session = session, .pin = pPin, .pin_len = ulPinLen, .pin_tries = pPinTries};

  // Use the card operation utility function
  return cnk_with_card(slotID, verify_pin_card_operation, &ctx, out_card);
}

// Verify the PIV PIN with session - handles card connection and caches PIN
CK_RV cnk_verify_piv_pin_with_session(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_UTF8CHAR_PTR pPin,
                                      CK_ULONG ulPinLen, CK_BYTE_PTR pPinTries) {
  return cnk_verify_piv_pin_with_session_ex(slotID, session, pPin, ulPinLen, pPinTries, NULL);
}

typedef struct {
  CK_UTF8CHAR_PTR pin;
  CK_ULONG pinLen;
  CK_BYTE_PTR pinTries;
} ContextPinVerification;

static CK_RV verify_context_pin_card_operation(SCARDHANDLE hCard, void *context) {
  ContextPinVerification *verification = context;
  return cnk_verify_piv_pin(hCard, verification->pin, verification->pinLen, verification->pinTries);
}

CK_RV cnk_verify_piv_pin_for_context(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
                                     CK_BYTE_PTR pPinTries) {
  ContextPinVerification verification = {.pin = pPin, .pinLen = ulPinLen, .pinTries = pPinTries};
  return cnk_with_card(slotID, verify_context_pin_card_operation, &verification, NULL);
}

/* Verify the PIV management key using the algorithm reported by slot 9B
 * metadata and send the resulting host cryptogram back to the card.
 *
 * pKey: 24-byte raw management key.
 */
CK_RV cnkVerifyManagementKey(CNK_PKCS11_SESSION *session, CK_BYTE_PTR pKey) {
  SCARDHANDLE hCard;
  CK_RV rv;

  // Select PIV before management authentication and keep the same transaction
  // through the challenge-response APDUs.
  CNK_ENSURE_OK(cnk_begin_piv_transaction(session->slotId, &hCard));

  rv = authenticateManagementKeyOnCard(hCard, pKey);
  cnk_disconnect_card(hCard);
  CNK_RETURN(rv, "");
}
