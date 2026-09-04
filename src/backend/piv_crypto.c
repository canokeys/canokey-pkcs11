#include "backend/pcsc.h"

#include "api/object.h"
#include "api/session.h"
#include "internal/logging.h"
#include "internal/util.h"

#include <mbedtls/platform_util.h>
#include <string.h>

#define CNK_PIV_MAX_PUBLIC_KEY_RESPONSE 4096
#define CNK_PIV_MAX_GENERAL_AUTH_INPUT 65520
#define CNK_PIV_MAX_GENERAL_AUTH_RESPONSE 4096
#define PIV_PADDED_PIN_LEN 8

static void freeScopedBuffer(CK_BYTE **buffer) {
  if (buffer != NULL && *buffer != NULL) {
    ck_free(*buffer);
    *buffer = NULL;
  }
}

static void zeroize_general_auth_response(CK_BYTE **response) {
  if (response != NULL && *response != NULL)
    mbedtls_platform_zeroize(*response, CNK_PIV_MAX_GENERAL_AUTH_RESPONSE);
}

static CK_RV cnk_piv_general_authenticate_raw(CK_SLOT_ID slotId, CNK_PKCS11_SESSION *pSession, CK_BYTE algorithmType,
                                              CK_BYTE pivSlot, CK_BYTE pinPolicy, CK_BYTE inputTag, CK_BYTE_PTR pData,
                                              CK_ULONG cbDataLen, CK_BYTE_PTR pOutput, CK_ULONG_PTR pcbOutput,
                                              const CK_BYTE *contextPin, CK_ULONG contextPinLen,
                                              const char *operationName) {
  SCARDHANDLE hCard = 0;
  CK_RV rv = CKR_OK;

  CNK_ENSURE_NONNULL(pOutput, pcbOutput);

  if (cbDataLen > 0)
    CNK_ENSURE_NONNULL(pData);

  if (cbDataLen > CNK_PIV_MAX_GENERAL_AUTH_INPUT)
    CNK_RETURN(CKR_DATA_LEN_RANGE, "GENERAL AUTHENTICATE input exceeds firmware limit");

  rv = cnk_connect_for_private_key_operation(slotId, pSession, pinPolicy, contextPin, contextPinLen, &hCard,
                                             operationName);
  if (rv != CKR_OK)
    return rv;

  // Size the transient template to this request instead of consuming about
  // 64 KiB from an arbitrary host application's thread stack.
  CK_BYTE *tlv_data __attribute__((cleanup(freeScopedBuffer))) = ck_malloc(cbDataLen + 16);
  if (tlv_data == NULL) {
    cnk_disconnect_card(hCard);
    return CKR_HOST_MEMORY;
  }
  CK_ULONG tlv_len = 0;

  // Start with the outer Dynamic Authentication Template (tag 0x7C)
  tlv_data[tlv_len++] = 0x7C;
  // We'll fill in the length later once we know the total length
  CK_ULONG len_pos = tlv_len++;

  // Add the Response tag (0x82) with zero length
  tlv_data[tlv_len++] = 0x82;
  tlv_data[tlv_len++] = 0x00;

  // Add the operation input tag with the raw input data.
  tlv_data[tlv_len++] = inputTag;

  // Encode the length of the input data
  if (cbDataLen > 255) {
    // Use two-byte length encoding for lengths > 255
    tlv_data[tlv_len++] = 0x82;                               // Two-byte length marker
    tlv_data[tlv_len++] = (CK_BYTE)((cbDataLen >> 8) & 0xFF); // Length high byte
    tlv_data[tlv_len++] = (CK_BYTE)(cbDataLen & 0xFF);        // Length low byte
  } else if (cbDataLen >= 0x80) {
    tlv_data[tlv_len++] = 0x81;
    tlv_data[tlv_len++] = (CK_BYTE)cbDataLen;
  } else {
    // DER short form is valid only below 128 bytes.
    tlv_data[tlv_len++] = (CK_BYTE)cbDataLen;
  }

  // Copy the raw input data
  if (cbDataLen > 0) {
    memcpy(tlv_data + tlv_len, pData, cbDataLen);
    tlv_len += cbDataLen;
  }

  // Now fill in the length of the outer template
  // The length needs to be updated based on the total length of the contents
  CK_ULONG content_len = tlv_len - len_pos - 1;
  if (content_len > 0xFF) {
    // Need to shift everything to make room for 3-byte length
    memmove(tlv_data + len_pos + 3, tlv_data + len_pos + 1, tlv_len - len_pos - 1);

    // Store the original calculated length before modification
    // Update positions sequentially to avoid undefined behavior
    tlv_data[len_pos] = 0x82; // Two-byte length marker
    len_pos++;

    tlv_data[len_pos] = (CK_BYTE)((content_len >> 8) & 0xFF); // Length high byte
    len_pos++;

    tlv_data[len_pos] = (CK_BYTE)(content_len & 0xFF); // Length low byte

    tlv_len += 2; // Adjust total length for the extra length bytes
  } else if (content_len >= 0x80) {
    memmove(tlv_data + len_pos + 2, tlv_data + len_pos + 1, content_len);
    tlv_data[len_pos] = 0x81;
    tlv_data[len_pos + 1] = (CK_BYTE)content_len;
    tlv_len += 1;
  } else {
    tlv_data[len_pos] = (CK_BYTE)content_len;
  }

  // Build the GENERAL AUTHENTICATE APDU
  // CanoKey rejects extended GENERAL AUTHENTICATE APDUs for RSA-sized data, so
  // large templates are sent with short APDU command chaining.
  CK_BYTE abAuthApdu[262];
  CK_ULONG cbAuthApdu = 0;

  CK_BYTE response[CNK_PIV_MAX_GENERAL_AUTH_RESPONSE] = {0};
#if defined(__clang__) || defined(__GNUC__)
  CK_BYTE *responseGuard __attribute__((cleanup(zeroize_general_auth_response))) = response;
#else
#error "CanoKey GENERAL AUTH response cleanup requires compiler cleanup support"
#endif
  DWORD cbResponse = sizeof(response); // Use DWORD for PC/SC API compatibility
  LONG pcsc_rv = SCARD_S_SUCCESS;

  if (tlv_len <= 255) {
    // APDU header
    abAuthApdu[cbAuthApdu++] = 0x00;                    // CLA
    abAuthApdu[cbAuthApdu++] = 0x87;                    // INS - GENERAL AUTHENTICATE
    abAuthApdu[cbAuthApdu++] = algorithmType;           // P1 - Algorithm
    abAuthApdu[cbAuthApdu++] = pivSlot;                 // P2 - Key reference (PIV slot)
    abAuthApdu[cbAuthApdu++] = (CK_BYTE)tlv_len;        // Lc
    memcpy(abAuthApdu + cbAuthApdu, tlv_data, tlv_len); // Data
    cbAuthApdu += tlv_len;
    abAuthApdu[cbAuthApdu++] = 0x00; // Le (request max available)

    CNK_DEBUG("Sending PIV GENERAL AUTHENTICATE command for %s", operationName);
    pcsc_rv = cnk_transceive_apdu(hCard, abAuthApdu, cbAuthApdu, response, &cbResponse, CK_TRUE);
  } else {
    CK_ULONG offset = 0;
    CK_ULONG remaining = tlv_len;

    while (remaining > 0) {
      CK_ULONG chunk_len = remaining > 0xFF ? 0xFF : remaining;
      CK_BBOOL has_more_chunks = remaining > chunk_len;
      cbAuthApdu = 0;

      // Set the ISO command-chaining bit while more chunks follow.
      abAuthApdu[cbAuthApdu++] = has_more_chunks ? 0x10 : 0x00;      // CLA
      abAuthApdu[cbAuthApdu++] = 0x87;                               // INS - GENERAL AUTHENTICATE
      abAuthApdu[cbAuthApdu++] = algorithmType;                      // P1 - Algorithm
      abAuthApdu[cbAuthApdu++] = pivSlot;                            // P2 - Key reference (PIV slot)
      abAuthApdu[cbAuthApdu++] = (CK_BYTE)chunk_len;                 // Lc
      memcpy(abAuthApdu + cbAuthApdu, tlv_data + offset, chunk_len); // Data chunk
      cbAuthApdu += chunk_len;

      if (!has_more_chunks)
        abAuthApdu[cbAuthApdu++] = 0x00; // Le (request max available)

      cbResponse = sizeof(response);
      CNK_DEBUG("Sending PIV GENERAL AUTHENTICATE command chunk for %s: offset=%lu, length=%lu, more=%d", operationName,
                offset, chunk_len, has_more_chunks);
      pcsc_rv = cnk_transceive_apdu(hCard, abAuthApdu, cbAuthApdu, response, &cbResponse,
                                    has_more_chunks ? CK_FALSE : CK_TRUE);
      if (pcsc_rv != SCARD_S_SUCCESS)
        break;

      if (cbResponse < 2) {
        CNK_ERROR("GENERAL AUTHENTICATE chunk response too short");
        pcsc_rv = SCARD_E_UNEXPECTED;
        break;
      }

      if (has_more_chunks) {
        CK_BYTE sw1 = response[cbResponse - 2];
        CK_BYTE sw2 = response[cbResponse - 1];
        if (sw1 != 0x90 || sw2 != 0x00) {
          CNK_ERROR("GENERAL AUTHENTICATE chunk returned error status: %02X%02X", sw1, sw2);
          cnk_disconnect_card(hCard);
          CNK_RETURN(CKR_DEVICE_ERROR, "Failed to send GENERAL AUTHENTICATE command chunk");
        }
      }

      offset += chunk_len;
      remaining -= chunk_len;
    }
  }

  if (pcsc_rv != SCARD_S_SUCCESS) {
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "Failed to send GENERAL AUTHENTICATE command");
  }

  if (cbResponse < 2) {
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "GENERAL AUTHENTICATE response too short");
  }

  CK_BYTE sw1 = response[cbResponse - 2];
  CK_BYTE sw2 = response[cbResponse - 1];
  if (sw1 != 0x90 || sw2 != 0x00) {
    CNK_ERROR("GENERAL AUTHENTICATE returned error status: %02X%02X", sw1, sw2);
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "GENERAL AUTHENTICATE failed");
  }

  // Remove the SW from the response
  cbResponse -= 2;

  // Parse the response: 7C len1 82 len2 <raw result>
  if (cbResponse < 4) {
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "Invalid response format: too short");
  }
  if (response[0] != 0x7C) {
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "Invalid response format: missing 7C tag");
  }

  CK_ULONG offset = 1;
  CK_LONG fail = 0;
  CK_ULONG lengthSize = 0;
  CK_ULONG outerLength = tlvGetLengthSafe(response + offset, cbResponse - offset, &fail, &lengthSize);
  if (fail || offset + lengthSize + outerLength > cbResponse) {
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "Invalid response format: bad outer length");
  }
  offset += lengthSize;

  if (offset >= cbResponse || response[offset] != 0x82) {
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "Invalid response format: missing 82 tag");
  }
  offset++;

  fail = 0;
  lengthSize = 0;
  CK_ULONG outputLength = tlvGetLengthSafe(response + offset, cbResponse - offset, &fail, &lengthSize);
  if (fail || offset + lengthSize + outputLength > cbResponse) {
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "Invalid response format: bad output length");
  }
  offset += lengthSize;

  CNK_DEBUG("Raw GENERAL AUTHENTICATE output length for %s: %lu, buffer size: %lu", operationName, outputLength,
            *pcbOutput);

  if (outputLength > *pcbOutput) {
    cnk_disconnect_card(hCard);
    *pcbOutput = outputLength;
    CNK_RETURN(CKR_BUFFER_TOO_SMALL, "Output buffer too small for GENERAL AUTHENTICATE response");
  }

  memcpy(pOutput, response + offset, outputLength);
  *pcbOutput = outputLength;

  cnk_disconnect_card(hCard);
  return CKR_OK;
}

CK_RV cnk_piv_decrypt(CK_SLOT_ID slotId, CNK_PKCS11_SESSION *pSession, CK_BYTE_PTR pEncryptedData,
                      CK_ULONG cbEncryptedData, CK_BYTE_PTR pRawData, CK_ULONG_PTR pcbRawData) {
  return cnk_piv_general_authenticate_raw(
      slotId, pSession, pSession->decryptingContext.algorithmType, pSession->decryptingContext.pivSlot,
      pSession->decryptingContext.pinPolicy, 0x81, pEncryptedData, cbEncryptedData, pRawData, pcbRawData,
      pSession->decryptingContext.contextPin, pSession->decryptingContext.contextPinLen, "decrypt");
}

CK_RV cnk_piv_ecdh(CK_SLOT_ID slotId, CNK_PKCS11_SESSION *pSession, CK_BYTE algorithmType, CK_BYTE pivSlot,
                   CK_BYTE pinPolicy, CK_BYTE_PTR pPublicData, CK_ULONG cbPublicData, CK_BYTE_PTR pSharedSecret,
                   CK_ULONG_PTR pcbSharedSecret) {
  // C_DeriveKey has no context-specific authentication parameter. Refuse
  // PIN-always keys rather than silently reusing the token-wide USER PIN.
  if (pinPolicy == CNK_PIV_PIN_POLICY_ALWAYS)
    CNK_RETURN(CKR_USER_NOT_LOGGED_IN, "PIN-always ECDH requires context-specific authentication");
  return cnk_piv_general_authenticate_raw(slotId, pSession, algorithmType, pivSlot, pinPolicy, 0x85, pPublicData,
                                          cbPublicData, pSharedSecret, pcbSharedSecret, NULL, 0, "ECDH");
}

CK_RV cnk_piv_mlkem_decapsulate(CK_SLOT_ID slotId, CNK_PKCS11_SESSION *pSession, CK_BYTE algorithmType, CK_BYTE pivSlot,
                                CK_BYTE pinPolicy, CK_BYTE_PTR pCiphertext, CK_ULONG cbCiphertext,
                                CK_BYTE_PTR pSharedSecret, CK_ULONG_PTR pcbSharedSecret) {
  CK_BYTE pin[PIV_PADDED_PIN_LEN] = {0};
  CK_ULONG pinLen = 0;
  if (pinPolicy == CNK_PIV_PIN_POLICY_ALWAYS) {
    CK_RV rv = cnk_token_copy_pin(pSession, pin, &pinLen);
    if (rv != CKR_OK)
      return rv;
  }
  CK_RV rv = cnk_piv_general_authenticate_raw(slotId, pSession, algorithmType, pivSlot, pinPolicy, 0x81, pCiphertext,
                                              cbCiphertext, pSharedSecret, pcbSharedSecret, pinLen == 0 ? NULL : pin,
                                              pinLen, "ML-KEM decapsulate");
  mbedtls_platform_zeroize(pin, sizeof(pin));
  return rv;
}

// Sign data using PIV key
// This function signs raw data using the PIV GENERAL AUTHENTICATE command
CK_RV cnk_piv_sign(CK_SLOT_ID slotId, CNK_PKCS11_SESSION *pSession, CK_BYTE_PTR pData, CK_ULONG cbDataLen,
                   CK_BYTE_PTR pSignature, CK_ULONG_PTR pcbSignature) {
  if (pSession->signingContext.algorithmType == pSession->mldsa65Algorithm)
    return cnk_piv_general_authenticate_raw(
        slotId, pSession, pSession->signingContext.algorithmType, pSession->signingContext.pivSlot,
        pSession->signingContext.pinPolicy, 0x81, pData, cbDataLen, pSignature, pcbSignature,
        pSession->signingContext.contextPin, pSession->signingContext.contextPinLen, "ML-DSA sign");

  SCARDHANDLE hCard;

  // Check if we're just getting the signature length
  if (pSignature == NULL_PTR)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "pSignature is NULL");

  // Check if input data is too large (max 512 bytes for RSA 4096)
  if (cbDataLen > 512)
    CNK_RETURN(CKR_DATA_LEN_RANGE, "Input data too large (max 512 bytes)");

  CK_RV rv = cnk_connect_for_private_key_operation(slotId, pSession, pSession->signingContext.pinPolicy,
                                                   pSession->signingContext.contextPin,
                                                   pSession->signingContext.contextPinLen, &hCard, "sign");
  if (rv != CKR_OK)
    return rv;

  // Now construct the PIV TLV structure for GENERAL AUTHENTICATE
  // Buffer for TLV data structure (tag + length + value)
  CK_BYTE tlv_data[1024]; // Increased buffer size for larger input data
  CK_ULONG tlv_len = 0;

  // Start with the outer Dynamic Authentication Template (tag 0x7C)
  tlv_data[tlv_len++] = 0x7C;
  // We'll fill in the length later once we know the total length
  CK_ULONG len_pos = tlv_len++;

  // Add the Response tag (0x82) with zero length
  tlv_data[tlv_len++] = 0x82;
  tlv_data[tlv_len++] = 0x00;

  // Add the Challenge tag (0x81) with the raw input data
  tlv_data[tlv_len++] = 0x81;

  // Encode the length of the input data
  if (cbDataLen > 255) {
    // Use two-byte length encoding for lengths > 255
    tlv_data[tlv_len++] = 0x82;                               // Two-byte length marker
    tlv_data[tlv_len++] = (CK_BYTE)((cbDataLen >> 8) & 0xFF); // Length high byte
    tlv_data[tlv_len++] = (CK_BYTE)(cbDataLen & 0xFF);        // Length low byte
  } else if (cbDataLen >= 0x80) {
    tlv_data[tlv_len++] = 0x81;
    tlv_data[tlv_len++] = (CK_BYTE)cbDataLen;
  } else {
    // DER short form is valid only below 128 bytes.
    tlv_data[tlv_len++] = (CK_BYTE)cbDataLen;
  }

  // Copy the raw input data
  memcpy(tlv_data + tlv_len, pData, cbDataLen);
  tlv_len += cbDataLen;

  // Now fill in the length of the outer template
  // The length needs to be updated based on the total length of the contents
  CK_ULONG content_len = tlv_len - len_pos - 1;
  if (content_len > 0xFF) {
    // Need to shift everything to make room for 3-byte length
    memmove(tlv_data + len_pos + 3, tlv_data + len_pos + 1, tlv_len - len_pos - 1);

    // Store the original calculated length before modification
    // Update positions sequentially to avoid undefined behavior
    tlv_data[len_pos] = 0x82; // Two-byte length marker
    len_pos++;

    tlv_data[len_pos] = (CK_BYTE)((content_len >> 8) & 0xFF); // Length high byte
    len_pos++;

    tlv_data[len_pos] = (CK_BYTE)(content_len & 0xFF); // Length low byte

    tlv_len += 2; // Adjust total length for the extra length bytes
  } else if (content_len >= 0x80) {
    memmove(tlv_data + len_pos + 2, tlv_data + len_pos + 1, content_len);
    tlv_data[len_pos] = 0x81;
    tlv_data[len_pos + 1] = (CK_BYTE)content_len;
    tlv_len += 1;
  } else {
    tlv_data[len_pos] = (CK_BYTE)content_len;
  }

  // Build the GENERAL AUTHENTICATE APDU
  // CanoKey rejects extended GENERAL AUTHENTICATE APDUs for RSA-sized data, so
  // large templates are sent with short APDU command chaining.
  CK_BYTE abAuthApdu[1100];
  CK_ULONG cbAuthApdu = 0;

  CK_BYTE response[1024];              // Increased buffer size for larger responses
  DWORD cbResponse = sizeof(response); // Use DWORD for PC/SC API compatibility
  LONG pcsc_rv = SCARD_S_SUCCESS;

  if (tlv_len <= 255) {
    // APDU header
    abAuthApdu[cbAuthApdu++] = 0x00;                                   // CLA
    abAuthApdu[cbAuthApdu++] = 0x87;                                   // INS - GENERAL AUTHENTICATE
    abAuthApdu[cbAuthApdu++] = pSession->signingContext.algorithmType; // P1 - Algorithm
    abAuthApdu[cbAuthApdu++] = pSession->signingContext.pivSlot;       // P2 - Key reference (PIV slot)
    abAuthApdu[cbAuthApdu++] = (CK_BYTE)tlv_len;                       // Lc
    memcpy(abAuthApdu + cbAuthApdu, tlv_data, tlv_len);                // Data
    cbAuthApdu += tlv_len;
    abAuthApdu[cbAuthApdu++] = 0x00; // Le (request max available)

    CNK_DEBUG("Sending PIV GENERAL AUTHENTICATE command for signing");
    pcsc_rv = cnk_transceive_apdu(hCard, abAuthApdu, cbAuthApdu, response, &cbResponse, CK_TRUE);
  } else {
    CK_ULONG offset = 0;
    CK_ULONG remaining = tlv_len;

    while (remaining > 0) {
      CK_ULONG chunk_len = remaining > 0xFF ? 0xFF : remaining;
      CK_BBOOL has_more_chunks = remaining > chunk_len;
      cbAuthApdu = 0;

      // Set the ISO command-chaining bit while more chunks follow.
      abAuthApdu[cbAuthApdu++] = has_more_chunks ? 0x10 : 0x00;          // CLA
      abAuthApdu[cbAuthApdu++] = 0x87;                                   // INS - GENERAL AUTHENTICATE
      abAuthApdu[cbAuthApdu++] = pSession->signingContext.algorithmType; // P1 - Algorithm
      abAuthApdu[cbAuthApdu++] = pSession->signingContext.pivSlot;       // P2 - Key reference (PIV slot)
      abAuthApdu[cbAuthApdu++] = (CK_BYTE)chunk_len;                     // Lc
      memcpy(abAuthApdu + cbAuthApdu, tlv_data + offset, chunk_len);     // Data chunk
      cbAuthApdu += chunk_len;

      if (!has_more_chunks)
        abAuthApdu[cbAuthApdu++] = 0x00; // Le (request max available)

      cbResponse = sizeof(response);
      CNK_DEBUG("Sending PIV GENERAL AUTHENTICATE command chunk: offset=%lu, length=%lu, more=%d", offset, chunk_len,
                has_more_chunks);
      pcsc_rv = cnk_transceive_apdu(hCard, abAuthApdu, cbAuthApdu, response, &cbResponse,
                                    has_more_chunks ? CK_FALSE : CK_TRUE);
      if (pcsc_rv != SCARD_S_SUCCESS)
        break;

      if (cbResponse < 2) {
        CNK_ERROR("GENERAL AUTHENTICATE chunk response too short");
        pcsc_rv = SCARD_E_UNEXPECTED;
        break;
      }

      if (has_more_chunks) {
        CK_BYTE sw1 = response[cbResponse - 2];
        CK_BYTE sw2 = response[cbResponse - 1];
        if (sw1 != 0x90 || sw2 != 0x00) {
          CNK_ERROR("GENERAL AUTHENTICATE chunk returned error status: %02X%02X", sw1, sw2);
          cnk_disconnect_card(hCard);
          CNK_RETURN(CKR_DEVICE_ERROR, "Failed to send GENERAL AUTHENTICATE command chunk");
        }
      }

      offset += chunk_len;
      remaining -= chunk_len;
    }
  }

  if (pcsc_rv != SCARD_S_SUCCESS) {
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "Failed to send GENERAL AUTHENTICATE command");
  }

  // Check for success (9000) or more data available (61XX)
  if (cbResponse < 2) {
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "GENERAL AUTHENTICATE response is missing status bytes");
  }
  CK_BYTE sw1 = response[cbResponse - 2];
  CK_BYTE sw2 = response[cbResponse - 1];
  if (sw1 != 0x90 || sw2 != 0x00) {
    CNK_ERROR("GENERAL AUTHENTICATE returned error status: %02X%02X", sw1, sw2);
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "Failed to sign");
  }

  // Remove the SW from the response
  cbResponse -= 2;

  // Parse the response
  // The signature is returned in the format: 7C len1 82 len2 <signature>

  // Check if we have enough data
  if (cbResponse < 4) { // At least 7C len 82 len
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "Invalid response format: too short");
  }

  // Verify the response format
  if (response[0] != 0x7C) {
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "Invalid response format: missing 7C tag");
  }

  // Decode the outer 7C length, including the 0x81 form used when a P-521
  // DER signature makes the template larger than 127 bytes.
  CK_ULONG offset = 1;
  CK_LONG outerFail = 0;
  CK_ULONG outerLengthSize = 0;
  CK_ULONG outerLength = tlvGetLengthSafe(response + offset, cbResponse - offset, &outerFail, &outerLengthSize);
  if (outerFail || outerLengthSize > cbResponse - offset || outerLength > cbResponse - offset - outerLengthSize) {
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "Invalid response format: bad outer length");
  }
  offset += outerLengthSize;
  CK_ULONG outerEnd = offset + outerLength;

  // Check for the inner 82 tag (signature response)
  if (offset >= outerEnd || response[offset] != 0x82) {
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "Invalid response format: missing 82 tag");
  }

  if (offset >= outerEnd) {
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "Invalid response format: empty 7C template");
  }

  // Skip the inner TLV header
  offset++; // Skip the 82 tag
  if (offset >= outerEnd) {
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "Invalid response format: missing signature length");
  }

  // Handle the length field
  CK_ULONG signatureLength = 0;
  if (offset < outerEnd) {
    CK_LONG fail = 0;
    CK_ULONG bcLength = 0;
    signatureLength = tlvGetLengthSafe(&response[offset], outerEnd - offset, &fail, &bcLength);
    if (!fail && bcLength <= outerEnd - offset && signatureLength <= outerEnd - offset - bcLength) {
      offset += bcLength; // Skip length bytes
    } else {
      cnk_disconnect_card(hCard);
      *pcbSignature = 0;
      CNK_RETURN(CKR_DEVICE_ERROR, "Invalid response format: failed to parse length field");
    }
  }

  // Extract ECDSA signature components if needed
  size_t sig_len = signatureLength;
  CNK_DEBUG("Raw signature length: %zu, buffer size: %zu", sig_len, *pcbSignature);

  // Check if this is an ECDSA signature
  CK_BYTE algorithmType = pSession->signingContext.algorithmType;
  if (algorithmType == PIV_ALG_ECC_256 || algorithmType == PIV_ALG_ECC_384 ||
      algorithmType == CNK_PivConfiguredAlgorithm(pSession, PIV_ALG_ECC_521) ||
      algorithmType == CNK_PivConfiguredAlgorithm(pSession, PIV_ALG_SECP256K1)) {
    // ECDSA signature is in DER format, convert to raw r||s format
    CNK_DEBUG("Converting ECDSA signature from DER to raw format");

    CK_ULONG ec_size = algorithmType == CNK_PivConfiguredAlgorithm(pSession, PIV_ALG_ECC_521)
                           ? 66
                           : (algorithmType == PIV_ALG_ECC_384 ? 48 : 32);
    CK_ULONG expected_sig_size = ec_size * 2; // r || s

    // Check buffer size for raw signature
    if (expected_sig_size > *pcbSignature) {
      cnk_disconnect_card(hCard);
      *pcbSignature = expected_sig_size;
      CNK_RETURN(CKR_BUFFER_TOO_SMALL, "Signature buffer too small for raw ECDSA signature");
    }

    // Temp buffer for the raw signature
    CK_BYTE raw_sig[132] = {0};

    // Parse DER encoded signature
    const CK_BYTE *der_sig = response + offset;
    size_t der_len = sig_len;

    // Expecting SEQUENCE { r INTEGER, s INTEGER }
    if (der_len < 2 || der_sig[0] != 0x30) { // 0x30 is the SEQUENCE tag in DER
      cnk_disconnect_card(hCard);
      CNK_RETURN(CKR_DEVICE_ERROR, "Invalid ECDSA signature: not a valid SEQUENCE");
    }

    // Skip SEQUENCE tag
    size_t der_pos = 1;

    // Get sequence length
    CK_LONG seq_len_fail = 0;
    CK_ULONG seq_len_size = 0;
    CK_ULONG seq_len = tlvGetLengthSafe(der_sig + der_pos, der_len - der_pos, &seq_len_fail, &seq_len_size);
    if (seq_len_fail || seq_len_size > der_len - der_pos) {
      cnk_disconnect_card(hCard);
      CNK_RETURN(CKR_DEVICE_ERROR, "Invalid ECDSA signature: couldn't parse SEQUENCE length");
    }
    der_pos += seq_len_size;
    if (seq_len != der_len - der_pos) {
      cnk_disconnect_card(hCard);
      CNK_RETURN(CKR_DEVICE_ERROR, "Invalid ECDSA signature: SEQUENCE length mismatch");
    }

    // Expect r INTEGER
    if (der_pos >= der_len || der_sig[der_pos] != 0x02) { // 0x02 is the INTEGER tag in DER
      cnk_disconnect_card(hCard);
      CNK_RETURN(CKR_DEVICE_ERROR, "Invalid ECDSA signature: r value not an INTEGER");
    }
    der_pos++; // Skip INTEGER tag

    // Get r length
    CK_LONG r_len_fail = 0;
    CK_ULONG r_len_size = 0;
    CK_ULONG r_len = tlvGetLengthSafe(der_sig + der_pos, der_len - der_pos, &r_len_fail, &r_len_size);
    if (r_len_fail || r_len_size > der_len - der_pos) {
      cnk_disconnect_card(hCard);
      CNK_RETURN(CKR_DEVICE_ERROR, "Invalid ECDSA signature: couldn't parse r INTEGER length");
    }
    der_pos += r_len_size;
    if (r_len > der_len - der_pos) {
      cnk_disconnect_card(hCard);
      CNK_RETURN(CKR_DEVICE_ERROR, "Invalid ECDSA signature: r value exceeds response");
    }

    // Adjust for negative numbers (where first byte is 0x00)
    CK_ULONG r_value_offset = 0;
    if (r_len > 0 && der_sig[der_pos] == 0x00) {
      r_value_offset = 1;
      r_len--;
    }

    // Copy r value with padding if needed
    if (r_len <= ec_size) {
      // Zero-pad to the left
      memset(raw_sig, 0, ec_size - r_len);
      memcpy(raw_sig + (ec_size - r_len), der_sig + der_pos + r_value_offset, r_len);
    } else {
      cnk_disconnect_card(hCard);
      CNK_RETURN(CKR_DEVICE_ERROR, "Invalid ECDSA signature: r value is too large");
    }
    der_pos += r_len + r_value_offset;

    // Expect s INTEGER
    if (der_pos >= der_len || der_sig[der_pos] != 0x02) { // 0x02 is the INTEGER tag in DER
      cnk_disconnect_card(hCard);
      CNK_RETURN(CKR_DEVICE_ERROR, "Invalid ECDSA signature: s value not an INTEGER");
    }
    der_pos++; // Skip INTEGER tag

    // Get s length
    CK_LONG s_len_fail = 0;
    CK_ULONG s_len_size = 0;
    CK_ULONG s_len = tlvGetLengthSafe(der_sig + der_pos, der_len - der_pos, &s_len_fail, &s_len_size);
    if (s_len_fail || s_len_size > der_len - der_pos) {
      cnk_disconnect_card(hCard);
      CNK_RETURN(CKR_DEVICE_ERROR, "Invalid ECDSA signature: couldn't parse s INTEGER length");
    }
    der_pos += s_len_size;
    if (s_len > der_len - der_pos) {
      cnk_disconnect_card(hCard);
      CNK_RETURN(CKR_DEVICE_ERROR, "Invalid ECDSA signature: s value exceeds response");
    }

    // Adjust for negative numbers (where first byte is 0x00)
    CK_ULONG s_value_offset = 0;
    if (s_len > 0 && der_sig[der_pos] == 0x00) {
      s_value_offset = 1;
      s_len--;
    }

    // Copy s value with padding if needed
    if (s_len <= ec_size) {
      // Zero-pad to the left
      memset(raw_sig + ec_size, 0, ec_size - s_len);
      memcpy(raw_sig + ec_size + (ec_size - s_len), der_sig + der_pos + s_value_offset, s_len);
    } else {
      cnk_disconnect_card(hCard);
      CNK_RETURN(CKR_DEVICE_ERROR, "Invalid ECDSA signature: s value is too large");
    }
    der_pos += s_len + s_value_offset;
    if (der_pos != der_len) {
      cnk_disconnect_card(hCard);
      CNK_RETURN(CKR_DEVICE_ERROR, "Invalid ECDSA signature: trailing DER data");
    }

    // Copy the raw signature to output buffer
    memcpy(pSignature, raw_sig, expected_sig_size);
    *pcbSignature = expected_sig_size;
    CNK_DEBUG("Converted ECDSA signature to %lu byte raw format", expected_sig_size);
  } else {
    // For non-ECDSA signatures, just copy the raw signature
    if (sig_len > *pcbSignature) {
      cnk_disconnect_card(hCard);
      *pcbSignature = sig_len;
      CNK_RETURN(CKR_BUFFER_TOO_SMALL, "Signature buffer too small for actual signature");
    }

    memcpy(pSignature, response + offset, sig_len);
    *pcbSignature = (CK_ULONG)sig_len;
  }

  cnk_disconnect_card(hCard);
  return CKR_OK;
}

CK_RV cnk_piv_generate_keypair(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_BYTE algorithmType, CK_BYTE pivSlot,
                               CK_BYTE pinPolicy, CK_BYTE touchPolicy, CK_BYTE_PTR pbPublicKey,
                               CK_ULONG_PTR pcbPublicKey) {
  CNK_LOG_FUNC(": slotID: %ld, algorithmType: 0x%02X, pivSlot: 0x%02X, pinPolicy: %u, touchPolicy: %u", slotID,
               algorithmType, pivSlot, pinPolicy, touchPolicy);
  CNK_ENSURE_NONNULL(pbPublicKey, pcbPublicKey);

  CK_BYTE data[16];
  CK_ULONG data_len = 0;
  data[data_len++] = 0xAC;
  data[data_len++] = 0x03;
  data[data_len++] = 0x80;
  data[data_len++] = 0x01;
  data[data_len++] = algorithmType;
  data[data_len++] = 0xAA;
  data[data_len++] = 0x01;
  data[data_len++] = pinPolicy;
  data[data_len++] = 0xAB;
  data[data_len++] = 0x01;
  data[data_len++] = touchPolicy;

  CK_BYTE response[CNK_PIV_MAX_PUBLIC_KEY_RESPONSE];
  CK_ULONG response_len = sizeof(response);
  SCARDHANDLE hCard = 0;

  CK_RV rv = cnk_authenticate_admin_for_write(slotID, session, &hCard);
  if (rv != CKR_OK)
    return rv;

  rv = cnk_transmit_chained_apdu(hCard, 0x47, 0x00, pivSlot, data, data_len, response, &response_len, CK_TRUE);
  cnk_disconnect_card(hCard);
  if (rv != CKR_OK)
    CNK_RETURN(rv, "GENERATE ASYMMETRIC KEY PAIR");
  // The card mutation committed even if response parsing later fails, so a
  // subsequent metadata query must perform a fresh hardware read.
  cnk_piv_public_cache_invalidate(session);
  if (response_len < 2)
    CNK_RETURN(CKR_DEVICE_ERROR, "generate response too short");

  CK_ULONG public_key_len = response_len - 2;
  if (public_key_len < 2 || response[0] != 0x7F || response[1] != 0x49)
    CNK_RETURN(CKR_DEVICE_ERROR, "bad generate public key response");

  CK_ULONG encoded_offset = 2;
  CK_ULONG encoded_len = public_key_len - encoded_offset;
  CK_LONG fail = 0;
  CK_ULONG wrapper_len_size = 0;
  CK_ULONG wrapper_len =
      tlvGetLengthSafe(response + encoded_offset, public_key_len - encoded_offset, &fail, &wrapper_len_size);
  if (!fail && wrapper_len_size > 0 && wrapper_len == public_key_len - encoded_offset - wrapper_len_size) {
    encoded_offset += wrapper_len_size;
    encoded_len = wrapper_len;
  }

  if (*pcbPublicKey < encoded_len) {
    *pcbPublicKey = encoded_len;
    CNK_RETURN(CKR_BUFFER_TOO_SMALL, "public key buffer too small");
  }

  memcpy(pbPublicKey, response + encoded_offset, encoded_len);
  *pcbPublicKey = encoded_len;
  CNK_RET_OK;
}

CK_RV cnk_piv_import_key(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_BYTE algorithmType, CK_BYTE pivSlot,
                         CK_BYTE_PTR keyData, CK_ULONG keyDataLen) {
  CNK_LOG_FUNC(": slotID: %ld, algorithmType: 0x%02X, pivSlot: 0x%02X, keyData: %p, keyDataLen: %lu", slotID,
               algorithmType, pivSlot, keyData, keyDataLen);
  CNK_ENSURE_NONNULL(keyData);

  SCARDHANDLE hCard = 0;
  CK_RV rv = cnk_authenticate_admin_for_write(slotID, session, &hCard);
  if (rv != CKR_OK)
    return rv;

  rv = cnk_transmit_chained_apdu(hCard, 0xFE, algorithmType, pivSlot, keyData, keyDataLen, NULL, NULL, CK_FALSE);
  cnk_disconnect_card(hCard);
  if (rv != CKR_OK)
    CNK_RETURN(rv, "IMPORT ASYMMETRIC KEY");
  cnk_piv_public_cache_invalidate(session);
  CNK_RET_OK;
}
