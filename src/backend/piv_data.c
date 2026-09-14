#include "backend/pcsc.h"
#include "backend/libcanokey.h"

#include "api/session.h"

#include "api/session.h"
#include "internal/logging.h"
#include "internal/macros.h"

#include <mbedtls/platform_util.h>
#include <string.h>

#define CNK_PIV_MAX_DATA_OBJECT_SIZE 8192
#define PIV_PADDED_PIN_LEN 8

static CK_RV map_libcanokey_object_error(const CNK_LIBCANO_OPERATION *operation, uint32_t status) {
  CNK_LIBCANO_ERROR error = {.struct_size = sizeof(error)};
  if (operation != NULL && cnk_operation_error(operation, &error) == CNK_LIBCANO_OK) {
    switch (error.kind) {
    case CNK_LIBCANO_ERROR_NOT_FOUND:
      return CKR_DATA_INVALID;
    case CNK_LIBCANO_ERROR_AUTHENTICATION_FAILED:
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
  return status == CNK_LIBCANO_BUFFER_TOO_SMALL ? CKR_BUFFER_TOO_SMALL : CKR_DEVICE_ERROR;
}

static CK_RV cnk_get_piv_data_libcanokey(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, const CK_BYTE *tag,
                                         CK_ULONG tag_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len,
                                         CK_BBOOL fetch_data) {
  CNK_ENSURE_NONNULL(session, tag);
  if (tag_len == 0 || tag_len > 4 || (fetch_data && data_len == NULL))
    return CKR_ARGUMENTS_BAD;
  CNK_ENSURE_OK(cnk_ensure_libcanokey_profile(session));

  SCARDHANDLE card = 0;
  CK_BYTE pin[PIV_PADDED_PIN_LEN] = {0};
  CK_ULONG pinLen = 0;
  CK_BBOOL pinVerified = CK_FALSE;
  CK_RV rv = cnk_token_copy_pin(session, pin, &pinLen);
  if (rv == CKR_OK) {
    rv = cnk_verify_piv_pin_with_session_ex(slotID, session, pin, pinLen, NULL, &card);
    pinVerified = rv == CKR_OK;
  } else if (rv == CKR_USER_NOT_LOGGED_IN) {
    rv = cnk_begin_piv_transaction(slotID, &card);
  }
  mbedtls_platform_zeroize(pin, sizeof(pin));
  if (rv != CKR_OK)
    return rv;

  CNK_LIBCANO_CONTEXT *context = NULL;
  CNK_LIBCANO_OPERATION *operation = NULL;
  CNK_LIBCANO_ERROR error = {.struct_size = sizeof(error)};
  uint32_t step = 0;
  uint32_t status = CNK_LIBCANO_OK;
  CK_BYTE response[8192] = {0};
  CNK_ENSURE_OK(cnk_mutex_lock(&session->token->lock));
  CNK_LIBCANO_PROFILE *profile = session->token->libcanokeyProfile;
  uint32_t contextStatus = profile == NULL
                               ? CNK_LIBCANO_INVALID_STATE
                               : cnk_piv_context_new(profile,
                                                     pinVerified ? CNK_LIBCANO_CONTEXT_PIN_VERIFIED
                                                                 : CNK_LIBCANO_CONTEXT_SELECTED,
                                                     &context, &error);
  cnk_mutex_unlock(&session->token->lock);
  if (contextStatus != CNK_LIBCANO_OK ||
      cnk_piv_read_object_in_context_new(context, tag, tag_len, NULL, &operation, &error) != CNK_LIBCANO_OK ||
      cnk_operation_start(operation, &step, &error) != CNK_LIBCANO_OK) {
    rv = CKR_DEVICE_ERROR;
    goto cleanup;
  }
  while (step == CNK_LIBCANO_STEP_EXCHANGE) {
    size_t commandLen = 0;
    status = cnk_operation_command(operation, NULL, &commandLen);
    if (status != CNK_LIBCANO_OK || commandLen == 0 || commandLen > 2048) {
      rv = map_libcanokey_object_error(operation, status);
      goto cleanup;
    }
    CK_BYTE command[2048];
    status = cnk_operation_command(operation, command, &commandLen);
    if (status != CNK_LIBCANO_OK) {
      rv = map_libcanokey_object_error(operation, status);
      goto cleanup;
    }
    DWORD responseLen = sizeof(response);
    if (cnk_transceive_apdu(card, command, (CK_ULONG)commandLen, response, &responseLen, CK_FALSE) != SCARD_S_SUCCESS) {
      rv = CKR_DEVICE_ERROR;
      goto cleanup;
    }
    status = cnk_operation_advance(operation, response, responseLen, &step, &error);
    if (status != CNK_LIBCANO_OK) {
      rv = map_libcanokey_object_error(operation, status);
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
    rv = map_libcanokey_object_error(operation, status);
    goto cleanup;
  }
  if (!fetch_data) {
    rv = CKR_OK;
    goto cleanup;
  }
  CK_ULONG capacity = *data_len;
  *data_len = (CK_ULONG)required;
  if (data == NULL) {
    rv = CKR_OK;
    goto cleanup;
  }
  if (capacity < required) {
    rv = CKR_BUFFER_TOO_SMALL;
    goto cleanup;
  }
  status = cnk_operation_result_copy_bytes(operation, data, &required);
  rv = map_libcanokey_object_error(operation, status);

cleanup:
  if (operation != NULL)
    cnk_operation_free(operation);
  if (context != NULL)
    cnk_piv_context_free(context);
  cnk_disconnect_card(card);
  mbedtls_platform_zeroize(response, sizeof(response));
  return rv;
}

static CK_RV cnk_get_piv_data_on_card(SCARDHANDLE hCard, const CK_BYTE *tag, CK_ULONG tag_len, CK_BYTE_PTR data,
                                      CK_ULONG_PTR data_len, CK_BBOOL fetch_data) {
  CNK_ENSURE_NONNULL(tag);
  if (tag_len == 0 || tag_len > 4)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "bad PIV data object tag");
  if (fetch_data && data_len == NULL)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "data_len is NULL");

  CK_BYTE apdu[14] = {0x00, 0xCB, 0x3F, 0xFF, 0x00, 0x5C};
  apdu[4] = (CK_BYTE)(2 + tag_len);
  apdu[6] = (CK_BYTE)tag_len;
  memcpy(apdu + 7, tag, tag_len);
  apdu[7 + tag_len] = 0x00;

  // GET DATA returns the object payload followed by SW1/SW2. Reserve those
  // status bytes in addition to the maximum accepted payload size.
  CK_BYTE response[CNK_PIV_MAX_DATA_OBJECT_SIZE + 2];
  DWORD response_len = sizeof(response);
  LONG pcsc_rv = cnk_transceive_apdu(hCard, apdu, 8 + tag_len, response, &response_len, fetch_data);
  if (pcsc_rv != SCARD_S_SUCCESS) {
    CNK_ERROR("Failed to send GET DATA command: %ld", pcsc_rv);
    return CKR_DEVICE_ERROR;
  }

  // Check if the command was successful
  if (response_len == 2 && response[0] == 0x6A && response[1] == 0x82) {
    CNK_RETURN(CKR_DATA_INVALID, "PIV tag not found");
  }
  if (response_len == 2 && response[0] == 0x69 && response[1] == 0x82) {
    CNK_RETURN(CKR_USER_NOT_LOGGED_IN, "PIV data object access denied");
  }
  CK_BBOOL success = response_len >= 2 && response[response_len - 2] == 0x90 && response[response_len - 1] == 0x00;
  CK_BBOOL moreData = response_len >= 2 && response[response_len - 2] == 0x61;
  if (response_len < 2 || (fetch_data && !success) || (!fetch_data && !success && !moreData)) {
    CNK_RETURN(CKR_DEVICE_ERROR, "Failed to execute GET DATA command");
  }

  // Report and optionally copy the response data, excluding status bytes.
  if (fetch_data) {
    CK_ULONG required = response_len - 2;
    CK_ULONG available = *data_len;
    *data_len = required;
    if (data != NULL) {
      if (available < required) {
        CNK_RETURN(CKR_BUFFER_TOO_SMALL, "Output buffer too small");
      }
      memcpy(data, response, required);
    }
  }

  CNK_RET_OK;
}

// Get PIV data from the CanoKey device
// If data is NULL, no data will be copied
// This function may return:
// - CKR_DATA_INVALID if the data object does not exist.
// - CKR_OK if the data object is successfully read.
// - CKR_DEVICE_ERROR if the data object could not be read.
CK_RV cnk_get_piv_data_by_tag(CK_SLOT_ID slotID, const CK_BYTE *tag, CK_ULONG tag_len, CK_BYTE_PTR data,
                              CK_ULONG_PTR data_len, CK_BBOOL fetch_data) {
  CNK_LOG_FUNC(": slotID: %ld, tag: %p, tag_len: %lu, data: %p, data_len: %p, fetch_data: %d", slotID, tag, tag_len,
               data, data_len, fetch_data);

  SCARDHANDLE hCard;
  CNK_ENSURE_OK(cnk_begin_piv_transaction(slotID, &hCard));

  CK_RV rv = cnk_get_piv_data_on_card(hCard, tag, tag_len, data, data_len, fetch_data);

  cnk_disconnect_card(hCard);
  CNK_RETURN(rv, "GET DATA");
}

CK_RV cnk_get_piv_data_by_tag_with_session(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, const CK_BYTE *tag,
                                           CK_ULONG tag_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len,
                                           CK_BBOOL fetch_data) {
  CNK_LOG_FUNC(": slotID: %ld, session: %p, tag: %p, tag_len: %lu, data: %p, data_len: %p, fetch_data: %d", slotID,
               session, tag, tag_len, data, data_len, fetch_data);
  return cnk_get_piv_data_libcanokey(slotID, session, tag, tag_len, data, data_len, fetch_data);
}

CK_RV cnk_get_piv_data(CK_SLOT_ID slotID, CK_BYTE tag, CK_BYTE_PTR data, CK_ULONG_PTR data_len, CK_BBOOL fetch_data) {
  CNK_LOG_FUNC(": slotID: %ld, tag: 0x%02X, data: %p, data_len: %p, fetch_data: %d", slotID, tag, data, data_len,
               fetch_data);

  // Where xx is mapped from the PIV tag as follows:
  // 9A -> 05, 9C -> 0A, 9D -> 0B, 9E -> 01, 82 -> 0D, 83 -> 0E
  CK_BYTE mapped_tag;
  switch (tag) {
  case 0x9A:
    mapped_tag = PIV_OBJECT_TAG_CERT_9A;
    break;
  case 0x9C:
    mapped_tag = PIV_OBJECT_TAG_CERT_9C;
    break;
  case 0x9D:
    mapped_tag = PIV_OBJECT_TAG_CERT_9D;
    break;
  case 0x9E:
    mapped_tag = PIV_OBJECT_TAG_CERT_9E;
    break;
  case 0x82:
    mapped_tag = PIV_OBJECT_TAG_CERT_82;
    break;
  case 0x83:
    mapped_tag = PIV_OBJECT_TAG_CERT_83;
    break;
  default:
    mapped_tag = tag;
    break; // Keep original tag if not in mapping
  }

  CK_BYTE object_tag[] = {0x5F, 0xC1, mapped_tag};
  return cnk_get_piv_data_by_tag(slotID, object_tag, sizeof(object_tag), data, data_len, fetch_data);
}

CK_RV cnk_put_piv_data_by_tag(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, const CK_BYTE *tag, CK_ULONG tag_len,
                              CK_BYTE_PTR data, CK_ULONG data_len) {
  CNK_LOG_FUNC(": slotID: %ld, tag: %p, tag_len: %lu, data: %p, data_len: %lu", slotID, tag, tag_len, data, data_len);

  CNK_ENSURE_NONNULL(tag);
  if (tag_len == 0 || tag_len > 4)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "bad PIV data object tag");
  if (data_len > 0)
    CNK_ENSURE_NONNULL(data);

  CK_BYTE object_data[2 + 4 + CNK_PIV_MAX_DATA_OBJECT_SIZE];
  if (data_len > sizeof(object_data) - 2 - tag_len)
    CNK_RETURN(CKR_DATA_LEN_RANGE, "PIV data object too large");

  object_data[0] = 0x5C;
  object_data[1] = (CK_BYTE)tag_len;
  memcpy(object_data + 2, tag, tag_len);
  if (data_len > 0)
    memcpy(object_data + 2 + tag_len, data, data_len);

  SCARDHANDLE hCard = 0;
  CK_RV rv = cnk_authenticate_admin_for_write(slotID, session, &hCard);
  if (rv != CKR_OK)
    return rv;

  rv = cnk_transmit_chained_apdu(hCard, 0xDB, 0x3F, 0xFF, object_data, data_len + 2 + tag_len, NULL, NULL, CK_FALSE);
  cnk_disconnect_card(hCard);
  if (rv != CKR_OK)
    CNK_RETURN(rv, "PUT DATA");
  // A successful write may change certificate or key-adjacent public data;
  // discard the standalone snapshot before exposing the result to callers.
  cnk_piv_public_cache_invalidate(session);
  CNK_RET_OK;
}

CK_RV cnk_put_piv_data(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_BYTE tag, CK_BYTE_PTR data,
                       CK_ULONG data_len) {
  CNK_LOG_FUNC(": slotID: %ld, tag: 0x%02X, data: %p, data_len: %lu", slotID, tag, data, data_len);
  CK_BYTE object_tag[] = {0x5F, 0xC1, tag};
  return cnk_put_piv_data_by_tag(slotID, session, object_tag, sizeof(object_tag), data, data_len);
}

// Helper function to get firmware version and hardware name
CK_RV cnk_get_version(CK_SLOT_ID slotID, CK_BYTE *fw_major, CK_BYTE *fw_minor, char *hw_name_out, size_t hw_name_len) {
  SCARDHANDLE hCard;
  char local_hw_name[256] = {0}; // Local buffer for hardware name

  // Connect to the card for this operation
  CK_RV rv = cnk_begin_card_transaction(slotID, &hCard);
  if (rv != CKR_OK) {
    return rv;
  }

  // Select the CanoKey AID: F000000000
  CK_BYTE select_apdu[] = {0x00, 0xA4, 0x04, 0x00, 0x05, 0xF0, 0x00, 0x00, 0x00, 0x00};
  CK_BYTE response[258];
  DWORD response_len = sizeof(response);

  // Use the transceive function to send the command and log both command and response
  rv = cnk_transceive_apdu(hCard, select_apdu, sizeof(select_apdu), response, &response_len, CK_FALSE);
  if (rv != SCARD_S_SUCCESS) {
    cnk_disconnect_card(hCard);
    return CKR_DEVICE_ERROR;
  }

  // Check if the select command was successful (SW1SW2 = 9000)
  if (response_len < 2 || response[response_len - 2] != 0x90 || response[response_len - 1] != 0x00) {
    cnk_disconnect_card(hCard);
    return CKR_DEVICE_ERROR;
  }

  // First get the hardware name
  CK_BYTE hw_version_apdu[] = {0x00, 0x31, 0x01, 0x00, 0x00};
  response_len = sizeof(response);

  // Send the hardware version command
  LONG pcsc_rv =
      cnk_transceive_apdu(hCard, hw_version_apdu, sizeof(hw_version_apdu), response, &response_len, CK_FALSE);
  if (pcsc_rv == SCARD_S_SUCCESS && response_len >= 2 && response[response_len - 2] == 0x90 &&
      response[response_len - 1] == 0x00) {

    // Extract hardware name
    size_t name_len = response_len - 2; // Exclude status bytes
    if (name_len > sizeof(local_hw_name) - 1) {
      name_len = sizeof(local_hw_name) - 1;
    }
    memcpy(local_hw_name, response, name_len);
    local_hw_name[name_len] = '\0';
  } else {
    // If hardware name retrieval fails, set a default
    strcpy(local_hw_name, "CanoKey");
  }

  // Now get the firmware version
  CK_BYTE fw_version_apdu[] = {0x00, 0x31, 0x00, 0x00, 0x00};
  response_len = sizeof(response);

  // Send the firmware version command
  pcsc_rv = cnk_transceive_apdu(hCard, fw_version_apdu, sizeof(fw_version_apdu), response, &response_len, CK_FALSE);
  if (pcsc_rv != SCARD_S_SUCCESS) {
    cnk_disconnect_card(hCard);
    return CKR_DEVICE_ERROR;
  }

  // Check if the command was successful
  if (response_len < 2 || response[response_len - 2] != 0x90 || response[response_len - 1] != 0x00) {
    cnk_disconnect_card(hCard);
    return CKR_DEVICE_ERROR;
  }

  // Parse firmware version string (format: "X.Y.Z")
  char version_str[16] = {0};
  size_t len = response_len - 2; // Exclude status bytes
  if (len > sizeof(version_str) - 1) {
    len = sizeof(version_str) - 1;
  }
  memcpy(version_str, response, len);
  version_str[len] = '\0';

  int v_major, v_minor, v_patch;
  if (sscanf(version_str, "%d.%d.%d", &v_major, &v_minor, &v_patch) == 3) {
    // For firmware version: major is the first part, minor is the second part * 10 + the third part
    *fw_major = (CK_BYTE)v_major;
    *fw_minor = (CK_BYTE)(v_minor * 10 + v_patch);
  } else {
    // Fallback if parsing fails
    *fw_major = 0;
    *fw_minor = 0;
  }

  // Copy the hardware name to the output buffer if provided
  if (hw_name_out != NULL && hw_name_len > 0) {
    strncpy(hw_name_out, local_hw_name, hw_name_len - 1);
    hw_name_out[hw_name_len - 1] = '\0'; // Ensure null termination
  }

  // Disconnect from the card when done
  cnk_disconnect_card(hCard);
  return CKR_OK;
}

// Get serial number (4-byte big endian number)
CK_RV cnk_get_serial_number(CK_SLOT_ID slotID, CK_ULONG *serial_number) {
  SCARDHANDLE hCard;

  // Connect to the card for this operation
  CK_RV rv = cnk_begin_card_transaction(slotID, &hCard);
  if (rv != CKR_OK) {
    return rv;
  }

  // Select the CanoKey AID: F000000000
  CK_BYTE select_apdu[] = {0x00, 0xA4, 0x04, 0x00, 0x05, 0xF0, 0x00, 0x00, 0x00, 0x00};
  CK_BYTE response[258];
  DWORD response_len = sizeof(response);

  // Use the transceive function to send the command and log both command and response
  rv = cnk_transceive_apdu(hCard, select_apdu, sizeof(select_apdu), response, &response_len, CK_FALSE);
  if (rv != SCARD_S_SUCCESS) {
    cnk_disconnect_card(hCard);
    return CKR_DEVICE_ERROR;
  }

  // Check if the select command was successful (SW1SW2 = 9000)
  if (response_len < 2 || response[response_len - 2] != 0x90 || response[response_len - 1] != 0x00) {
    cnk_disconnect_card(hCard);
    return CKR_DEVICE_ERROR;
  }

  // Send the get serial number command: 00 32 00 00 00
  CK_BYTE sn_apdu[] = {0x00, 0x32, 0x00, 0x00, 0x00};
  response_len = sizeof(response);

  // Send the command
  LONG pcsc_rv = cnk_transceive_apdu(hCard, sn_apdu, sizeof(sn_apdu), response, &response_len, CK_FALSE);
  if (pcsc_rv != SCARD_S_SUCCESS) {
    cnk_disconnect_card(hCard);
    return CKR_DEVICE_ERROR;
  }

  // Check if the command was successful
  if (response_len < 6 || response[response_len - 2] != 0x90 || response[response_len - 1] != 0x00) {
    cnk_disconnect_card(hCard);
    return CKR_DEVICE_ERROR;
  }

  // Parse the 4-byte big endian serial number
  if (response_len >= 6) { // 4 bytes + 2 status bytes
    *serial_number = ((CK_ULONG)response[0] << 24) | ((CK_ULONG)response[1] << 16) | ((CK_ULONG)response[2] << 8) |
                     (CK_ULONG)response[3];
  } else {
    // Fallback if response is too short
    *serial_number = 0;
  }

  // Disconnect from the card when done
  cnk_disconnect_card(hCard);
  return CKR_OK;
}
