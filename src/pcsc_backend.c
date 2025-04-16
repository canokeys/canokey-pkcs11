#include "pcsc_backend.h"
#include "logging.h"
#include "pkcs11.h"
#include "pkcs11_session.h"
#include "utils.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Global variables for reader management
ReaderInfo *g_cnk_readers = NULL; // Array of reader info structs
CK_ULONG g_cnk_num_readers = 0;
CK_BBOOL g_cnk_is_initialized = CK_FALSE;

// Function pointer type for card operations
typedef CK_RV (*CardOperationFunc)(SCARDHANDLE hCard, void *context);

// Utility function to handle card connection, operation, and disconnection
static CK_RV cnk_with_card(CK_SLOT_ID slotID, CardOperationFunc operation, void *context, SCARDHANDLE *out_card) {
  if (!operation)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "operation is NULL");

  SCARDHANDLE hCard;
  CK_RV rv;

  // Connect to card
  rv = cnk_connect_and_select_canokey(slotID, &hCard);
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

// Helper function to check if a string contains 'canokey' (case insensitive)
static CK_BBOOL contains_canokey(const char *str) { return str && ck_strcasestr(str, "canokey") ? CK_TRUE : CK_FALSE; }

// Initialize PC/SC context only
CK_RV cnk_initialize_pcsc(void) {
  if (g_cnk_is_initialized)
    return CKR_OK;

  LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &g_cnk_pcsc_context);
  if (rv != SCARD_S_SUCCESS) {
    return CKR_DEVICE_ERROR;
  }

  g_cnk_is_initialized = CK_TRUE;
  return CKR_OK;
}

// List readers and populate g_cnk_readers
CK_RV cnk_list_readers(void) {
  if (!g_cnk_is_initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  // If readers are already listed, clean them up first
  if (g_cnk_readers) {
    for (CK_ULONG i = 0; i < g_cnk_num_readers; i++) {
      ck_free(g_cnk_readers[i].name);
    }
    ck_free(g_cnk_readers);
    g_cnk_readers = NULL;
    g_cnk_num_readers = 0;
  }

  // Get the list of readers
  DWORD readers_len = 0;

  // First call to get the needed buffer size
  LONG rv = SCardListReaders(g_cnk_pcsc_context, NULL, NULL, &readers_len);
  if (rv != SCARD_S_SUCCESS && rv != (LONG)SCARD_E_INSUFFICIENT_BUFFER) {
    return CKR_DEVICE_ERROR;
  }

  // Allocate memory for the readers list
  char *readers_buf = (char *)ck_malloc(readers_len);
  if (!readers_buf) {
    return CKR_HOST_MEMORY;
  }

  // Get the actual readers list
  rv = SCardListReaders(g_cnk_pcsc_context, NULL, readers_buf, &readers_len);
  if (rv != SCARD_S_SUCCESS) {
    ck_free(readers_buf);
    return CKR_DEVICE_ERROR;
  }

  // Count the number of readers with 'canokey' in their name
  g_cnk_num_readers = 0;
  char *reader = readers_buf;
  while (*reader != '\0') {
    if (contains_canokey(reader)) {
      g_cnk_num_readers++;
    }
    reader += strlen(reader) + 1;
  }

  // Allocate memory for the reader info array
  g_cnk_readers = ck_malloc(g_cnk_num_readers * sizeof(ReaderInfo));
  if (g_cnk_readers) {
    memset(g_cnk_readers, 0, g_cnk_num_readers * sizeof(ReaderInfo));
  }
  if (!g_cnk_readers) {
    ck_free(readers_buf);
    return CKR_HOST_MEMORY;
  }

  // Fill the reader list with readers containing 'canokey' and assign unique IDs
  reader = readers_buf;
  CK_ULONG index = 0;
  while (*reader != '\0' && index < g_cnk_num_readers) {
    if (contains_canokey(reader)) {
      size_t name_len = strlen(reader) + 1;
      g_cnk_readers[index].name = ck_malloc(name_len);
      if (g_cnk_readers[index].name) {
        memcpy(g_cnk_readers[index].name, reader, name_len);
      }
      if (!g_cnk_readers[index].name) {
        // Clean up on error
        for (CK_ULONG i = 0; i < index; i++) {
          ck_free(g_cnk_readers[i].name);
        }
        ck_free(g_cnk_readers);
        g_cnk_readers = NULL;
        g_cnk_num_readers = 0;
        ck_free(readers_buf);
        return CKR_HOST_MEMORY;
      }
      // Assign a unique ID to this reader (using index as the ID)
      g_cnk_readers[index].slot_id = index;
      index++;
    }
    reader += strlen(reader) + 1;
  }

  ck_free(readers_buf);
  return CKR_OK;
}

// Clean up PC/SC resources
void cnk_cleanup_pcsc(void) {
  if (!g_cnk_is_initialized)
    return;

  if (g_cnk_readers) {
    for (CK_ULONG i = 0; i < g_cnk_num_readers; i++) {
      ck_free(g_cnk_readers[i].name);
    }
    ck_free(g_cnk_readers);
    g_cnk_readers = NULL;
  }

  if (g_cnk_pcsc_context) {
    SCardReleaseContext(g_cnk_pcsc_context);
    g_cnk_pcsc_context = 0;
  }

  g_cnk_num_readers = 0;
  g_cnk_is_initialized = CK_FALSE;
}

// Get the number of readers
CK_ULONG cnk_get_num_readers(void) { return g_cnk_num_readers; }

// Get the slot ID for a reader at the given index
CK_SLOT_ID cnk_get_reader_slot_id(CK_ULONG index) {
  if (index >= g_cnk_num_readers) {
    return (CK_SLOT_ID)-1; // Invalid slot ID
  }
  return g_cnk_readers[index].slot_id;
}

// Helper function to connect to a card and select the CanoKey AID
CK_RV cnk_connect_and_select_canokey(CK_SLOT_ID slotID, SCARDHANDLE *phCard) {
  // In managed mode, use the provided card handle
  if (g_cnk_is_managed_mode) {
    *phCard = g_cnk_scard;

    // Begin transaction with default timeout of 2 seconds
    LONG rv = SCardBeginTransaction(*phCard);
    if (rv != SCARD_S_SUCCESS) {
      return CKR_DEVICE_ERROR;
    }

    return CKR_OK;
  }

  // Standalone mode - initialize PCSC if needed
  if (!g_cnk_is_initialized) {
    CK_RV rv = cnk_initialize_pcsc();
    if (rv != CKR_OK)
      return rv;
  }

  // If readers haven't been listed yet, list them now
  if (g_cnk_num_readers == 0 || g_cnk_readers == NULL) {
    CK_RV rv = cnk_list_readers();
    if (rv != CKR_OK)
      return rv;
  }

  if (g_cnk_readers == NULL) {
    CNK_ERROR("No readers found after listing");
    return CKR_SLOT_ID_INVALID;
  }

  // Find the reader corresponding to the slot ID
  CK_ULONG i;
  for (i = 0; i < g_cnk_num_readers; i++) {
    if (g_cnk_readers[i].slot_id == slotID)
      break;
  }

  if (i >= g_cnk_num_readers) {
    return CKR_SLOT_ID_INVALID;
  }

  // Connect to the card
  DWORD active_protocol;
  LONG rv = SCardConnect(g_cnk_pcsc_context, g_cnk_readers[i].name, SCARD_SHARE_SHARED,
                         SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, phCard, &active_protocol);
  if (rv != SCARD_S_SUCCESS) {
    return CKR_DEVICE_ERROR;
  }

  // Begin transaction with default timeout of 2 seconds
  rv = SCardBeginTransaction(*phCard);
  if (rv != SCARD_S_SUCCESS) {
    SCardDisconnect(*phCard, SCARD_LEAVE_CARD);
    return CKR_DEVICE_ERROR;
  }

  // Note: We don't end the transaction here to allow for subsequent operations
  // The caller is responsible for calling cnk_disconnect_card when done

  return CKR_OK;
}

// Disconnect from a card and end any active transaction
void cnk_disconnect_card(SCARDHANDLE hCard) {
  if (hCard == 0) {
    return;
  }

  // End transaction first
  SCardEndTransaction(hCard, SCARD_LEAVE_CARD);

  // In managed mode, don't disconnect the card
  if (g_cnk_is_managed_mode) {
    return;
  }

  // In standalone mode, disconnect the card
  SCardDisconnect(hCard, SCARD_LEAVE_CARD);
}

// Helper function to transmit APDU commands and log both command and response
static LONG cnk_transceive_apdu(SCARDHANDLE hCard, const CK_BYTE *command, DWORD command_len, CK_BYTE *response,
                                DWORD *response_len) {
  if (hCard == 0 || command == NULL || response == NULL || response_len == NULL) {
    return SCARD_E_INVALID_PARAMETER;
  }

  // Log the APDU command
  CNK_LOG_APDU_COMMAND(command, command_len);

  // Transmit the command
  LONG rv = SCardTransmit(hCard, SCARD_PCI_T1, command, command_len, NULL, response, response_len);

  // Log the APDU response
  if (rv == SCARD_S_SUCCESS) {
    CNK_LOG_APDU_RESPONSE(response, *response_len);
  } else {
    CNK_ERROR("SCardTransmit failed with error: 0x%lx", rv);
  }

  return rv;
}

// PIV application functions

// Select the PIV application using AID A000000308
CK_RV cnk_select_piv_application(SCARDHANDLE hCard) {
  if (hCard == 0)
    CNK_RETURN(CKR_DEVICE_ERROR, "Card handle is invalid");

  // PIV AID: A0 00 00 03 08
  CK_BYTE piv_aid[] = {0xA0, 0x00, 0x00, 0x03, 0x08};
  CK_BYTE select_apdu[11] = {0x00, 0xA4, 0x04, 0x00};

  // Set the length of the AID
  select_apdu[4] = sizeof(piv_aid);

  // Copy the AID into the APDU
  memcpy(select_apdu + 5, piv_aid, sizeof(piv_aid));

  // Prepare response buffer
  CK_BYTE response[258];
  DWORD response_len = sizeof(response);

  // Send the SELECT command using the transceive function
  LONG rv = cnk_transceive_apdu(hCard, select_apdu, sizeof(select_apdu), response, &response_len);

  if (rv != SCARD_S_SUCCESS) {
    CNK_RETURN(CKR_DEVICE_ERROR, "Failed to select PIV application");
  }

  // Check if the command was successful (status words 90 00)
  if (response_len < 2 || response[response_len - 2] != 0x90 || response[response_len - 1] != 0x00) {
    CNK_RETURN(CKR_DEVICE_ERROR, "Select PIV application failed");
  }

  return CKR_OK;
}

// Verify the PIV PIN
CK_RV cnk_verify_piv_pin(SCARDHANDLE hCard, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  if (hCard == 0 || pPin == NULL) {
    CNK_RETURN(CKR_ARGUMENTS_BAD, "Invalid arguments");
  }

  // PIN length must be between 1 and 8 characters
  if (ulPinLen < 1 || ulPinLen > 8) {
    CNK_RETURN(CKR_PIN_LEN_RANGE, "Invalid PIN length");
  }

  // First select the PIV application
  CK_RV rv = cnk_select_piv_application(hCard);
  if (rv != CKR_OK) {
    CNK_RETURN(rv, "Failed to select PIV application");
  }

  // Prepare the VERIFY command: 00 20 00 80 08 [PIN padded with 0xFF]
  CK_BYTE verify_apdu[14] = {0x00, 0x20, 0x00, 0x80, 0x08};

  // Pad the PIN with 0xFF
  memset(verify_apdu + 5, 0xFF, 8);
  memcpy(verify_apdu + 5, pPin, ulPinLen);

  // Prepare response buffer
  CK_BYTE response[258];
  DWORD response_len = sizeof(response);

  // Send the VERIFY command using the transceive function
  LONG pcsc_rv = cnk_transceive_apdu(hCard, verify_apdu, sizeof(verify_apdu), response, &response_len);

  if (pcsc_rv != SCARD_S_SUCCESS) {
    CNK_RETURN(CKR_DEVICE_ERROR, "Failed to verify PIV PIN");
  }

  // Check if the command was successful (status words 90 00)
  if (response_len < 2) {
    CNK_RETURN(CKR_DEVICE_ERROR, "Failed to verify PIV PIN");
  }

  // Check status words
  if (response[response_len - 2] == 0x90 && response[response_len - 1] == 0x00) {
    CNK_RETURN(CKR_OK, "PIV PIN verified");
  } else if (response[response_len - 2] == 0x63) {
    // PIN verification failed, remaining attempts in low nibble of SW2
    CNK_RETURN(CKR_PIN_INCORRECT, "PIV PIN verification failed");
  } else if (response[response_len - 2] == 0x69 && response[response_len - 1] == 0x83) {
    // PIN blocked
    CNK_RETURN(CKR_PIN_LOCKED, "PIV PIN blocked");
  } else {
    CNK_RETURN(CKR_DEVICE_ERROR, "Failed to verify PIV PIN");
  }
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
  CK_BYTE logout_apdu[] = {0x00, 0x20, 0xFF, 0x80, 0x00};

  // Prepare response buffer
  CK_BYTE response[258];
  DWORD response_len = sizeof(response);

  // Send the LOGOUT command using the transceive function
  LONG pcsc_rv = cnk_transceive_apdu(hCard, logout_apdu, sizeof(logout_apdu), response, &response_len);

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
  } else {
    CNK_RETURN(CKR_DEVICE_ERROR, "Failed to logout PIV PIN");
  }
}

// Get PIV data from the CanoKey device
// If fetch_data is CK_FALSE, only checks for existence and sets data_len to 1 if found, 0 if not
CK_RV cnk_get_piv_data(CK_SLOT_ID slotID, CK_BYTE tag, CK_BYTE_PTR *data, CK_ULONG_PTR data_len, CK_BBOOL fetch_data) {
  SCARDHANDLE hCard;
  CK_RV rv = cnk_connect_and_select_canokey(slotID, &hCard);
  CK_BBOOL need_disconnect = CK_FALSE;
  CK_BBOOL response_on_heap = CK_FALSE;

  // If we're just checking for existence, we can use a smaller buffer
  CK_BYTE response_buf[128];
  CK_BYTE_PTR response = response_buf;
  DWORD response_len = sizeof(response_buf);

  if (rv != CKR_OK) {
    CNK_ERROR("Connect to card failed");
    goto cleanup;
  }
  need_disconnect = CK_TRUE;

  // Select PIV application
  rv = cnk_select_piv_application(hCard);
  if (rv != CKR_OK) {
    CNK_ERROR("Select PIV application failed");
    goto cleanup;
  }

  // Prepare GET DATA APDU
  // Command: 00 CB 3F FF 05 5C 03 5F C1 xx 00
  // Where xx is mapped from the PIV tag as follows:
  // 9A -> 05, 9C -> 0A, 9D -> 0B, 9E -> 01, 82 -> 0D, 83 -> 0E
  CK_BYTE mapped_tag;
  switch (tag) {
  case 0x9A:
    mapped_tag = 0x05;
    break;
  case 0x9C:
    mapped_tag = 0x0A;
    break;
  case 0x9D:
    mapped_tag = 0x0B;
    break;
  case 0x9E:
    mapped_tag = 0x01;
    break;
  case 0x82:
    mapped_tag = 0x0D;
    break;
  case 0x83:
    mapped_tag = 0x0E;
    break;
  default:
    mapped_tag = tag;
    break; // Keep original tag if not in mapping
  }

  if (fetch_data) {
    response_len = 4096;
    response = (CK_BYTE_PTR)ck_malloc(response_len); // Allocate larger buffer for data
    if (response == NULL) {
      CNK_ERROR("ck_malloc failed");
      rv = CKR_HOST_MEMORY;
      goto cleanup;
    }
    memset(response, 0, response_len);
    response_on_heap = CK_TRUE;
  }

  // For existence check, we can modify the APDU to only request the header
  // This is more efficient than fetching the entire content
  CK_BYTE apdu[11] = {0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, mapped_tag, fetch_data ? 0x00 : 0x01};

  // Send the get PIV data command using the transceive function
  LONG pcsc_rv = cnk_transceive_apdu(hCard, apdu, sizeof(apdu), response, &response_len);

  if (pcsc_rv != SCARD_S_SUCCESS) {
    CNK_ERROR("transceive failure: %lu", pcsc_rv);
    rv = CKR_DEVICE_ERROR;
    goto cleanup;
  }

  // Only fetch complete data if fetch_data is true
  if (fetch_data && response_len >= 2 && response[response_len - 2] == 0x61) {
    // For large responses, the card will return 61xx, indicating xx more bytes are available
    // We need to use GET RESPONSE (C0) to fetch the remaining data until we get 9000
    DWORD data_offset = response_len - 2; // Save the current data length (excluding SW1SW2)

    // Process initial response
    // Check if we have a 61xx status word (more data available)
    while (response_len >= 2 && response[response_len - 2] == 0x61) {
      // Save the current data (excluding SW1SW2)
      CK_BYTE sw2 = response[response_len - 1];

      // Prepare GET RESPONSE command
      CK_BYTE get_response[5] = {0x00, 0xC0, 0x00, 0x00, sw2};

      // Get next chunk directly into the response buffer after the current data
      DWORD next_chunk_len = sizeof(response) - data_offset;

      // Send GET RESPONSE command
      pcsc_rv = cnk_transceive_apdu(hCard, get_response, sizeof(get_response), response + data_offset, &next_chunk_len);

      if (pcsc_rv != SCARD_S_SUCCESS) {
        CNK_ERROR("transceive failure: %lu", pcsc_rv);
        rv = CKR_DEVICE_ERROR;
        goto cleanup;
      }

      // Update data_offset and response_len
      if (next_chunk_len >= 2) {
        data_offset += next_chunk_len - 2; // Exclude SW1SW2 from data length
        response_len = data_offset + 2;    // Total response length includes SW1SW2
      }
    }
  }
  // When fetch_data is false, we don't need to call GET RESPONSE - just use the initial response

  cnk_disconnect_card(hCard);
  need_disconnect = CK_FALSE;

  // Check if the response indicates success
  if (response_len < 2) {
    CNK_ERROR("transceive response too short: %lu", response_len);
    rv = CKR_DEVICE_ERROR;
    goto cleanup;
  }

  // Success cases:
  // 1. SW1SW2 = 9000 (normal success)
  // 2. SW1 = 61 (more data available) when fetch_data is false (we only care about existence)
  if (response[response_len - 2] == 0x90 && response[response_len - 1] == 0x00) {
    // Normal success case - continue processing
  } else if (!fetch_data && response[response_len - 2] == 0x61) {
    // When not fetching data, 61XX means the object exists
    CNK_DEBUG("Object exists, but not fetching data");
    *data = NULL;
    *data_len = 1; // Indicates that the object exists
    rv = CKR_OK;
    goto cleanup;
  } else if (response[response_len - 2] == 0x6A && response[response_len - 1] == 0x82) {
    // Object doesn't exist
    CNK_ERROR("Object not found");
    *data = NULL;
    *data_len = 0;
    rv = CKR_OK;
    goto cleanup;
  } else {
    // Other error
    CNK_ERROR("transceive failure")
    rv = CKR_DEVICE_ERROR;
    goto cleanup;
  }

  if (fetch_data) {
    // Allocate memory for the data (excluding SW1SW2)
    *data_len = response_len - 2;
    *data = (CK_BYTE_PTR)ck_malloc(*data_len);
    if (*data == NULL) {
      CNK_ERROR("ck_malloc failed");
      rv = CKR_HOST_MEMORY;
      goto cleanup;
    }

    // Copy the data (excluding SW1SW2)
    memcpy(*data, response, *data_len);
  } else {
    // For existence check, just set data_len to 1 to indicate existence
    // If a cert exists, then the corresponding public key and private key also exist
    *data = NULL;
    *data_len = 1; // Indicates that the object exists
  }

cleanup:
  if (need_disconnect) {
    cnk_disconnect_card(hCard);
  }
  if (response_on_heap) {
    ck_free(response);
  }
  return rv;
}

// Helper function to get firmware version and hardware name
CK_RV cnk_get_version(CK_SLOT_ID slotID, CK_BYTE *fw_major, CK_BYTE *fw_minor, char *hw_name_out, size_t hw_name_len) {
  SCARDHANDLE hCard;
  char local_hw_name[256] = {0}; // Local buffer for hardware name

  // Connect to the card for this operation
  CK_RV rv = cnk_connect_and_select_canokey(slotID, &hCard);
  if (rv != CKR_OK) {
    return rv;
  }

  // Select the CanoKey AID: F000000000
  CK_BYTE select_apdu[] = {0x00, 0xA4, 0x04, 0x00, 0x05, 0xF0, 0x00, 0x00, 0x00, 0x00};
  CK_BYTE response[258];
  DWORD response_len = sizeof(response);

  // Use the transceive function to send the command and log both command and response
  rv = cnk_transceive_apdu(hCard, select_apdu, sizeof(select_apdu), response, &response_len);
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
  LONG pcsc_rv = cnk_transceive_apdu(hCard, hw_version_apdu, sizeof(hw_version_apdu), response, &response_len);
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
  pcsc_rv = cnk_transceive_apdu(hCard, fw_version_apdu, sizeof(fw_version_apdu), response, &response_len);
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

// Check if the library is initialized
CK_BBOOL cnk_is_initialized(void) { return g_cnk_is_initialized; }

// Get the number of available slots
CK_ULONG cnk_get_slot_count(void) { return g_cnk_num_readers; }

// Get serial number (4-byte big endian number)
CK_RV cnk_get_serial_number(CK_SLOT_ID slotID, CK_ULONG *serial_number) {
  SCARDHANDLE hCard;

  // Connect to the card for this operation
  CK_RV rv = cnk_connect_and_select_canokey(slotID, &hCard);
  if (rv != CKR_OK) {
    return rv;
  }

  // Select the CanoKey AID: F000000000
  CK_BYTE select_apdu[] = {0x00, 0xA4, 0x04, 0x00, 0x05, 0xF0, 0x00, 0x00, 0x00, 0x00};
  CK_BYTE response[258];
  DWORD response_len = sizeof(response);

  // Use the transceive function to send the command and log both command and response
  rv = cnk_transceive_apdu(hCard, select_apdu, sizeof(select_apdu), response, &response_len);
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
  LONG pcsc_rv = cnk_transceive_apdu(hCard, sn_apdu, sizeof(sn_apdu), response, &response_len);
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

// Sign data using PIV key
// This function signs raw data using the PIV GENERAL AUTHENTICATE command
// Supports input data up to 512 bytes (for RSA 4096)
CK_RV cnk_piv_sign(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_BYTE piv_tag, CK_BYTE_PTR pData,
                   CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
  SCARDHANDLE hCard;
  LONG pcsc_rv;
  CK_RV rv;

  // Check if we're just getting the signature length
  if (pSignature == NULL_PTR)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "pSignature is NULL");

  // Check if input data is too large (max 512 bytes for RSA 4096)
  if (ulDataLen > 512)
    CNK_RETURN(CKR_DATA_LEN_RANGE, "Input data too large (max 512 bytes)");

  // Verify PIN before signing
  if (session->piv_pin_len == 0)
    CNK_RETURN(CKR_PIN_INCORRECT, "PIN verification required before signing");

  // Use the extended version to keep the card connection open
  rv = cnk_verify_piv_pin_with_session_ex(slotID, session, session->piv_pin, session->piv_pin_len, &hCard);
  if (rv != CKR_OK) {
    CNK_ERROR("Failed to verify PIN");
    cnk_disconnect_card(hCard);
    return rv;
  }

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
  if (ulDataLen > 255) {
    // Use two-byte length encoding for lengths > 255
    tlv_data[tlv_len++] = 0x82;                               // Two-byte length marker
    tlv_data[tlv_len++] = (CK_BYTE)((ulDataLen >> 8) & 0xFF); // Length high byte
    tlv_data[tlv_len++] = (CK_BYTE)(ulDataLen & 0xFF);        // Length low byte
  } else {
    // Use one-byte length encoding for lengths <= 255
    tlv_data[tlv_len++] = (CK_BYTE)ulDataLen;
  }

  // Copy the raw input data
  memcpy(tlv_data + tlv_len, pData, ulDataLen);
  tlv_len += ulDataLen;

  // Now fill in the length of the outer template
  // The length needs to be updated based on the total length of the contents
  if (tlv_len - len_pos - 1 > 0xFF) {
    // Need to shift everything to make room for 3-byte length
    memmove(tlv_data + len_pos + 3, tlv_data + len_pos + 1, tlv_len - len_pos - 1);

    // Store the original calculated length before modification
    CK_ULONG content_len = tlv_len - len_pos - 1;

    // Update positions sequentially to avoid undefined behavior
    tlv_data[len_pos] = 0x82; // Two-byte length marker
    len_pos++;

    tlv_data[len_pos] = (CK_BYTE)((content_len >> 8) & 0xFF); // Length high byte
    len_pos++;

    tlv_data[len_pos] = (CK_BYTE)(content_len & 0xFF); // Length low byte
    len_pos++;

    tlv_len += 2; // Adjust total length for the extra length bytes
  } else {
    tlv_data[len_pos] = (CK_BYTE)(tlv_len - len_pos - 1);
  }

  // Build the GENERAL AUTHENTICATE APDU
  // Increased buffer size for Extended APDU (4 header + 3 Lc + ~1024 data + 3 Le)
  CK_BYTE auth_apdu[1100];
  DWORD apdu_len = 0;

  // APDU header
  auth_apdu[apdu_len++] = 0x00;    // CLA
  auth_apdu[apdu_len++] = 0x87;    // INS - GENERAL AUTHENTICATE
  auth_apdu[apdu_len++] = 0x07;    // P1 - Algorithm (RSA 2048)
  auth_apdu[apdu_len++] = piv_tag; // P2 - Key reference (PIV slot)

  // Handle Lc, Data, and Le based on APDU format and using the TLV data
  if (tlv_len <= 255) {
    // Standard APDU format
    auth_apdu[apdu_len++] = (CK_BYTE)tlv_len;        // Lc
    memcpy(auth_apdu + apdu_len, tlv_data, tlv_len); // Data
    apdu_len += tlv_len;
    auth_apdu[apdu_len++] = 0x00; // Le (request max available)
  } else {
    // Extended APDU format
    auth_apdu[apdu_len++] = 0x00;                             // Extended length marker
    auth_apdu[apdu_len++] = (CK_BYTE)((tlv_len >> 8) & 0xFF); // Lc high byte
    auth_apdu[apdu_len++] = (CK_BYTE)(tlv_len & 0xFF);        // Lc low byte
    memcpy(auth_apdu + apdu_len, tlv_data, tlv_len);          // Data
    apdu_len += tlv_len;
    auth_apdu[apdu_len++] = 0x00; // Le high byte (request max available)
    auth_apdu[apdu_len++] = 0x00; // Le low byte
  }

  // Send the GENERAL AUTHENTICATE command
  CK_BYTE response[1024]; // Increased buffer size for larger responses
  DWORD response_len = sizeof(response);

  CNK_DEBUG("Sending PIV GENERAL AUTHENTICATE command for signing");
  pcsc_rv = cnk_transceive_apdu(hCard, auth_apdu, apdu_len, response, &response_len);

  if (pcsc_rv != SCARD_S_SUCCESS) {
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "Failed to send GENERAL AUTHENTICATE command");
  }

  // Buffer to hold the complete response
  CK_BYTE complete_response[1024];
  CK_ULONG complete_response_len = 0;

  // Check for success (9000) or more data available (61XX)
  CK_BYTE sw1 = response[response_len - 2];
  CK_BYTE sw2 = response[response_len - 1];

  if (sw1 == 0x90 && sw2 == 0x00) {
    // Success - copy the data (excluding status bytes) to the complete response buffer
    if (response_len > 2) {
      memcpy(complete_response, response, response_len - 2);
      complete_response_len = response_len - 2;
    }
  } else if (sw1 == 0x61) {
    // More data available - copy the initial data (excluding status bytes)
    if (response_len > 2) {
      memcpy(complete_response, response, response_len - 2);
      complete_response_len = response_len - 2;
    }

    // Use GET RESPONSE to fetch remaining data
    CK_BYTE get_response_apdu[] = {0x00, 0xC0, 0x00, 0x00, 0x00}; // GET RESPONSE command

    // Continue fetching data while the card returns 61XX
    while (sw1 == 0x61) {
      // Set the expected length in the GET RESPONSE command
      get_response_apdu[4] = sw2;

      // Send GET RESPONSE command
      CNK_DEBUG("Sending GET RESPONSE command for %d bytes", sw2);
      response_len = sizeof(response);
      pcsc_rv = cnk_transceive_apdu(hCard, get_response_apdu, sizeof(get_response_apdu), response, &response_len);

      if (pcsc_rv != SCARD_S_SUCCESS) {
        CNK_ERROR("Failed to send GET RESPONSE command: %ld", pcsc_rv);
        cnk_disconnect_card(hCard);
        return CKR_DEVICE_ERROR;
      }

      if (response_len < 2) {
        CNK_ERROR("GET RESPONSE returned too short response");
        cnk_disconnect_card(hCard);
        return CKR_DEVICE_ERROR;
      }

      // Update status bytes
      sw1 = response[response_len - 2];
      sw2 = response[response_len - 1];

      // Check if we have enough space in the complete response buffer
      if (complete_response_len + response_len - 2 > sizeof(complete_response)) {
        CNK_ERROR("Response too large for buffer");
        cnk_disconnect_card(hCard);
        return CKR_DEVICE_ERROR;
      }

      // Append the data (excluding status bytes) to the complete response
      if (response_len > 2) {
        memcpy(complete_response + complete_response_len, response, response_len - 2);
        complete_response_len += response_len - 2;
      }
    }

    // Final check - the last response should be 9000
    if (sw1 != 0x90 || sw2 != 0x00) {
      CNK_ERROR("Final GET RESPONSE returned error status: %02X%02X", sw1, sw2);
      cnk_disconnect_card(hCard);
      return CKR_DEVICE_ERROR;
    }
  } else {
    // Error status
    CNK_ERROR("GENERAL AUTHENTICATE command failed with status: %02X%02X", sw1, sw2);
    cnk_disconnect_card(hCard);
    return CKR_DEVICE_ERROR;
  }

  // Parse the response
  // The signature is returned in the format: 7C len1 82 len2 <signature>

  // Check if we have enough data
  if (complete_response_len < 4) { // At least 7C len 82 len
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "Invalid response format: too short");
  }

  // Verify the response format
  if (complete_response[0] != 0x7C) {
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "Invalid response format: missing 7C tag");
  }

  // Find the signature data
  size_t offset = 0;

  // Skip the outer TLV header
  if (complete_response[1] == 0x82) { // Extended length (2 bytes)
    offset = 4;                       // Skip 7C 82 xx xx
  } else {
    offset = 2; // Skip 7C xx
  }

  // Check for the inner 82 tag (signature response)
  if (offset < complete_response_len && complete_response[offset] != 0x82) {
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "Invalid response format: missing 82 tag");
  }

  // Skip the inner TLV header
  offset++; // Skip the 82 tag

  // Handle the length field
  if (offset < complete_response_len) {
    if (complete_response[offset] == 0x82 && offset + 2 < complete_response_len) {
      // Two-byte length
      offset += 3; // Skip 82 and two length bytes
    } else if (complete_response[offset] == 0x81 && offset + 1 < complete_response_len) {
      // One-byte length with 81 prefix
      offset += 2; // Skip 81 and one length byte
    } else {
      // One-byte length
      offset += 1; // Skip one length byte
    }
  }

  // Copy the signature
  size_t sig_len = complete_response_len - offset;
  if (sig_len > *pulSignatureLen) {
    cnk_disconnect_card(hCard);
    *pulSignatureLen = sig_len;
    CNK_RETURN(CKR_BUFFER_TOO_SMALL, "Signature buffer too small for actual signature");
  }

  memcpy(pSignature, complete_response + offset, sig_len);
  *pulSignatureLen = (CK_ULONG)sig_len;

  cnk_disconnect_card(hCard);
  return CKR_OK;
}

CK_RV cnk_get_metadata(CK_SLOT_ID slotID, CK_BYTE piv_tag, CK_BYTE_PTR algorithm_type, CK_BYTE_PTR modulus_ptr,
                       CK_ULONG_PTR modulus_len_ptr) {
  SCARDHANDLE hCard;
  CK_RV rv;

  // Initialize output parameters
  if (algorithm_type == NULL)
    CNK_RETURN(CKR_FUNCTION_FAILED, "algorithm_type is NULL");

  // If modulus is requested, ensure the length pointer is provided
  if (modulus_ptr != NULL && modulus_len_ptr == NULL)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "modulus_len_ptr is NULL when modulus_ptr is provided");

  // Connect to the card for this operation
  rv = cnk_connect_and_select_canokey(slotID, &hCard);
  if (rv != CKR_OK) {
    return rv;
  }

  // Select the PIV application
  rv = cnk_select_piv_application(hCard);
  if (rv != CKR_OK) {
    cnk_disconnect_card(hCard);
    return rv;
  }

  // Prepare the APDU for getting metadata
  // Command: 00 F7 00 XX 00 where XX is the PIV tag
  CK_BYTE metadata_apdu[] = {0x00, 0xF7, 0x00, piv_tag, 0x00};

  // Buffer to hold the complete response (up to 1024 bytes)
  CK_BYTE complete_response[1024];
  CK_ULONG complete_response_len = 0;

  // Temporary buffer for receiving responses
  CK_BYTE response[258]; // Maximum single response size
  DWORD response_len = sizeof(response);

  // Send the metadata command
  CNK_DEBUG("Sending metadata command for PIV tag 0x%02X", piv_tag);
  LONG pcsc_rv = cnk_transceive_apdu(hCard, metadata_apdu, sizeof(metadata_apdu), response, &response_len);
  if (pcsc_rv != SCARD_S_SUCCESS) {
    CNK_ERROR("Failed to send metadata command: %ld", pcsc_rv);
    cnk_disconnect_card(hCard);
    return CKR_DEVICE_ERROR;
  }

  // Process the initial response
  if (response_len < 2) {
    CNK_ERROR("Response too short");
    cnk_disconnect_card(hCard);
    return CKR_DEVICE_ERROR;
  }

  // Check for success (9000) or more data available (61XX)
  CK_BYTE sw1 = response[response_len - 2];
  CK_BYTE sw2 = response[response_len - 1];

  if (sw1 == 0x90 && sw2 == 0x00) {
    // Success - copy the data (excluding status bytes) to the complete response buffer
    if (response_len > 2) {
      memcpy(complete_response, response, response_len - 2);
      complete_response_len = response_len - 2;
    }
  } else if (sw1 == 0x61) {
    // More data available - copy the initial data (excluding status bytes)
    if (response_len > 2) {
      memcpy(complete_response, response, response_len - 2);
      complete_response_len = response_len - 2;
    }

    // Use GET RESPONSE to fetch remaining data
    CK_BYTE get_response_apdu[] = {0x00, 0xC0, 0x00, 0x00, 0x00}; // GET RESPONSE command

    // Continue fetching data while the card returns 61XX
    while (sw1 == 0x61) {
      // Set the expected length in the GET RESPONSE command
      get_response_apdu[4] = sw2;

      // Send GET RESPONSE command
      CNK_DEBUG("Sending GET RESPONSE command for %d bytes", sw2);
      response_len = sizeof(response);
      pcsc_rv = cnk_transceive_apdu(hCard, get_response_apdu, sizeof(get_response_apdu), response, &response_len);

      if (pcsc_rv != SCARD_S_SUCCESS) {
        CNK_ERROR("Failed to send GET RESPONSE command: %ld", pcsc_rv);
        cnk_disconnect_card(hCard);
        return CKR_DEVICE_ERROR;
      }

      if (response_len < 2) {
        CNK_ERROR("GET RESPONSE returned too short response");
        cnk_disconnect_card(hCard);
        return CKR_DEVICE_ERROR;
      }

      // Update status bytes
      sw1 = response[response_len - 2];
      sw2 = response[response_len - 1];

      // Check if we have enough space in the complete response buffer
      if (complete_response_len + response_len - 2 > sizeof(complete_response)) {
        CNK_ERROR("Response too large for buffer");
        cnk_disconnect_card(hCard);
        return CKR_DEVICE_ERROR;
      }

      // Append the data (excluding status bytes) to the complete response
      if (response_len > 2) {
        memcpy(complete_response + complete_response_len, response, response_len - 2);
        complete_response_len += response_len - 2;
      }
    }

    // Final check - the last response should be 9000
    if (sw1 != 0x90 || sw2 != 0x00) {
      CNK_ERROR("Final GET RESPONSE returned error status: %02X%02X", sw1, sw2);
      cnk_disconnect_card(hCard);
      return CKR_DEVICE_ERROR;
    }
  } else {
    // Error status
    CNK_ERROR("Metadata command failed with status: %02X%02X", sw1, sw2);
    cnk_disconnect_card(hCard);
    return CKR_DEVICE_ERROR;
  }

  // Process the complete response data
  CK_ULONG data_len = complete_response_len;
  CK_BYTE *data = complete_response;
  CK_ULONG pos = 0;

  CNK_DEBUG("Complete metadata response length: %lu bytes", data_len);

  // Parse the TLV data
  while (pos < data_len) {
    // Get the tag
    CK_BYTE tag = data[pos++];
    if (pos >= data_len)
      break;

    // Get the length (handle DER encoding)
    CK_ULONG length = 0;
    CK_BYTE len_byte = data[pos++];

    if (len_byte <= 0x7F) {
      // Short form: length is directly in the byte
      length = len_byte;
    } else if (len_byte == 0x81 && pos < data_len) {
      // Long form: next byte contains the length (up to 255)
      length = data[pos++];
    } else if (len_byte == 0x82 && pos + 1 < data_len) {
      // Longer form: next two bytes contain the length (up to 65535)
      length = (data[pos] << 8) | data[pos + 1];
      pos += 2;
    } else {
      // Invalid or unsupported length encoding
      CNK_ERROR("Invalid length encoding in metadata response");
      cnk_disconnect_card(hCard);
      return CKR_DEVICE_ERROR;
    }

    // Make sure we have enough data for the value
    if (pos + length > data_len) {
      CNK_ERROR("Incomplete TLV data in metadata response");
      cnk_disconnect_card(hCard);
      return CKR_DEVICE_ERROR;
    }

    // Process the tag-value pair
    switch (tag) {
    case 0x01: // Algorithm type
      if (length == 1 && algorithm_type != NULL) {
        *algorithm_type = data[pos];
        CNK_DEBUG("Algorithm type: 0x%02X", *algorithm_type);
      }
      break;

    case 0x02: // Pin and touch policies
      if (length >= 2) {
        CNK_DEBUG("Pin and touch policies: 0x%02X 0x%02X", data[pos], data[pos + 1]);
        // First byte is pin policy, second byte is touch policy
      }
      break;

    case 0x03: // Key origin
      if (length >= 1) {
        CNK_DEBUG("Key origin: 0x%02X", data[pos]);
        // This indicates how the key was generated (e.g., generated, imported)
      }
      break;

    case 0x04: // Public key encoding
      if (length > 0) {
        CNK_DEBUG("Public key data present, length: %lu bytes", length);

        /* Walk the TLVs inside the value --------------------------------- */
        CK_ULONG vpos = 0; /* cursor inside the value buffer   */
        while (vpos < length) {

          /* ---- read inner tag --------------------------------------- */
          CK_BYTE itag = data[pos + vpos++];
          if (vpos >= length)
            break; /* malformed */

          /* ---- read inner length (DER) ------------------------------ */
          CK_ULONG ilen = 0;
          CK_BYTE lbyte = data[pos + vpos++];
          if (lbyte <= 0x7F) {
            ilen = lbyte;
          } else if (lbyte == 0x81 && vpos < length) {
            ilen = data[pos + vpos++];
          } else if (lbyte == 0x82 && vpos + 1 < length) {
            ilen = ((CK_ULONG)data[pos + vpos] << 8) | (CK_ULONG)data[pos + vpos + 1];
            vpos += 2;
          } else {
            CNK_ERROR("Bad length in public‑key TLV");
            cnk_disconnect_card(hCard);
            return CKR_DEVICE_ERROR;
          }

          if (vpos + ilen > length) {
            CNK_ERROR("Truncated public‑key TLV");
            cnk_disconnect_card(hCard);
            return CKR_DEVICE_ERROR;
          }

          /* ---- RSA modulus lives in tag 0x81 ------------------------ */
          if (itag == 0x81) {
            /* Let the caller know how big it is … */
            if (modulus_len_ptr)
              *modulus_len_ptr = ilen;

            /* …and copy it if a buffer was supplied. ------------------ */
            if (modulus_ptr) {
              if (*modulus_len_ptr < ilen) {
                /* buffer too small – tell caller the size we need */
                cnk_disconnect_card(hCard);
                return CKR_BUFFER_TOO_SMALL;
              }
              memcpy(modulus_ptr, data + pos + vpos, ilen);
              CNK_DEBUG("Copied RSA modulus (%lu bytes)", ilen);
            }
            /* We found what we needed; no reason to parse further.     */
            break;
          }

          /* ---- ECC public point lives in tag 0x86 – ignore for now -- */
          vpos += ilen; /* advance to next inner TLV        */
        }
      }
      break;

    default:
      CNK_DEBUG("Unhandled metadata tag: 0x%02X, length: %lu", tag, length);
      break;
    }

    // Move to the next TLV
    pos += length;
  }

  // Disconnect from the card when done
  cnk_disconnect_card(hCard);
  return CKR_OK;
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
} VerifyPinContext;

// Card operation function for PIN verification
static CK_RV verify_pin_card_operation(SCARDHANDLE hCard, void *context) {
  VerifyPinContext *ctx = (VerifyPinContext *)context;

  CNK_ENSURE_NONNULL(ctx);
  CNK_ENSURE_NONNULL(ctx->session);

  // Verify the PIN
  CNK_ENSURE_OK(cnk_verify_piv_pin(hCard, ctx->pin, ctx->pin_len));

  // If PIN verification was successful, cache the PIN in the session
  if (ctx->session->piv_pin != ctx->pin) {
    // Store the PIN in the session
    memset(ctx->session->piv_pin, 0xFF, sizeof(ctx->session->piv_pin)); // Pad with 0xFF
    memcpy(ctx->session->piv_pin, ctx->pin, ctx->pin_len);
    ctx->session->piv_pin_len = ctx->pin_len;
  }

  CNK_RET_OK;
}

// Extended version of verify PIN with option to control card disconnection
CK_RV cnk_verify_piv_pin_with_session_ex(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_UTF8CHAR_PTR pPin,
                                         CK_ULONG ulPinLen, SCARDHANDLE *out_card) {
  if (session == NULL || (pPin == NULL && ulPinLen > 0)) {
    CNK_RETURN(CKR_ARGUMENTS_BAD, "Invalid arguments");
  }

  // PIN length must be between 1 and 8 characters
  if (ulPinLen < 1 || ulPinLen > 8) {
    CNK_RETURN(CKR_PIN_LEN_RANGE, "Invalid PIN length");
  }

  // Set up the context for the operation
  VerifyPinContext ctx = {.session = session, .pin = pPin, .pin_len = ulPinLen};

  // Use the card operation utility function
  return cnk_with_card(slotID, verify_pin_card_operation, &ctx, out_card);
}

// Verify the PIV PIN with session - handles card connection and caches PIN
CK_RV cnk_verify_piv_pin_with_session(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_UTF8CHAR_PTR pPin,
                                      CK_ULONG ulPinLen) {
  return cnk_verify_piv_pin_with_session_ex(slotID, session, pPin, ulPinLen, NULL);
}
