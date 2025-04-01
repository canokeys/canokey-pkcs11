#include "pcsc_backend.h"
#include "logging.h"
#include "pkcs11_session.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Global variables for reader management
ReaderInfo *g_cnk_readers = NULL; // Array of reader info structs
CK_ULONG g_cnk_num_readers = 0;
CK_BBOOL g_cnk_is_initialized = CK_FALSE;

// Helper function to check if a string contains 'canokey' (case insensitive)
static CK_BBOOL contains_canokey(const char *str) {
  if (!str)
    return CK_FALSE;

  // Convert to lowercase for case-insensitive comparison
  char *lowercase = strdup(str);
  if (!lowercase)
    return CK_FALSE;

  for (size_t i = 0; lowercase[i]; i++) {
    lowercase[i] = tolower(lowercase[i]);
  }

  CK_BBOOL result = (strstr(lowercase, "canokey") != NULL);
  free(lowercase);
  return result;
}

// Initialize PC/SC context only
CK_RV cnk_initialize_pcsc() {
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
CK_RV cnk_list_readers() {
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
  if (rv != SCARD_S_SUCCESS && rv != SCARD_E_INSUFFICIENT_BUFFER) {
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
void cnk_cleanup_pcsc() {
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
LONG transceive_apdu(SCARDHANDLE hCard, const BYTE *command, DWORD command_len, BYTE *response, DWORD *response_len) {
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
  if (hCard == 0) {
    return CKR_DEVICE_ERROR;
  }

  // PIV AID: A0 00 00 03 08
  BYTE piv_aid[] = {0xA0, 0x00, 0x00, 0x03, 0x08};
  BYTE select_apdu[11] = {0x00, 0xA4, 0x04, 0x00};

  // Set the length of the AID
  select_apdu[4] = sizeof(piv_aid);

  // Copy the AID into the APDU
  memcpy(select_apdu + 5, piv_aid, sizeof(piv_aid));

  // Prepare response buffer
  BYTE response[258];
  DWORD response_len = sizeof(response);

  // Send the SELECT command using the transceive function
  LONG rv = transceive_apdu(hCard, select_apdu, sizeof(select_apdu), response, &response_len);

  if (rv != SCARD_S_SUCCESS) {
    return CKR_DEVICE_ERROR;
  }

  // Check if the command was successful (status words 90 00)
  if (response_len < 2 || response[response_len - 2] != 0x90 || response[response_len - 1] != 0x00) {
    return CKR_DEVICE_ERROR;
  }

  return CKR_OK;
}

// Verify the PIV PIN
CK_RV cnk_verify_piv_pin(SCARDHANDLE hCard, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  if (hCard == 0 || pPin == NULL) {
    return CKR_ARGUMENTS_BAD;
  }

  // PIN length must be between 1 and 8 characters
  if (ulPinLen < 1 || ulPinLen > 8) {
    return CKR_PIN_LEN_RANGE;
  }

  // First select the PIV application
  CK_RV rv = cnk_select_piv_application(hCard);
  if (rv != CKR_OK) {
    return rv;
  }

  // Prepare the VERIFY command: 00 20 00 80 08 [PIN padded with 0xFF]
  BYTE verify_apdu[14] = {0x00, 0x20, 0x00, 0x80, 0x08};

  // Pad the PIN with 0xFF
  memset(verify_apdu + 5, 0xFF, 8);
  memcpy(verify_apdu + 5, pPin, ulPinLen);

  // Prepare response buffer
  BYTE response[258];
  DWORD response_len = sizeof(response);

  // Send the VERIFY command using the transceive function
  LONG pcsc_rv = transceive_apdu(hCard, verify_apdu, sizeof(verify_apdu), response, &response_len);

  if (pcsc_rv != SCARD_S_SUCCESS) {
    return CKR_DEVICE_ERROR;
  }

  // Check if the command was successful (status words 90 00)
  if (response_len < 2) {
    return CKR_DEVICE_ERROR;
  }

  // Check status words
  if (response[response_len - 2] == 0x90 && response[response_len - 1] == 0x00) {
    return CKR_OK;
  } else if (response[response_len - 2] == 0x63) {
    // PIN verification failed, remaining attempts in low nibble of SW2
    return CKR_PIN_INCORRECT;
  } else if (response[response_len - 2] == 0x69 && response[response_len - 1] == 0x83) {
    // PIN blocked
    return CKR_PIN_LOCKED;
  } else {
    return CKR_DEVICE_ERROR;
  }
}

// Logout PIV PIN using APDU 00 20 FF 80
CK_RV cnk_logout_piv_pin(SCARDHANDLE hCard) {
  if (hCard == 0) {
    return CKR_DEVICE_ERROR;
  }

  // First select the PIV application
  CK_RV rv = cnk_select_piv_application(hCard);
  if (rv != CKR_OK) {
    return rv;
  }

  // Prepare the LOGOUT command: 00 20 FF 80 00
  BYTE logout_apdu[] = {0x00, 0x20, 0xFF, 0x80, 0x00};

  // Prepare response buffer
  BYTE response[258];
  DWORD response_len = sizeof(response);

  // Send the LOGOUT command using the transceive function
  LONG pcsc_rv = transceive_apdu(hCard, logout_apdu, sizeof(logout_apdu), response, &response_len);

  if (pcsc_rv != SCARD_S_SUCCESS) {
    return CKR_DEVICE_ERROR;
  }

  // Check if the command was successful (status words 90 00)
  if (response_len < 2) {
    return CKR_DEVICE_ERROR;
  }

  // Check status words
  if (response[response_len - 2] == 0x90 && response[response_len - 1] == 0x00) {
    return CKR_OK;
  } else {
    return CKR_DEVICE_ERROR;
  }
}

// Logout PIV PIN with session - handles card connection
CK_RV cnk_logout_piv_pin_with_session(CK_SLOT_ID slotID) {
  // Connect to the card
  SCARDHANDLE hCard;
  CK_RV rv = cnk_connect_and_select_canokey(slotID, &hCard);
  if (rv != CKR_OK) {
    return rv;
  }

  // Logout the PIN
  rv = cnk_logout_piv_pin(hCard);

  // Disconnect from the card
  cnk_disconnect_card(hCard);

  return rv;
}

// Verify the PIV PIN with session - handles card connection and caches PIN
CK_RV cnk_verify_piv_pin_with_session(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_UTF8CHAR_PTR pPin,
                                      CK_ULONG ulPinLen) {
  if (session == NULL || (pPin == NULL && ulPinLen > 0)) {
    return CKR_ARGUMENTS_BAD;
  }

  // PIN length must be between 1 and 8 characters
  if (ulPinLen < 1 || ulPinLen > 8) {
    return CKR_PIN_LEN_RANGE;
  }

  // Connect to the card
  SCARDHANDLE hCard;
  CK_RV rv = cnk_connect_and_select_canokey(slotID, &hCard);
  if (rv != CKR_OK) {
    return rv;
  }

  // Verify the PIN
  rv = cnk_verify_piv_pin(hCard, pPin, ulPinLen);

  // If PIN verification was successful, cache the PIN in the session
  if (rv == CKR_OK) {
    // Store the PIN in the session
    memset(session->piv_pin, 0xFF, sizeof(session->piv_pin)); // Pad with 0xFF
    memcpy(session->piv_pin, pPin, ulPinLen);
    session->piv_pin_len = ulPinLen;
  }

  // Disconnect from the card
  cnk_disconnect_card(hCard);

  return rv;
}

// Get PIV data from the CanoKey device
// If fetch_data is CK_FALSE, only checks for existence and sets data_len to 1 if found, 0 if not
CK_RV cnk_get_piv_data(CK_SLOT_ID slotID, CK_BYTE tag, CK_BYTE_PTR *data, CK_ULONG_PTR data_len, CK_BBOOL fetch_data) {
  SCARDHANDLE hCard;
  CK_RV rv = cnk_connect_and_select_canokey(slotID, &hCard);
  if (rv != CKR_OK) {
    return rv;
  }

  // Select PIV application
  rv = cnk_select_piv_application(hCard);
  if (rv != CKR_OK) {
    cnk_disconnect_card(hCard);
    return rv;
  }

  // Prepare GET DATA APDU
  // Command: 00 CB 3F FF 05 5C 03 5F C1 xx 00
  // Where xx is mapped from the PIV tag as follows:
  // 9A -> 05, 9C -> 0A, 9D -> 0B, 9E -> 01, 82 -> 0D, 83 -> 0E
  BYTE mapped_tag;
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

  // If we're just checking for existence, we can use a smaller buffer
  BYTE response[fetch_data ? 4096 : 128]; // Smaller buffer if just checking existence
  DWORD response_len = sizeof(response);

  // For existence check, we can modify the APDU to only request the header
  // This is more efficient than fetching the entire content
  BYTE apdu[11] = {0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, mapped_tag, fetch_data ? 0x00 : 0x01};

  // Send the get PIV data command using the transceive function
  LONG pcsc_rv = transceive_apdu(hCard, apdu, sizeof(apdu), response, &response_len);

  if (pcsc_rv != SCARD_S_SUCCESS) {
    cnk_disconnect_card(hCard);
    return CKR_DEVICE_ERROR;
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
      BYTE sw1 = response[response_len - 2];
      BYTE sw2 = response[response_len - 1];

      // Prepare GET RESPONSE command
      BYTE get_response[5] = {0x00, 0xC0, 0x00, 0x00, sw2};

      // Get next chunk directly into the response buffer after the current data
      DWORD next_chunk_len = sizeof(response) - data_offset;

      // Send GET RESPONSE command
      pcsc_rv = transceive_apdu(hCard, get_response, sizeof(get_response), response + data_offset, &next_chunk_len);

      if (pcsc_rv != SCARD_S_SUCCESS) {
        cnk_disconnect_card(hCard);
        return CKR_DEVICE_ERROR;
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

  // Check if the response indicates success
  if (response_len < 2) {
    return CKR_DEVICE_ERROR;
  }

  // Success cases:
  // 1. SW1SW2 = 9000 (normal success)
  // 2. SW1 = 61 (more data available) when fetch_data is false (we only care about existence)
  if (response[response_len - 2] == 0x90 && response[response_len - 1] == 0x00) {
    // Normal success case - continue processing
  } else if (!fetch_data && response[response_len - 2] == 0x61) {
    // When not fetching data, 61XX means the object exists
    *data = NULL;
    *data_len = 1; // Indicates that the object exists
    return CKR_OK;
  } else if (response[response_len - 2] == 0x6A && response[response_len - 1] == 0x82) {
    // Object doesn't exist
    *data = NULL;
    *data_len = 0;
    return CKR_OK;
  } else {
    // Other error
    return CKR_DEVICE_ERROR;
  }

  if (fetch_data) {
    // Allocate memory for the data (excluding SW1SW2)
    *data_len = response_len - 2;
    *data = (CK_BYTE_PTR)ck_malloc(*data_len);
    if (*data == NULL) {
      return CKR_HOST_MEMORY;
    }

    // Copy the data (excluding SW1SW2)
    memcpy(*data, response, *data_len);
  } else {
    // For existence check, just set data_len to 1 to indicate existence
    // If a cert exists, then the corresponding public key and private key also exist
    *data = NULL;
    *data_len = 1; // Indicates that the object exists
  }

  return CKR_OK;
}

// Helper function to get firmware or hardware version
CK_RV cnk_get_version(CK_SLOT_ID slotID, CK_BYTE version_type, CK_BYTE *major, CK_BYTE *minor) {
  SCARDHANDLE hCard;

  // Connect to the card for this operation
  CK_RV rv = cnk_connect_and_select_canokey(slotID, &hCard);
  if (rv != CKR_OK) {
    return rv;
  }

  // Select the CanoKey AID: F000000000
  BYTE select_apdu[] = {0x00, 0xA4, 0x04, 0x00, 0x05, 0xF0, 0x00, 0x00, 0x00, 0x00};
  BYTE response[258];
  DWORD response_len = sizeof(response);

  // Use the transceive function to send the command and log both command and response
  rv = transceive_apdu(hCard, select_apdu, sizeof(select_apdu), response, &response_len);
  if (rv != SCARD_S_SUCCESS) {
    cnk_disconnect_card(hCard);
    return CKR_DEVICE_ERROR;
  }

  // Check if the select command was successful (SW1SW2 = 9000)
  if (response_len < 2 || response[response_len - 2] != 0x90 || response[response_len - 1] != 0x00) {
    cnk_disconnect_card(hCard);
    return CKR_DEVICE_ERROR;
  }

  // Prepare the APDU for getting version
  // 0x00 for firmware version, 0x01 for hardware version
  BYTE version_apdu[] = {0x00, 0x31, version_type, 0x00, 0x00};
  response_len = sizeof(response);

  // Send the version command using the transceive function
  LONG pcsc_rv = transceive_apdu(hCard, version_apdu, sizeof(version_apdu), response, &response_len);
  if (pcsc_rv != SCARD_S_SUCCESS) {
    cnk_disconnect_card(hCard);
    return CKR_DEVICE_ERROR;
  }

  // Check if the command was successful
  if (response_len < 2 || response[response_len - 2] != 0x90 || response[response_len - 1] != 0x00) {
    cnk_disconnect_card(hCard);
    return CKR_DEVICE_ERROR;
  }

  // Extract version information from the response
  if (version_type == 0x00) {
    // Firmware version - parse the version string (format: "X.Y.Z")
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
      *major = v_major;
      *minor = v_minor * 10 + v_patch;
    } else {
      // Fallback if parsing fails
      *major = 0;
      *minor = 0;
    }
  } else if (version_type == 0x01) {
    // Hardware version - the response contains hardware name
    // Convert hardware name to null-terminated string for easier processing
    char hw_name[256] = {0};
    size_t name_len = response_len - 2; // Exclude status bytes
    if (name_len > 255)
      name_len = 255;

    hw_name[name_len] = '\0';

    // Check if the hardware name contains "Canary"
    if (strstr(hw_name, "Canary") != NULL) {
      *major = 3;
      *minor = 0;
    }
    // Check if the hardware name contains "Pigeon"
    else if (strstr(hw_name, "Pigeon") != NULL) {
      *major = 2;
      *minor = 0;
    }
    // Otherwise, use 1.0
    else {
      *major = 1;
      *minor = 0;
    }
  } else {
    // Unknown version type
    *major = 0;
    *minor = 0;
  }

  // Disconnect from the card when done
  cnk_disconnect_card(hCard);
  return CKR_OK;
}
