#include "pcsc_backend.h"
#include "logging.h"
#include "mbedtls/des.h"
#include "pkcs11.h"
#include "pkcs11_mutex.h"
#include "pkcs11_session.h"
#include "utils.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

// Global variables for reader management
ReaderInfo *g_cnk_readers = NULL; // Array of reader info structs
CK_LONG g_cnk_num_readers = 0;
CK_BBOOL g_cnk_is_initialized = CK_FALSE;
CNK_PKCS11_MUTEX g_cnk_readers_mutex;

// Function pointer type for card operations
typedef CK_RV (*CardOperationFunc)(SCARDHANDLE hCard, void *context);

// Utility function to handle card connection, operation, and disconnection
static CK_RV cnk_with_card(CK_SLOT_ID slotID, CardOperationFunc operation, void *context, SCARDHANDLE *out_card) {
  if (!operation)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "operation is NULL");

  SCARDHANDLE hCard;

  // Connect to card
  CK_RV rv = cnk_connect_and_select_canokey(slotID, &hCard);
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

// Helper function to check if a string contains 'canokey' (case-insensitive)
static CK_BBOOL contains_canokey(const char *str) { return str && ck_strcasestr(str, "canokey") ? CK_TRUE : CK_FALSE; }

CK_RV cnk_initialize_backend(void) {
  cnk_mutex_create(&g_cnk_readers_mutex);
  CNK_RET_OK;
}

// Initialize PC/SC context only
CK_RV cnk_initialize_pcsc(void) {
  if (g_cnk_is_initialized)
    CNK_RET_OK;

  LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &g_cnk_pcsc_context);
  if (rv != SCARD_S_SUCCESS) {
    CNK_ERROR("SCardEstablishContext failed with error: 0x%lx", rv);
    return CKR_DEVICE_ERROR;
  }

  g_cnk_is_initialized = CK_TRUE;

  CNK_RET_OK;
}

// List readers and populate g_cnk_readers
CK_RV cnk_list_readers(void) {
  CNK_LOG_FUNC();

  cnk_mutex_lock(&g_cnk_readers_mutex);
  if (!g_cnk_is_initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  // If readers are already listed, clean them up first
  if (g_cnk_readers) {
    for (CK_LONG i = 0; i < g_cnk_num_readers; i++) {
      ck_free(g_cnk_readers[i].name);
    }
    ck_free(g_cnk_readers);
    g_cnk_readers = NULL;
    g_cnk_num_readers = 0;
  }

  // Get the list of readers
  DWORD readers_len = 0;

  // First call to get the needed buffer size
  ULONG rv = SCardListReaders(g_cnk_pcsc_context, NULL, NULL, &readers_len);
  if (rv != (ULONG)SCARD_S_SUCCESS && rv != (ULONG)SCARD_E_INSUFFICIENT_BUFFER) {
    cnk_mutex_unlock(&g_cnk_readers_mutex);
    CNK_ERROR("SCardListReaders failed with error: 0x%lx", rv);
    return CKR_DEVICE_ERROR;
  }

  // Allocate memory for the readers list
  char *readers_buf = (char *)ck_malloc(readers_len);
  if (!readers_buf) {
    cnk_mutex_unlock(&g_cnk_readers_mutex);
    CNK_ERROR("Failed to allocate memory for readers list");
    return CKR_HOST_MEMORY;
  }

  // Get the actual readers list
  rv = SCardListReaders(g_cnk_pcsc_context, NULL, readers_buf, &readers_len);
  if (rv != SCARD_S_SUCCESS) {
    ck_free(readers_buf);
    cnk_mutex_unlock(&g_cnk_readers_mutex);
    CNK_ERROR("SCardListReaders failed with error: 0x%lx", rv);
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
  g_cnk_readers = (ReaderInfo *)ck_malloc(g_cnk_num_readers * sizeof(ReaderInfo));
  if (g_cnk_readers) {
    memset(g_cnk_readers, 0, g_cnk_num_readers * sizeof(ReaderInfo));
  }
  if (!g_cnk_readers) {
    ck_free(readers_buf);
    cnk_mutex_unlock(&g_cnk_readers_mutex);
    return CKR_HOST_MEMORY;
  }

  // Fill the reader list with readers containing 'canokey' and assign unique IDs
  reader = readers_buf;
  CK_LONG index = 0;
  while (*reader != '\0' && index < g_cnk_num_readers) {
    if (contains_canokey(reader)) {
      size_t name_len = strlen(reader) + 1;
      g_cnk_readers[index].name = (char *)ck_malloc(name_len);
      if (g_cnk_readers[index].name) {
        memcpy(g_cnk_readers[index].name, reader, name_len);
      }
      if (!g_cnk_readers[index].name) {
        // Clean up on error
        for (CK_LONG i = 0; i < index; i++) {
          ck_free(g_cnk_readers[i].name);
        }
        ck_free(g_cnk_readers);
        g_cnk_readers = NULL;
        g_cnk_num_readers = 0;
        ck_free(readers_buf);
        cnk_mutex_unlock(&g_cnk_readers_mutex);
        return CKR_HOST_MEMORY;
      }
      // Assign a unique ID to this reader (using index as the ID)
      g_cnk_readers[index].slot_id = index;
      index++;
    }
    reader += strlen(reader) + 1;
  }

  ck_free(readers_buf);
  cnk_mutex_unlock(&g_cnk_readers_mutex);
  return CKR_OK;
}

// Clean up PC/SC resources
void cnk_cleanup_pcsc(void) {
  cnk_mutex_lock(&g_cnk_readers_mutex);
  if (!g_cnk_is_initialized)
    return;

  if (g_cnk_readers) {
    for (CK_LONG i = 0; i < g_cnk_num_readers; i++) {
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
  cnk_mutex_unlock(&g_cnk_readers_mutex);
  cnk_mutex_destroy(&g_cnk_readers_mutex);
}

// Get the number of readers
CK_ULONG cnk_get_num_readers(void) {
  cnk_mutex_lock(&g_cnk_readers_mutex);
  CK_ULONG num = g_cnk_num_readers;
  cnk_mutex_unlock(&g_cnk_readers_mutex);
  return num;
}

// Get the slot ID for a reader at the given index
CK_SLOT_ID cnk_get_reader_slot_id(CK_ULONG index) {
  CK_SLOT_ID slot = (CK_SLOT_ID)-1;
  cnk_mutex_lock(&g_cnk_readers_mutex);
  if (index < (CK_ULONG)g_cnk_num_readers) {
    slot = g_cnk_readers[index].slot_id;
  }
  cnk_mutex_unlock(&g_cnk_readers_mutex);
  return slot;
}

// Helper function to connect to a card
CK_RV cnk_connect_and_select_canokey(CK_SLOT_ID slotID, SCARDHANDLE *phCard) {
  // In managed mode, use the provided card handle
  if (g_cnk_is_managed_mode) {
    *phCard = g_cnk_scard;

    // Begin transaction with default timeout of 2 seconds
    LONG rv = SCardBeginTransaction(*phCard);
    if (rv != SCARD_S_SUCCESS) {
      CNK_ERROR("SCardBeginTransaction failed with error: 0x%lx", rv);
      CNK_RETURN(CKR_DEVICE_ERROR, "SCardBeginTransaction failed");
    }

    CNK_RET_OK;
  }

  // Standalone mode - initialize PCSC if needed
  if (!g_cnk_is_initialized) {
    CK_RV rv = cnk_initialize_pcsc();
    if (rv != CKR_OK) {
      CNK_ERROR("Failed to initialize PCSC: 0x%lx", rv);
      CNK_RETURN(rv, "cnk_initialize_pcsc failed");
    }
  }

  // If readers haven't been listed yet, list them now
  if (g_cnk_num_readers == 0 || g_cnk_readers == NULL) {
    CK_RV rv = cnk_list_readers();
    if (rv != CKR_OK) {
      CNK_ERROR("Failed to list readers: 0x%lx", rv);
      CNK_RETURN(rv, "cnk_list_readers failed");
    }
  }

  if (g_cnk_readers == NULL) {
    CNK_ERROR("No readers found after listing");
    CNK_RETURN(CKR_SLOT_ID_INVALID, "No readers found");
  }

  // Find the reader corresponding to the slot ID
  CK_LONG i;
  for (i = 0; i < g_cnk_num_readers; i++) {
    if (g_cnk_readers[i].slot_id == slotID)
      break;
  }

  if (i >= g_cnk_num_readers) {
    CNK_RETURN(CKR_SLOT_ID_INVALID, "Invalid slot ID");
  }

  // Connect to the card
  DWORD active_protocol;
  LONG rv = SCardConnect(g_cnk_pcsc_context, g_cnk_readers[i].name, SCARD_SHARE_SHARED,
                         SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, phCard, &active_protocol);
  if (rv != SCARD_S_SUCCESS) {
    CNK_ERROR("SCardConnect failed with error: 0x%lx", rv);
    CNK_RETURN(CKR_DEVICE_ERROR, "SCardConnect failed");
  }

  // Begin transaction with default timeout of 2 seconds
  rv = SCardBeginTransaction(*phCard);
  if (rv != SCARD_S_SUCCESS) {
    SCardDisconnect(*phCard, SCARD_LEAVE_CARD);
    CNK_ERROR("SCardBeginTransaction failed with error: 0x%lx", rv);
    CNK_RETURN(CKR_DEVICE_ERROR, "SCardBeginTransaction failed");
  }

  // Note: We don't end the transaction here to allow for subsequent operations
  // The caller is responsible for calling cnk_disconnect_card when done

  CNK_RET_OK;
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
static LONG cnk_transceive_apdu(SCARDHANDLE hCard, const CK_BYTE *pCommand, CK_ULONG cbCommand, CK_BYTE *pResponse,
                                DWORD *pcbResponse, CK_BBOOL auto_get_response) {
  DWORD available = *pcbResponse;
  CNK_LOG_FUNC(": hCard = %p, pCommand = %p, cbCommand = %lu, pResponse = %p, available = %lu, auto_get_response = %d",
               hCard, pCommand, cbCommand, pResponse, available, auto_get_response);

  if (hCard == 0 || pCommand == NULL || pResponse == NULL || pcbResponse == NULL)
    CNK_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid arguments");

  // Log the APDU command
  CNK_LOG_APDU_COMMAND(pCommand, cbCommand);

  // Transmit the command
  LONG rv = SCardTransmit(hCard, SCARD_PCI_T1, pCommand, cbCommand, NULL, pResponse, pcbResponse);
  if (rv != SCARD_S_SUCCESS) {
    CNK_ERROR("SCardTransmit failed: 0x%lX", rv);
    return rv;
  }
  CNK_LOG_APDU_RESPONSE(pResponse, *pcbResponse);

  // If auto_get_response is false, return here
  if (!auto_get_response)
    CNK_RET_OK;

  // At least two status bytes are expected
  if (*pcbResponse < 2)
    CNK_RETURN(SCARD_E_UNEXPECTED, "Response too short for status bytes");

  // Get the data length and status bytes
  DWORD data_len = (*pcbResponse > 2) ? (*pcbResponse - 2) : 0;
  DWORD total_len = data_len;
  CK_BYTE sw1 = pResponse[*pcbResponse - 2];
  CK_BYTE sw2 = pResponse[*pcbResponse - 1];

  // If SW1=0x61, loop to send GET RESPONSE
  while (sw1 == 0x61) {
    // Prepare GET RESPONSE APDU: 00 C0 00 00 Le
    CK_BYTE get_resp_apdu[5] = {0x00, 0xC0, 0x00, 0x00, sw2};
    CNK_DEBUG("Auto GET RESPONSE for %u bytes", sw2);
    CNK_LOG_APDU_COMMAND(get_resp_apdu, sizeof(get_resp_apdu));

    // Temporary buffer to receive this GET RESPONSE response
    CK_BYTE temp[258];
    DWORD temp_len = sizeof(temp);
    rv = SCardTransmit(hCard, SCARD_PCI_T1, get_resp_apdu, sizeof(get_resp_apdu), NULL, temp, &temp_len);
    if (rv != SCARD_S_SUCCESS) {
      CNK_ERROR("GET RESPONSE failed: 0x%lX", rv);
      return rv;
    }
    CNK_LOG_APDU_RESPONSE(temp, temp_len);

    // Check length
    if (temp_len < 2) {
      CNK_ERROR("GET RESPONSE returned too short data");
      return SCARD_E_UNEXPECTED;
    }

    // Update status bytes
    sw1 = temp[temp_len - 2];
    sw2 = temp[temp_len - 1];

    // Calculate this chunk's data length (without status bytes)
    DWORD chunk_len = temp_len - 2;
    if (total_len + chunk_len > available) {
      CNK_ERROR("Response buffer overflow: need %lu, have %lu", total_len + chunk_len, available);
      return SCARD_E_INSUFFICIENT_BUFFER;
    }

    // Append this chunk's data to the main response buffer
    memcpy(pResponse + total_len, temp, chunk_len);
    total_len += chunk_len;
  }

  // Append status bytes
  pResponse[total_len++] = sw1;
  pResponse[total_len++] = sw2;

  // Update output length, only return data part (no status bytes)
  *pcbResponse = total_len;
  CNK_DEBUG("Total response length (data only): %lu bytes", total_len - 2);
  CNK_LOG_APDU_RESPONSE(pResponse, total_len);

  CNK_RET_OK;
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

  // Check status words
  if (sw1 == 0x90 && sw2 == 0x00) {
    CNK_RETURN(CKR_OK, "PIV PIN verified");
  }

  if (sw1 == 0x63) {
    // PIN verification failed, remaining attempts in low nibble of SW2
    CK_BYTE attempts = sw2 & 0x0F;
    if (pPinTries != NULL) {
      *pPinTries = attempts;
    }
    CNK_RETURN(CKR_PIN_INCORRECT, "PIV PIN verification failed");
  }

  if (sw1 == 0x69 && sw2 == 0x83) {
    // PIN blocked
    CNK_RETURN(CKR_PIN_LOCKED, "PIV PIN blocked");
  }

  CNK_RETURN(CKR_DEVICE_ERROR, "Failed to verify PIV PIN");
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

// Get PIV data from the CanoKey device
// If data is NULL, no data will be copied
// This function may return:
// - CKR_DATA_INVALID if the data object does not exist.
// - CKR_OK if the data object is successfully read.
// - CKR_DEVICE_ERROR if the data object could not be read.
CK_RV cnk_get_piv_data(CK_SLOT_ID slotID, CK_BYTE tag, CK_BYTE_PTR data, CK_ULONG_PTR data_len, CK_BBOOL fetch_data) {
  CNK_LOG_FUNC(": slotID: %ld, tag: 0x%02X, data: %p, data_len: %p, fetch_data: %d", slotID, tag, data, data_len,
               fetch_data);

  SCARDHANDLE hCard;

  if (data != NULL && data_len == NULL)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "data_len is NULL");
  CNK_ENSURE_OK(cnk_connect_and_select_canokey(slotID, &hCard));

  // Select the PIV application
  CK_RV rv = cnk_select_piv_application(hCard);
  if (rv != CKR_OK) {
    cnk_disconnect_card(hCard);
    CNK_RETURN(rv, "Failed to select PIV application");
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

  CK_BYTE apdu[11] = {0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, mapped_tag, 0x00};

  // Buffer to hold the response
  CK_BYTE response[4096];
  DWORD response_len = sizeof(response);

  // Send the GET DATA APDU
  LONG pcsc_rv = cnk_transceive_apdu(hCard, apdu, sizeof(apdu), response, &response_len, fetch_data);
  if (pcsc_rv != SCARD_S_SUCCESS) {
    CNK_ERROR("Failed to send GET DATA command: %ld", pcsc_rv);
    cnk_disconnect_card(hCard);
    return CKR_DEVICE_ERROR;
  }

  // Check if the command was successful
  if (response_len == 2 && response[0] == 0x6A && response[1] == 0x82) {
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DATA_INVALID, "PIV tag not found");
  }
  if (response_len < 2 || (fetch_data && (response[response_len - 2] != 0x90 || response[response_len - 1] != 0x00)) ||
      (!fetch_data && response[response_len - 2] != 0x61)) {
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "Failed to execute GET DATA command");
  }

  // Copy the response data (excluding status bytes) to the output buffer
  if (data != NULL) {
    if (*data_len < response_len - 2) {
      cnk_disconnect_card(hCard);
      CNK_RETURN(CKR_BUFFER_TOO_SMALL, "Output buffer too small");
    }
    memcpy(data, response, response_len - 2);
    *data_len = response_len - 2;
  }

  cnk_disconnect_card(hCard);
  CNK_RET_OK;
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

// Sign data using PIV key
// This function signs raw data using the PIV GENERAL AUTHENTICATE command
CK_RV cnk_piv_sign(CK_SLOT_ID slotId, CNK_PKCS11_SESSION *pSession, CK_BYTE_PTR pData, CK_ULONG cbDataLen,
                   CK_BYTE_PTR pSignature, CK_ULONG_PTR pcbSignature) {
  SCARDHANDLE hCard;

  // Check if we're just getting the signature length
  if (pSignature == NULL_PTR)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "pSignature is NULL");

  // Check if input data is too large (max 512 bytes for RSA 4096)
  if (cbDataLen > 512)
    CNK_RETURN(CKR_DATA_LEN_RANGE, "Input data too large (max 512 bytes)");

  // Verify PIN before signing
  if (pSession->cbPin == 0)
    CNK_RETURN(CKR_PIN_INCORRECT, "PIN verification required before signing");

  // Use the extended version to keep the card connection open
  CK_RV rv = cnk_verify_piv_pin_with_session_ex(slotId, pSession, pSession->pin, pSession->cbPin, NULL, &hCard);
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
  if (cbDataLen > 255) {
    // Use two-byte length encoding for lengths > 255
    tlv_data[tlv_len++] = 0x82;                               // Two-byte length marker
    tlv_data[tlv_len++] = (CK_BYTE)((cbDataLen >> 8) & 0xFF); // Length high byte
    tlv_data[tlv_len++] = (CK_BYTE)(cbDataLen & 0xFF);        // Length low byte
  } else {
    // Use one-byte length encoding for lengths <= 255
    tlv_data[tlv_len++] = (CK_BYTE)cbDataLen;
  }

  // Copy the raw input data
  memcpy(tlv_data + tlv_len, pData, cbDataLen);
  tlv_len += cbDataLen;

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

    tlv_len += 2; // Adjust total length for the extra length bytes
  } else {
    tlv_data[len_pos] = (CK_BYTE)(tlv_len - len_pos - 1);
  }

  // Build the GENERAL AUTHENTICATE APDU
  // Increased buffer size for Extended APDU (4 header + 3 Lc + ~1024 data + 3 Le)
  CK_BYTE abAuthApdu[1100];
  CK_ULONG cbAuthApdu = 0;

  // APDU header
  abAuthApdu[cbAuthApdu++] = 0x00;                                   // CLA
  abAuthApdu[cbAuthApdu++] = 0x87;                                   // INS - GENERAL AUTHENTICATE
  abAuthApdu[cbAuthApdu++] = pSession->signingContext.algorithmType; // P1 - Algorithm
  abAuthApdu[cbAuthApdu++] = pSession->signingContext.pivSlot;       // P2 - Key reference (PIV slot)

  // Handle Lc, Data, and Le based on APDU format and using the TLV data
  if (tlv_len <= 255) {
    // Standard APDU format
    abAuthApdu[cbAuthApdu++] = (CK_BYTE)tlv_len;        // Lc
    memcpy(abAuthApdu + cbAuthApdu, tlv_data, tlv_len); // Data
    cbAuthApdu += tlv_len;
    abAuthApdu[cbAuthApdu++] = 0x00; // Le (request max available)
  } else {
    // Extended APDU format
    abAuthApdu[cbAuthApdu++] = 0x00;                             // Extended length marker
    abAuthApdu[cbAuthApdu++] = (CK_BYTE)((tlv_len >> 8) & 0xFF); // Lc high byte
    abAuthApdu[cbAuthApdu++] = (CK_BYTE)(tlv_len & 0xFF);        // Lc low byte
    memcpy(abAuthApdu + cbAuthApdu, tlv_data, tlv_len);          // Data
    cbAuthApdu += tlv_len;
    abAuthApdu[cbAuthApdu++] = 0x00; // Le high byte (request max available)
    abAuthApdu[cbAuthApdu++] = 0x00; // Le low byte
  }

  // Send the GENERAL AUTHENTICATE command
  CK_BYTE response[1024];              // Increased buffer size for larger responses
  DWORD cbResponse = sizeof(response); // Use DWORD for PC/SC API compatibility

  CNK_DEBUG("Sending PIV GENERAL AUTHENTICATE command for signing");
  LONG pcsc_rv = cnk_transceive_apdu(hCard, abAuthApdu, cbAuthApdu, response, &cbResponse, CK_TRUE);

  if (pcsc_rv != SCARD_S_SUCCESS) {
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "Failed to send GENERAL AUTHENTICATE command");
  }

  // Check for success (9000) or more data available (61XX)
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

  // Find the signature data
  size_t offset = 0;

  // Skip the outer TLV header
  if (response[1] == 0x82) { // Extended length (2 bytes)
    offset = 4;              // Skip 7C 82 xx xx
  } else {
    offset = 2; // Skip 7C xx
  }

  // Check for the inner 82 tag (signature response)
  if (offset < cbResponse && response[offset] != 0x82) {
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "Invalid response format: missing 82 tag");
  }

  // Skip the inner TLV header
  offset++; // Skip the 82 tag

  // Handle the length field
  if (offset < cbResponse) {
    CK_LONG fail = 0;
    CK_ULONG bcLength = 0;
    tlvGetLengthSafe(&response[offset], cbResponse - offset, &fail, &bcLength);
    if (!fail) {
      offset += bcLength; // Skip length bytes
    } else {
      cnk_disconnect_card(hCard);
      *pcbSignature = 0;
      CNK_RETURN(CKR_DEVICE_ERROR, "Invalid response format: failed to parse length field");
    }
  }

  // Extract ECDSA signature components if needed
  size_t sig_len = cbResponse - offset;
  CNK_DEBUG("Raw signature length: %zu, buffer size: %zu", sig_len, *pcbSignature);

  // Check if this is an ECDSA signature
  CK_BYTE algorithmType = pSession->signingContext.algorithmType;
  if (algorithmType == PIV_ALG_ECC_256 || algorithmType == PIV_ALG_ECC_384) {
    // ECDSA signature is in DER format, convert to raw r||s format
    CNK_DEBUG("Converting ECDSA signature from DER to raw format");

    CK_ULONG ec_size = (algorithmType == PIV_ALG_ECC_256) ? 32 : 48; // P-256 = 32 bytes, P-384 = 48 bytes
    CK_ULONG expected_sig_size = ec_size * 2;                        // r || s

    // Check buffer size for raw signature
    if (expected_sig_size > *pcbSignature) {
      cnk_disconnect_card(hCard);
      *pcbSignature = expected_sig_size;
      CNK_RETURN(CKR_BUFFER_TOO_SMALL, "Signature buffer too small for raw ECDSA signature");
    }

    // Temp buffer for the raw signature
    CK_BYTE raw_sig[128] = {0}; // Max size for P-521 would be 132 bytes

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
    tlvGetLengthSafe(der_sig + der_pos, der_len - der_pos, &seq_len_fail, &seq_len_size);
    if (seq_len_fail) {
      cnk_disconnect_card(hCard);
      CNK_RETURN(CKR_DEVICE_ERROR, "Invalid ECDSA signature: couldn't parse SEQUENCE length");
    }
    der_pos += seq_len_size;

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
    if (r_len_fail) {
      cnk_disconnect_card(hCard);
      CNK_RETURN(CKR_DEVICE_ERROR, "Invalid ECDSA signature: couldn't parse r INTEGER length");
    }
    der_pos += r_len_size;

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
      // Truncate extra leading bytes (this shouldn't happen with valid signatures)
      memcpy(raw_sig, der_sig + der_pos + r_value_offset + (r_len - ec_size), ec_size);
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
    if (s_len_fail) {
      cnk_disconnect_card(hCard);
      CNK_RETURN(CKR_DEVICE_ERROR, "Invalid ECDSA signature: couldn't parse s INTEGER length");
    }
    der_pos += s_len_size;

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
      // Truncate extra leading bytes
      memcpy(raw_sig + ec_size, der_sig + der_pos + s_value_offset + (s_len - ec_size), ec_size);
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

CK_RV cnk_get_metadata(CK_SLOT_ID slotID, CK_BYTE pivTag, CK_BYTE_PTR pbAlgorithmType, CK_BYTE_PTR pbPublicKey,
                       CK_ULONG_PTR pulPublicKeyLen) {
  SCARDHANDLE hCard;

  CNK_ENSURE_NONNULL(pbAlgorithmType);

  // If modulus is requested, ensure the length pointer is provided
  if (pbPublicKey != NULL && pulPublicKeyLen == NULL)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "pulPublicKeyLen is NULL when pbPublicKey is provided");

  // Connect to the card for this operation
  CNK_ENSURE_OK(cnk_connect_and_select_canokey(slotID, &hCard));

  // Select the PIV application
  CK_RV rv = cnk_select_piv_application(hCard);
  if (rv != CKR_OK) {
    cnk_disconnect_card(hCard);
    return rv;
  }

  // Prepare the APDU for getting metadata
  // Command: 00 F7 00 XX 00 where XX is the PIV tag
  CK_BYTE metadata_apdu[] = {0x00, 0xF7, 0x00, pivTag, 0x00};

  // Buffer to hold the complete response (up to 1024 bytes)
  CK_BYTE response[1024];
  DWORD response_len = sizeof(response);

  // Send the metadata command
  CNK_DEBUG("Sending metadata command for PIV tag 0x%02X", pivTag);
  LONG pcsc_rv = cnk_transceive_apdu(hCard, metadata_apdu, sizeof(metadata_apdu), response, &response_len, CK_TRUE);
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
  if (sw1 != 0x90 || sw2 != 0x00) {
    CNK_ERROR("GET METADATA returned error status: %02X%02X", sw1, sw2);
    cnk_disconnect_card(hCard);
    CNK_RETURN(CKR_DEVICE_ERROR, "Failed to get metadata");
  }

  // Process the complete response data
  CK_ULONG data_len = response_len - 2;
  CK_BYTE *data = response;
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
      if (length == 1) {
        *pbAlgorithmType = data[pos];
        CNK_DEBUG("Algorithm type: 0x%02X", *pbAlgorithmType);
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
        memcpy(pbPublicKey, data + pos, length);
        *pulPublicKeyLen = length;
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
  CK_BYTE_PTR pin_tries;
} VerifyPinContext;

// Card operation function for PIN verification
static CK_RV verify_pin_card_operation(SCARDHANDLE hCard, void *context) {
  VerifyPinContext *ctx = (VerifyPinContext *)context;

  CNK_ENSURE_NONNULL(ctx);
  CNK_ENSURE_NONNULL(ctx->session);

  // Verify the PIN
  CNK_ENSURE_OK(cnk_verify_piv_pin(hCard, ctx->pin, ctx->pin_len, ctx->pin_tries));

  // If PIN verification was successful, cache the PIN in the session
  if (ctx->session->pin != ctx->pin) {
    // Store the PIN in the session
    memset(ctx->session->pin, 0xFF, sizeof(ctx->session->pin)); // Pad with 0xFF
    memcpy(ctx->session->pin, ctx->pin, ctx->pin_len);
    ctx->session->cbPin = ctx->pin_len;
  }

  CNK_RET_OK;
}

// Extended version of verify PIN with option to control card disconnection
CK_RV cnk_verify_piv_pin_with_session_ex(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_UTF8CHAR_PTR pPin,
                                         CK_ULONG ulPinLen, CK_BYTE_PTR pPinTries, SCARDHANDLE *out_card) {
  if (session == NULL || (pPin == NULL && ulPinLen > 0)) {
    CNK_RETURN(CKR_ARGUMENTS_BAD, "Invalid arguments");
  }

  // PIN length must be between 1 and 8 characters
  if (ulPinLen < 1 || ulPinLen > 8) {
    CNK_RETURN(CKR_PIN_LEN_RANGE, "Invalid PIN length");
  }

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

/* Verify the PIV management key by 3‑DES‑encrypting the card’s challenge
 * and sending the resulting host cryptogram back to the card.
 *
 * pKey  – 24‑byte raw management key.
 */
CK_RV cnkVerifyManagementKey(CNK_PKCS11_SESSION *session, CK_BYTE_PTR pKey) {
  SCARDHANDLE hCard;
  CK_BYTE capdu[32], rapdu[16], hostCryptogram[8];
  DWORD cbRapdu = sizeof(rapdu);
  CK_RV rv;
  LONG rvTransceive;
  mbedtls_des3_context ctx;
  int mbedtlsRet;

  // Connect to the card
  CNK_ENSURE_OK(cnk_connect_and_select_canokey(session->slotId, &hCard));

  // Select the PIV application
  rv = cnk_select_piv_application(hCard);
  if (rv != CKR_OK)
    goto cleanup;

  // Prepare the APDU for getting challenge
  // Command: 00 87 03 9B 04 7C 02 81 00
  memcpy(capdu, (CK_BYTE[]){0x00, 0x87, 0x03, 0x9B, 0x04, 0x7C, 0x02, 0x81, 0x00}, 9);

  // Send the GET CHALLENGE command
  rvTransceive = cnk_transceive_apdu(hCard, capdu, 9, rapdu, &cbRapdu, CK_TRUE);
  if (rvTransceive != SCARD_S_SUCCESS) {
    CNK_ERROR("Failed to get challenge, pc/sc error: %ld", rvTransceive);
    rv = CKR_DEVICE_ERROR;
    goto cleanup;
  }

  // Check if the command was successful
  if (cbRapdu != 14 || rapdu[cbRapdu - 2] != 0x90 || rapdu[cbRapdu - 1] != 0x00) {
    CNK_ERROR("Failed to get challenge, SW not OK");
    rv = CKR_DEVICE_ERROR;
    goto cleanup;
  }

  // Encrypt the challenge using the management key
  mbedtls_des3_init(&ctx);
  mbedtlsRet = mbedtls_des3_set3key_enc(&ctx, pKey);
  if (mbedtlsRet != 0) {
    mbedtls_des3_free(&ctx);
    CNK_RETURN(mbedtlsRet, "mbedtls_des3_set3key_enc() failed");
  }

  mbedtlsRet = mbedtls_des3_crypt_ecb(&ctx, rapdu + 4, hostCryptogram);
  mbedtls_des3_free(&ctx);
  if (mbedtlsRet != 0)
    CNK_RETURN(mbedtlsRet, "mbedtls_des3_crypt_ecb() failed");

  // Send the host cryptogram to the card
  // Prepare the APDU for authentication
  // Command: 00 87 03 9B 0C 7C 0A 82 08 <host_cryptogram>
  memcpy(capdu, (CK_BYTE[]){0x00, 0x87, 0x03, 0x9B, 0x0C, 0x7C, 0x0A, 0x82, 0x08}, 9);
  memcpy(capdu + 9, hostCryptogram, sizeof(hostCryptogram));

  // Check if the command was successful
  rvTransceive = cnk_transceive_apdu(hCard, capdu, 17, rapdu, &cbRapdu, CK_TRUE);
  if (rvTransceive != SCARD_S_SUCCESS) {
    CNK_ERROR("Failed to authenticate, pc/sc error: %ld", rvTransceive);
    rv = CKR_DEVICE_ERROR;
    goto cleanup;
  }

  // Check if the command was successful
  if (cbRapdu != 2 || rapdu[cbRapdu - 2] != 0x90 || rapdu[cbRapdu - 1] != 0x00) {
    CNK_ERROR("Failed to authenticate, SW not OK");
    rv = CKR_DEVICE_ERROR;
    goto cleanup;
  }

  // Authentication successful
  rv = CKR_OK;

cleanup:
  mbedtls_des3_free(&ctx);
  cnk_disconnect_card(hCard);
  CNK_RETURN(rv, "");
}
