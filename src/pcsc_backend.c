#include "pcsc_backend.h"
#include "pkcs11_managed.h"
#include "pkcs11_session.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Global variables for reader management
ReaderInfo *g_readers = NULL; // Array of reader info structs
CK_ULONG g_num_readers = 0;
CK_BBOOL g_is_initialized = CK_FALSE;

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
CK_RV initialize_pcsc() {
  if (g_is_initialized)
    return CKR_OK;

  LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &g_pcsc_context);
  if (rv != SCARD_S_SUCCESS) {
    return CKR_DEVICE_ERROR;
  }

  g_is_initialized = CK_TRUE;
  return CKR_OK;
}

// List readers and populate g_readers
CK_RV list_readers() {
  if (!g_is_initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  // If readers are already listed, clean them up first
  if (g_readers) {
    for (CK_ULONG i = 0; i < g_num_readers; i++) {
      ck_free(g_readers[i].name);
    }
    ck_free(g_readers);
    g_readers = NULL;
    g_num_readers = 0;
  }

  // Get the list of readers
  DWORD readers_len = 0;

  // First call to get the needed buffer size
  LONG rv = SCardListReaders(g_pcsc_context, NULL, NULL, &readers_len);
  if (rv != SCARD_S_SUCCESS && rv != SCARD_E_INSUFFICIENT_BUFFER) {
    return CKR_DEVICE_ERROR;
  }

  // Allocate memory for the readers list
  char *readers_buf = (char *)ck_malloc(readers_len);
  if (!readers_buf) {
    return CKR_HOST_MEMORY;
  }

  // Get the actual readers list
  rv = SCardListReaders(g_pcsc_context, NULL, readers_buf, &readers_len);
  if (rv != SCARD_S_SUCCESS) {
    ck_free(readers_buf);
    return CKR_DEVICE_ERROR;
  }

  // Count the number of readers with 'canokey' in their name
  g_num_readers = 0;
  char *reader = readers_buf;
  while (*reader != '\0') {
    if (contains_canokey(reader)) {
      g_num_readers++;
    }
    reader += strlen(reader) + 1;
  }

  // Allocate memory for the reader info array
  g_readers = ck_malloc(g_num_readers * sizeof(ReaderInfo));
  if (g_readers) {
    memset(g_readers, 0, g_num_readers * sizeof(ReaderInfo));
  }
  if (!g_readers) {
    ck_free(readers_buf);
    return CKR_HOST_MEMORY;
  }

  // Fill the reader list with readers containing 'canokey' and assign unique IDs
  reader = readers_buf;
  CK_ULONG index = 0;
  while (*reader != '\0' && index < g_num_readers) {
    if (contains_canokey(reader)) {
      size_t name_len = strlen(reader) + 1;
      g_readers[index].name = ck_malloc(name_len);
      if (g_readers[index].name) {
        memcpy(g_readers[index].name, reader, name_len);
      }
      if (!g_readers[index].name) {
        // Clean up on error
        for (CK_ULONG i = 0; i < index; i++) {
          ck_free(g_readers[i].name);
        }
        ck_free(g_readers);
        g_readers = NULL;
        g_num_readers = 0;
        ck_free(readers_buf);
        return CKR_HOST_MEMORY;
      }
      // Assign a unique ID to this reader (using index as the ID)
      g_readers[index].slot_id = index;
      index++;
    }
    reader += strlen(reader) + 1;
  }

  ck_free(readers_buf);
  return CKR_OK;
}

// Clean up PC/SC resources
void cleanup_pcsc() {
  if (!g_is_initialized)
    return;

  if (g_readers) {
    for (CK_ULONG i = 0; i < g_num_readers; i++) {
      ck_free(g_readers[i].name);
    }
    ck_free(g_readers);
    g_readers = NULL;
  }

  if (g_pcsc_context) {
    SCardReleaseContext(g_pcsc_context);
    g_pcsc_context = 0;
  }

  g_num_readers = 0;
  g_is_initialized = CK_FALSE;
}

// Get the number of readers
CK_ULONG get_num_readers(void) { return g_num_readers; }

// Get the slot ID for a reader at the given index
CK_SLOT_ID get_reader_slot_id(CK_ULONG index) {
  if (index >= g_num_readers) {
    return (CK_SLOT_ID)-1; // Invalid slot ID
  }
  return g_readers[index].slot_id;
}

// Helper function to connect to a card and select the CanoKey AID
CK_RV connect_and_select_canokey(CK_SLOT_ID slotID, SCARDHANDLE *phCard) {
  // In managed mode, use the provided card handle
  if (g_is_managed_mode) {
    *phCard = g_scard;

    // Begin transaction with default timeout of 2 seconds
    LONG rv = SCardBeginTransaction(*phCard);
    if (rv != SCARD_S_SUCCESS) {
      return CKR_DEVICE_ERROR;
    }

    return CKR_OK;
  }

  // Standalone mode - initialize PCSC if needed
  if (!g_is_initialized) {
    CK_RV rv = initialize_pcsc();
    if (rv != CKR_OK)
      return rv;
  }

  // If readers haven't been listed yet, list them now
  if (g_num_readers == 0 || g_readers == NULL) {
    CK_RV rv = list_readers();
    if (rv != CKR_OK)
      return rv;
  }

  // Find the reader corresponding to the slot ID
  CK_ULONG i;
  for (i = 0; i < g_num_readers; i++) {
    if (g_readers[i].slot_id == slotID)
      break;
  }

  if (i >= g_num_readers) {
    return CKR_SLOT_ID_INVALID;
  }

  // Connect to the card
  DWORD active_protocol;
  LONG rv = SCardConnect(g_pcsc_context, g_readers[i].name, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                         phCard, &active_protocol);
  if (rv != SCARD_S_SUCCESS) {
    return CKR_DEVICE_ERROR;
  }

  // Begin transaction with default timeout of 2 seconds
  rv = SCardBeginTransaction(*phCard);
  if (rv != SCARD_S_SUCCESS) {
    SCardDisconnect(*phCard, SCARD_LEAVE_CARD);
    return CKR_DEVICE_ERROR;
  }

  // Select the CanoKey AID: F000000000
  BYTE select_apdu[] = {0x00, 0xA4, 0x04, 0x00, 0x05, 0xF0, 0x00, 0x00, 0x00, 0x00};
  BYTE response[258];
  DWORD response_len = sizeof(response);

  rv = SCardTransmit(*phCard, SCARD_PCI_T1, select_apdu, sizeof(select_apdu), NULL, response, &response_len);
  if (rv != SCARD_S_SUCCESS) {
    disconnect_card(*phCard);
    return CKR_DEVICE_ERROR;
  }

  // Check if the select command was successful (SW1SW2 = 9000)
  if (response_len < 2 || response[response_len - 2] != 0x90 || response[response_len - 1] != 0x00) {
    disconnect_card(*phCard);
    return CKR_DEVICE_ERROR;
  }

  // Note: We don't end the transaction here to allow for subsequent operations
  // The caller is responsible for calling disconnect_card when done

  return CKR_OK;
}

// Disconnect from a card and end any active transaction
void disconnect_card(SCARDHANDLE hCard) {
  if (hCard == 0) {
    return;
  }

  // End transaction first
  SCardEndTransaction(hCard, SCARD_LEAVE_CARD);

  // In managed mode, don't disconnect the card
  if (g_is_managed_mode) {
    return;
  }

  // In standalone mode, disconnect the card
  SCardDisconnect(hCard, SCARD_LEAVE_CARD);
}

// PIV application functions

// Select the PIV application using AID A000000308
CK_RV select_piv_application(SCARDHANDLE hCard) {
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

  // Send the SELECT command
  LONG rv = SCardTransmit(hCard, SCARD_PCI_T1, select_apdu, sizeof(select_apdu), NULL, response, &response_len);

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
CK_RV verify_piv_pin(SCARDHANDLE hCard, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  if (hCard == 0 || pPin == NULL) {
    return CKR_ARGUMENTS_BAD;
  }

  // PIN length must be between 1 and 8 characters
  if (ulPinLen < 1 || ulPinLen > 8) {
    return CKR_PIN_LEN_RANGE;
  }

  // First select the PIV application
  CK_RV rv = select_piv_application(hCard);
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

  // Send the VERIFY command
  LONG pcsc_rv = SCardTransmit(hCard, SCARD_PCI_T1, verify_apdu, sizeof(verify_apdu), NULL, response, &response_len);

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
CK_RV logout_piv_pin(SCARDHANDLE hCard) {
  if (hCard == 0) {
    return CKR_DEVICE_ERROR;
  }

  // First select the PIV application
  CK_RV rv = select_piv_application(hCard);
  if (rv != CKR_OK) {
    return rv;
  }

  // Prepare the LOGOUT command: 00 20 FF 80 00
  BYTE logout_apdu[] = {0x00, 0x20, 0xFF, 0x80, 0x00};

  // Prepare response buffer
  BYTE response[258];
  DWORD response_len = sizeof(response);

  // Send the LOGOUT command
  LONG pcsc_rv = SCardTransmit(hCard, SCARD_PCI_T1, logout_apdu, sizeof(logout_apdu), NULL, response, &response_len);

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
CK_RV logout_piv_pin_with_session(CK_SLOT_ID slotID) {
  // Connect to the card
  SCARDHANDLE hCard;
  CK_RV rv = connect_and_select_canokey(slotID, &hCard);
  if (rv != CKR_OK) {
    return rv;
  }

  // Logout the PIN
  rv = logout_piv_pin(hCard);

  // Disconnect from the card
  disconnect_card(hCard);

  return rv;
}

// Verify the PIV PIN with session - handles card connection and caches PIN
CK_RV verify_piv_pin_with_session(CK_SLOT_ID slotID, PKCS11_SESSION *session, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  if (session == NULL || (pPin == NULL && ulPinLen > 0)) {
    return CKR_ARGUMENTS_BAD;
  }

  // PIN length must be between 1 and 8 characters
  if (ulPinLen < 1 || ulPinLen > 8) {
    return CKR_PIN_LEN_RANGE;
  }

  // Connect to the card
  SCARDHANDLE hCard;
  CK_RV rv = connect_and_select_canokey(slotID, &hCard);
  if (rv != CKR_OK) {
    return rv;
  }

  // Verify the PIN
  rv = verify_piv_pin(hCard, pPin, ulPinLen);

  // If PIN verification was successful, cache the PIN in the session
  if (rv == CKR_OK) {
    // Store the PIN in the session
    memset(session->piv_pin, 0xFF, sizeof(session->piv_pin)); // Pad with 0xFF
    memcpy(session->piv_pin, pPin, ulPinLen);
    session->piv_pin_len = ulPinLen;
  }

  // Disconnect from the card
  disconnect_card(hCard);

  return rv;
}

// Helper function to get firmware or hardware version
CK_RV get_version(CK_SLOT_ID slotID, CK_BYTE version_type, CK_BYTE *major, CK_BYTE *minor) {
  SCARDHANDLE hCard;

  // Connect to the card for this operation
  CK_RV rv = connect_and_select_canokey(slotID, &hCard);
  if (rv != CKR_OK) {
    return rv;
  }

  // Prepare the APDU for getting version
  BYTE version_apdu[] = {0x00, 0x31, version_type, 0x00, 0x00};
  BYTE response[258];
  DWORD response_len = sizeof(response);

  LONG pcsc_rv = SCardTransmit(hCard, SCARD_PCI_T1, version_apdu, sizeof(version_apdu), NULL, response, &response_len);
  if (pcsc_rv != SCARD_S_SUCCESS) {
    disconnect_card(hCard);
    return CKR_DEVICE_ERROR;
  }

  // Check if the command was successful and we got at least 5 bytes (3 version bytes + 2 status bytes)
  if (response_len < 5 || response[response_len - 2] != 0x90 || response[response_len - 1] != 0x00) {
    disconnect_card(hCard);
    return CKR_DEVICE_ERROR;
  }

  // Process hardware version if requested
  if (version_type == 0x01) {
    // Get hardware name from the device
    BYTE hw_name_apdu[] = {0x00, 0x32, 0x00, 0x00, 0x00};
    BYTE hw_name_response[258];
    DWORD hw_name_len = sizeof(hw_name_response);

    LONG pcsc_rv =
        SCardTransmit(hCard, SCARD_PCI_T1, hw_name_apdu, sizeof(hw_name_apdu), NULL, hw_name_response, &hw_name_len);
    if (pcsc_rv == SCARD_S_SUCCESS && hw_name_len > 2 && hw_name_response[hw_name_len - 2] == 0x90 &&
        hw_name_response[hw_name_len - 1] == 0x00) {

      // Convert hardware name to null-terminated string for easier processing
      char hw_name[256] = {0};
      size_t name_len = hw_name_len - 2; // Exclude status bytes
      if (name_len > 255)
        name_len = 255;
      memcpy(hw_name, hw_name_response, name_len);
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
      // Otherwise, set to 1.0
      else {
        *major = 1;
        *minor = 0;
      }
    } else {
      // If we can't get the hardware name, use default values
      *major = 1;
      *minor = 0;
    }
  }
  // Process firmware version if requested
  else if (version_type == 0x00) {
    // The response contains an ASCII encoded version string
    // Make sure it's null-terminated
    char version_str[16] = {0};
    size_t len = response_len - 2; // Exclude status bytes
    if (len > sizeof(version_str) - 1) {
      len = sizeof(version_str) - 1;
    }
    memcpy(version_str, response, len);
    version_str[len] = '\0';

    // Parse the version string (format: "X.Y.Z")
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
  }

  // Disconnect from the card when done
  disconnect_card(hCard);
  return CKR_OK;
}
