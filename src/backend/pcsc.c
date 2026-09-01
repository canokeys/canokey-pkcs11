#include "backend/pcsc.h"
#include "api/session.h"
#include "internal/crypto.h"
#include "internal/des.h"
#include "internal/logging.h"
#include "internal/mutex.h"
#include "internal/util.h"
#include "pkcs11.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define CNK_PIV_MAX_PUBLIC_KEY_RESPONSE 4096
#define CNK_PIV_MAX_GENERAL_AUTH_INPUT 65520
#define CNK_PIV_MAX_GENERAL_AUTH_RESPONSE 4096
#define CNK_PIV_MAX_DATA_OBJECT_SIZE 8192

#define PIV_PADDED_PIN_LEN 8
#define PIV_ALG_TDEA 0x03
#define PIV_ALG_AES_192 0x0A
#define PIV_MANAGEMENT_KEY_SLOT 0x9B
#define PIV_MANAGEMENT_KEY_LEN 24
#define PIV_MAX_MANAGEMENT_CHALLENGE_LEN 16

// Global variables for reader management
ReaderInfo *g_cnk_readers = NULL; // Array of reader info structs
CK_LONG g_cnk_num_readers = 0;
CK_BBOOL g_cnk_is_initialized = CK_FALSE;
CNK_PKCS11_MUTEX g_cnk_readers_mutex;
static ReaderInfo *known_readers = NULL;
static CK_LONG known_reader_count = 0;
static CK_SLOT_ID next_reader_slot_id = 0;

static void freeScopedBuffer(CK_BYTE **buffer) {
  if (buffer != NULL && *buffer != NULL) {
    ck_free(*buffer);
    *buffer = NULL;
  }
}

// Reader indexes can change after PnP refresh. Keep a name-to-slot registry for
// the initialized lifetime so existing sessions and removal events stay stable.
static CK_RV getStableReaderSlot(const char *name, CK_SLOT_ID *slotId) {
  for (CK_LONG i = 0; i < known_reader_count; i++) {
    if (strcmp(known_readers[i].name, name) == 0) {
      *slotId = known_readers[i].slot_id;
      return CKR_OK;
    }
  }
  ReaderInfo *replacement = ck_calloc((size_t)known_reader_count + 1, sizeof(*replacement));
  if (replacement == NULL)
    return CKR_HOST_MEMORY;
  if (known_reader_count > 0)
    memcpy(replacement, known_readers, (size_t)known_reader_count * sizeof(*replacement));
  size_t nameLen = strlen(name) + 1;
  replacement[known_reader_count].name = ck_malloc(nameLen);
  if (replacement[known_reader_count].name == NULL) {
    ck_free(replacement);
    return CKR_HOST_MEMORY;
  }
  memcpy(replacement[known_reader_count].name, name, nameLen);
  replacement[known_reader_count].slot_id = next_reader_slot_id++;
  *slotId = replacement[known_reader_count].slot_id;
  ck_free(known_readers);
  known_readers = replacement;
  known_reader_count++;
  return CKR_OK;
}

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

static CK_RV connectForPrivateKeyOperation(CK_SLOT_ID slotId, CNK_PKCS11_SESSION *session, CK_BYTE pinPolicy,
                                           const CK_BYTE *contextPin, CK_ULONG contextPinLen, SCARDHANDLE *hCard,
                                           const char *operationName) {
  CNK_ENSURE_NONNULL(session, hCard);

  if (pinPolicy == CNK_PIV_PIN_POLICY_NEVER) {
    CNK_ENSURE_OK(cnk_connect_and_select_canokey(slotId, hCard));
    CK_RV rv = cnk_select_piv_application(*hCard);
    if (rv != CKR_OK) {
      cnk_disconnect_card(*hCard);
      *hCard = 0;
      return rv;
    }
    CNK_RET_OK;
  }

  if (pinPolicy == CNK_PIV_PIN_POLICY_ALWAYS) {
    if (contextPin == NULL || contextPinLen == 0)
      CNK_RETURN(CKR_USER_NOT_LOGGED_IN, "context-specific PIN verification required");
    CNK_ENSURE_OK(cnk_connect_and_select_canokey(slotId, hCard));
    CK_RV rv = cnk_select_piv_application(*hCard);
    if (rv == CKR_OK)
      rv = cnk_verify_piv_pin(*hCard, (CK_UTF8CHAR_PTR)contextPin, contextPinLen, NULL);
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
    CNK_RETURN(CKR_USER_NOT_LOGGED_IN, "PIN verification required before private-key operation");
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

// Helper function to check if a string contains 'canokey' (case-insensitive)
static CK_BBOOL contains_canokey(const char *str) { return str && ck_strcasestr(str, "canokey") ? CK_TRUE : CK_FALSE; }

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

static void cache_piv_pin(CNK_PKCS11_SESSION *session, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  cnk_token_cache_pin(session, pPin, ulPinLen);
}

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
    cnk_mutex_unlock(&g_cnk_readers_mutex);
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
  if (rv == (ULONG)SCARD_E_NO_READERS_AVAILABLE || (rv == (ULONG)SCARD_S_SUCCESS && readers_len == 0)) {
    cnk_mutex_unlock(&g_cnk_readers_mutex);
    return CKR_OK;
  }
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
  if (g_cnk_num_readers == 0) {
    ck_free(readers_buf);
    cnk_mutex_unlock(&g_cnk_readers_mutex);
    return CKR_OK;
  }

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
      CK_RV slotRv = getStableReaderSlot(reader, &g_cnk_readers[index].slot_id);
      if (slotRv != CKR_OK) {
        for (CK_LONG i = 0; i <= index; i++)
          ck_free(g_cnk_readers[i].name);
        ck_free(g_cnk_readers);
        g_cnk_readers = NULL;
        g_cnk_num_readers = 0;
        ck_free(readers_buf);
        cnk_mutex_unlock(&g_cnk_readers_mutex);
        return slotRv;
      }
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
  if (!g_cnk_is_initialized) {
    cnk_mutex_unlock(&g_cnk_readers_mutex);
    return;
  }

  if (g_cnk_readers) {
    for (CK_LONG i = 0; i < g_cnk_num_readers; i++) {
      ck_free(g_cnk_readers[i].name);
    }
    ck_free(g_cnk_readers);
    g_cnk_readers = NULL;
  }
  for (CK_LONG i = 0; i < known_reader_count; i++)
    ck_free(known_readers[i].name);
  ck_free(known_readers);
  known_readers = NULL;
  known_reader_count = 0;
  next_reader_slot_id = 0;

  if (g_cnk_pcsc_context) {
    // Wake a thread blocked in SCardGetStatusChange before releasing the
    // context that backs C_WaitForSlotEvent.
    SCardCancel(g_cnk_pcsc_context);
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

CK_RV cnk_wait_for_slot_event(CK_FLAGS flags, CK_SLOT_ID_PTR slot) {
  if (g_cnk_is_managed_mode)
    return CKR_FUNCTION_NOT_SUPPORTED;
  if (!g_cnk_is_initialized || g_cnk_pcsc_context == 0)
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  CNK_ENSURE_OK(cnk_list_readers());

  // Copy names and slot IDs because the global reader list may be refreshed by
  // a PnP notification while SCardGetStatusChange is blocked.
  cnk_mutex_lock(&g_cnk_readers_mutex);
  CK_ULONG readerCount = (CK_ULONG)g_cnk_num_readers;
  SCARD_READERSTATE *states = ck_calloc(readerCount + 1, sizeof(*states));
  CK_SLOT_ID *slotIds = ck_calloc(readerCount, sizeof(*slotIds));
  if (states == NULL || (readerCount > 0 && slotIds == NULL)) {
    ck_free(states);
    ck_free(slotIds);
    cnk_mutex_unlock(&g_cnk_readers_mutex);
    return CKR_HOST_MEMORY;
  }
  for (CK_ULONG i = 0; i < readerCount; i++) {
    size_t nameLen = strlen(g_cnk_readers[i].name) + 1;
    char *name = ck_malloc(nameLen);
    if (name == NULL) {
      for (CK_ULONG j = 0; j < i; j++)
        ck_free((void *)states[j].szReader);
      ck_free(states);
      ck_free(slotIds);
      cnk_mutex_unlock(&g_cnk_readers_mutex);
      return CKR_HOST_MEMORY;
    }
    memcpy(name, g_cnk_readers[i].name, nameLen);
    states[i].szReader = name;
    slotIds[i] = g_cnk_readers[i].slot_id;
  }
  // The PC/SC pseudo-reader reports reader arrival/removal even when there are
  // currently no CanoKey readers to place in the status array.
  states[readerCount].szReader = "\\\\?PnP?\\Notification";
  cnk_mutex_unlock(&g_cnk_readers_mutex);

  // The first zero-timeout call establishes a baseline. The second call then
  // reports only changes after this invocation, matching PKCS#11 wait semantics.
  LONG pcscRv = SCardGetStatusChange(g_cnk_pcsc_context, 0, states, readerCount + 1);
  if (pcscRv == SCARD_S_SUCCESS) {
    for (CK_ULONG i = 0; i <= readerCount; i++)
      states[i].dwCurrentState = states[i].dwEventState & ~SCARD_STATE_CHANGED;
    DWORD timeout = (flags & CKF_DONT_BLOCK) != 0 ? 0 : INFINITE;
    pcscRv = SCardGetStatusChange(g_cnk_pcsc_context, timeout, states, readerCount + 1);
  }

  CK_RV rv = CKR_NO_EVENT;
  if (pcscRv == SCARD_S_SUCCESS) {
    for (CK_ULONG i = 0; i < readerCount; i++) {
      if ((states[i].dwEventState & SCARD_STATE_CHANGED) != 0) {
        *slot = slotIds[i];
        rv = CKR_OK;
        break;
      }
    }
    if (rv == CKR_NO_EVENT && (states[readerCount].dwEventState & SCARD_STATE_CHANGED) != 0) {
      CK_RV refreshRv = cnk_list_readers();
      if (refreshRv == CKR_OK) {
        cnk_mutex_lock(&g_cnk_readers_mutex);
        // Report removals using the old stable slot, including removal of the
        // final reader. If nothing was removed, report the newly added reader.
        for (CK_ULONG i = 0; i < readerCount && rv == CKR_NO_EVENT; i++) {
          CK_BBOOL stillPresent = CK_FALSE;
          for (CK_LONG j = 0; j < g_cnk_num_readers; j++)
            if (strcmp(states[i].szReader, g_cnk_readers[j].name) == 0)
              stillPresent = CK_TRUE;
          if (!stillPresent) {
            *slot = slotIds[i];
            rv = CKR_OK;
          }
        }
        for (CK_LONG i = 0; i < g_cnk_num_readers && rv == CKR_NO_EVENT; i++) {
          CK_BBOOL wasPresent = CK_FALSE;
          for (CK_ULONG j = 0; j < readerCount; j++)
            if (strcmp(g_cnk_readers[i].name, states[j].szReader) == 0)
              wasPresent = CK_TRUE;
          if (!wasPresent) {
            *slot = g_cnk_readers[i].slot_id;
            rv = CKR_OK;
          }
        }
        cnk_mutex_unlock(&g_cnk_readers_mutex);
      }
    }
  } else if (pcscRv == SCARD_E_CANCELLED) {
    rv = g_cnk_is_initialized ? CKR_FUNCTION_CANCELED : CKR_CRYPTOKI_NOT_INITIALIZED;
  } else if (pcscRv != SCARD_E_TIMEOUT) {
    rv = CKR_DEVICE_ERROR;
  }

  for (CK_ULONG i = 0; i < readerCount; i++)
    ck_free((void *)states[i].szReader);
  ck_free(states);
  ck_free(slotIds);
  return rv;
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
LONG cnk_transceive_apdu(SCARDHANDLE hCard, const CK_BYTE *pCommand, CK_ULONG cbCommand, CK_BYTE *pResponse,
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

static CK_RV cnk_transmit_chained_apdu(SCARDHANDLE hCard, CK_BYTE ins, CK_BYTE p1, CK_BYTE p2, const CK_BYTE *data,
                                       CK_ULONG data_len, CK_BYTE *response, CK_ULONG_PTR response_len,
                                       CK_BBOOL request_le) {
  CNK_ENSURE_NONNULL(data);
  if (response != NULL)
    CNK_ENSURE_NONNULL(response_len);

  CK_ULONG offset = 0;
  LONG pcsc_rv = SCARD_S_SUCCESS;
  CK_BYTE local_response[258];
  CK_ULONG response_capacity = response != NULL ? *response_len : sizeof(local_response);

  do {
    CK_ULONG remaining = data_len - offset;
    CK_ULONG chunk_len = remaining > 0xFF ? 0xFF : remaining;
    CK_BBOOL has_more_chunks = remaining > chunk_len;
    CK_BYTE apdu[5 + 255 + 1];
    CK_ULONG apdu_len = 0;

    apdu[apdu_len++] = has_more_chunks ? 0x10 : 0x00;
    apdu[apdu_len++] = ins;
    apdu[apdu_len++] = p1;
    apdu[apdu_len++] = p2;
    apdu[apdu_len++] = (CK_BYTE)chunk_len;
    if (chunk_len > 0) {
      memcpy(apdu + apdu_len, data + offset, chunk_len);
      apdu_len += chunk_len;
    }
    if (!has_more_chunks && request_le)
      apdu[apdu_len++] = 0x00;

    CK_BYTE *response_buffer = !has_more_chunks && response != NULL ? response : local_response;
    DWORD cbResponse = !has_more_chunks && response != NULL ? (DWORD)response_capacity : sizeof(local_response);
    pcsc_rv = cnk_transceive_apdu(hCard, apdu, apdu_len, response_buffer, &cbResponse,
                                  has_more_chunks ? CK_FALSE : request_le);
    if (pcsc_rv != SCARD_S_SUCCESS)
      CNK_RETURN(CKR_DEVICE_ERROR, "failed to transmit APDU");
    if (cbResponse < 2)
      CNK_RETURN(CKR_DEVICE_ERROR, "APDU response too short");

    CK_BYTE sw1 = response_buffer[cbResponse - 2];
    CK_BYTE sw2 = response_buffer[cbResponse - 1];
    if (sw1 != 0x90 || sw2 != 0x00)
      CNK_RETURN(CKR_DEVICE_ERROR, "APDU command failed");

    offset += chunk_len;
    if (!has_more_chunks && response != NULL)
      *response_len = (CK_ULONG)cbResponse;
  } while (offset < data_len);

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

  CNK_ENSURE_OK(validate_piv_pin_len(ulPinLen));

  // First select the PIV application
  CK_RV rv = cnk_select_piv_application(hCard);
  if (rv != CKR_OK) {
    CNK_RETURN(rv, "Failed to select PIV application");
  }

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
    cnk_token_update_cached_pin(ctx->session, ctx->old_pin, ctx->old_pin_len, ctx->new_pin, ctx->new_pin_len);
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
    cache_piv_pin(ctx->session, ctx->new_pin, ctx->new_pin_len);
    cnk_mutex_lock(&ctx->session->token->lock);
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

  CK_BYTE response[CNK_PIV_MAX_DATA_OBJECT_SIZE];
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
  CNK_ENSURE_OK(cnk_connect_and_select_canokey(slotID, &hCard));

  CK_RV rv = cnk_select_piv_application(hCard);
  if (rv == CKR_OK)
    rv = cnk_get_piv_data_on_card(hCard, tag, tag_len, data, data_len, fetch_data);

  cnk_disconnect_card(hCard);
  CNK_RETURN(rv, "GET DATA");
}

CK_RV cnk_get_piv_data_by_tag_with_session(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, const CK_BYTE *tag,
                                           CK_ULONG tag_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len,
                                           CK_BBOOL fetch_data) {
  CNK_LOG_FUNC(": slotID: %ld, session: %p, tag: %p, tag_len: %lu, data: %p, data_len: %p, fetch_data: %d", slotID,
               session, tag, tag_len, data, data_len, fetch_data);

  CNK_ENSURE_NONNULL(session);
  SCARDHANDLE hCard = 0;

  CK_RV rv;
  CK_BYTE pin[PIV_PADDED_PIN_LEN];
  CK_ULONG pinLen = 0;
  if (cnk_token_copy_pin(session, pin, &pinLen) == CKR_OK) {
    rv = cnk_verify_piv_pin_with_session_ex(slotID, session, pin, pinLen, NULL, &hCard);
    mbedtls_platform_zeroize(pin, sizeof(pin));
  } else {
    rv = cnk_connect_and_select_canokey(slotID, &hCard);
    if (rv == CKR_OK)
      rv = cnk_select_piv_application(hCard);
  }
  if (rv == CKR_OK)
    rv = cnk_get_piv_data_on_card(hCard, tag, tag_len, data, data_len, fetch_data);

  cnk_disconnect_card(hCard);
  CNK_RETURN(rv, "GET DATA");
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

static CK_RV authenticateAdminForWrite(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, SCARDHANDLE *hCard) {
  CNK_ENSURE_NONNULL(session, hCard);

  CK_BYTE managementKey[PIV_MANAGEMENT_KEY_LEN] = {0};
  CK_BBOOL connected = CK_FALSE;
  *hCard = 0;
  CK_RV rv = cnk_token_copy_management_key(session, managementKey);
  if (rv != CKR_OK) {
    rv = CKR_USER_NOT_LOGGED_IN;
    goto cleanup;
  }
  rv = cnk_connect_and_select_canokey(slotID, hCard);
  if (rv != CKR_OK)
    goto cleanup;
  connected = CK_TRUE;
  rv = cnk_select_piv_application(*hCard);
  if (rv != CKR_OK)
    goto cleanup;
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
  CK_RV rv = authenticateAdminForWrite(slotID, session, &hCard);
  if (rv != CKR_OK)
    return rv;

  rv = cnk_transmit_chained_apdu(hCard, 0xDB, 0x3F, 0xFF, object_data, data_len + 2 + tag_len, NULL, NULL, CK_FALSE);
  cnk_disconnect_card(hCard);
  if (rv != CKR_OK)
    CNK_RETURN(rv, "PUT DATA");
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

  rv = connectForPrivateKeyOperation(slotId, pSession, pinPolicy, contextPin, contextPinLen, &hCard, operationName);
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
  } else {
    // Use one-byte length encoding for lengths <= 255
    tlv_data[tlv_len++] = (CK_BYTE)cbDataLen;
  }

  // Copy the raw input data
  if (cbDataLen > 0) {
    memcpy(tlv_data + tlv_len, pData, cbDataLen);
    tlv_len += cbDataLen;
  }

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
  // CanoKey rejects extended GENERAL AUTHENTICATE APDUs for RSA-sized data, so
  // large templates are sent with short APDU command chaining.
  CK_BYTE abAuthApdu[262];
  CK_ULONG cbAuthApdu = 0;

  CK_BYTE response[CNK_PIV_MAX_GENERAL_AUTH_RESPONSE];
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
  return cnk_piv_general_authenticate_raw(slotId, pSession, algorithmType, pivSlot, pinPolicy, 0x85, pPublicData,
                                          cbPublicData, pSharedSecret, pcbSharedSecret, NULL, 0, "ECDH");
}

CK_RV cnk_piv_mlkem_decapsulate(CK_SLOT_ID slotId, CNK_PKCS11_SESSION *pSession, CK_BYTE algorithmType, CK_BYTE pivSlot,
                                CK_BYTE pinPolicy, CK_BYTE_PTR pCiphertext, CK_ULONG cbCiphertext,
                                CK_BYTE_PTR pSharedSecret, CK_ULONG_PTR pcbSharedSecret) {
  return cnk_piv_general_authenticate_raw(slotId, pSession, algorithmType, pivSlot, pinPolicy, 0x81, pCiphertext,
                                          cbCiphertext, pSharedSecret, pcbSharedSecret, NULL, 0, "ML-KEM decapsulate");
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

  CK_RV rv = connectForPrivateKeyOperation(slotId, pSession, pSession->signingContext.pinPolicy,
                                           pSession->signingContext.contextPin, pSession->signingContext.contextPinLen,
                                           &hCard, "sign");
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
  if (algorithmType == PIV_ALG_ECC_256 || algorithmType == PIV_ALG_ECC_384 || algorithmType == PIV_ALG_ECC_521 ||
      algorithmType == PIV_ALG_SECP256K1) {
    // ECDSA signature is in DER format, convert to raw r||s format
    CNK_DEBUG("Converting ECDSA signature from DER to raw format");

    CK_ULONG ec_size = algorithmType == PIV_ALG_ECC_521 ? 66 : (algorithmType == PIV_ALG_ECC_384 ? 48 : 32);
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

  CK_RV rv = authenticateAdminForWrite(slotID, session, &hCard);
  if (rv != CKR_OK)
    return rv;

  rv = cnk_transmit_chained_apdu(hCard, 0x47, 0x00, pivSlot, data, data_len, response, &response_len, CK_TRUE);
  cnk_disconnect_card(hCard);
  if (rv != CKR_OK)
    CNK_RETURN(rv, "GENERATE ASYMMETRIC KEY PAIR");
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
  CK_RV rv = authenticateAdminForWrite(slotID, session, &hCard);
  if (rv != CKR_OK)
    return rv;

  rv = cnk_transmit_chained_apdu(hCard, 0xFE, algorithmType, pivSlot, keyData, keyDataLen, NULL, NULL, CK_FALSE);
  cnk_disconnect_card(hCard);
  if (rv != CKR_OK)
    CNK_RETURN(rv, "IMPORT ASYMMETRIC KEY");
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

  cache_piv_pin(ctx->session, ctx->pin, ctx->pin_len);

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

  // Connect to the card
  CNK_ENSURE_OK(cnk_connect_and_select_canokey(session->slotId, &hCard));

  // Select the PIV application
  rv = cnk_select_piv_application(hCard);
  if (rv != CKR_OK)
    goto cleanup;

  rv = authenticateManagementKeyOnCard(hCard, pKey);

cleanup:
  cnk_disconnect_card(hCard);
  CNK_RETURN(rv, "");
}
