#include "backend/pcsc.h"
#include "internal/logging.h"
#include "internal/mutex.h"
#include "internal/util.h"
#include "pkcs11.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sched.h>
#endif

#if defined(CNK_TEST_TRANSPORT)
static const CNK_PCSC_TEST_TRANSPORT *g_cnk_test_transport = NULL;

static LONG cnk_test_SCardEstablishContext(DWORD scope, LPCVOID reserved1, LPCVOID reserved2, LPSCARDCONTEXT context) {
  return g_cnk_test_transport != NULL && g_cnk_test_transport->establish_context != NULL
             ? g_cnk_test_transport->establish_context(scope, reserved1, reserved2, context)
             : SCardEstablishContext(scope, reserved1, reserved2, context);
}
static LONG cnk_test_SCardReleaseContext(SCARDCONTEXT context) {
  return g_cnk_test_transport != NULL && g_cnk_test_transport->release_context != NULL
             ? g_cnk_test_transport->release_context(context)
             : SCardReleaseContext(context);
}
static LONG cnk_test_SCardListReaders(SCARDCONTEXT context, LPCSTR groups, LPSTR readers, LPDWORD length) {
  return g_cnk_test_transport != NULL && g_cnk_test_transport->list_readers != NULL
             ? g_cnk_test_transport->list_readers(context, groups, readers, length)
             : SCardListReaders(context, groups, readers, length);
}
static LONG cnk_test_SCardConnect(SCARDCONTEXT context, LPCSTR reader, DWORD share, DWORD protocols, LPSCARDHANDLE card,
                                  LPDWORD activeProtocol) {
  return g_cnk_test_transport != NULL && g_cnk_test_transport->connect != NULL
             ? g_cnk_test_transport->connect(context, reader, share, protocols, card, activeProtocol)
             : SCardConnect(context, reader, share, protocols, card, activeProtocol);
}
static LONG cnk_test_SCardDisconnect(SCARDHANDLE card, DWORD disposition) {
  return g_cnk_test_transport != NULL && g_cnk_test_transport->disconnect != NULL
             ? g_cnk_test_transport->disconnect(card, disposition)
             : SCardDisconnect(card, disposition);
}
static LONG cnk_test_SCardBeginTransaction(SCARDHANDLE card) {
  return g_cnk_test_transport != NULL && g_cnk_test_transport->begin_transaction != NULL
             ? g_cnk_test_transport->begin_transaction(card)
             : SCardBeginTransaction(card);
}
static LONG cnk_test_SCardEndTransaction(SCARDHANDLE card, DWORD disposition) {
  return g_cnk_test_transport != NULL && g_cnk_test_transport->end_transaction != NULL
             ? g_cnk_test_transport->end_transaction(card, disposition)
             : SCardEndTransaction(card, disposition);
}
static LONG cnk_test_SCardTransmit(SCARDHANDLE card, LPCSCARD_IO_REQUEST sendPci, LPCBYTE sendBuffer, DWORD sendLength,
                                   LPSCARD_IO_REQUEST receivePci, LPBYTE receiveBuffer, LPDWORD receiveLength) {
  return g_cnk_test_transport != NULL && g_cnk_test_transport->transmit != NULL
             ? g_cnk_test_transport->transmit(card, sendPci, sendBuffer, sendLength, receivePci, receiveBuffer,
                                              receiveLength)
             : SCardTransmit(card, sendPci, sendBuffer, sendLength, receivePci, receiveBuffer, receiveLength);
}
static LONG cnk_test_SCardGetStatusChange(SCARDCONTEXT context, DWORD timeout, SCARD_READERSTATE *states, DWORD count) {
  return g_cnk_test_transport != NULL && g_cnk_test_transport->get_status_change != NULL
             ? g_cnk_test_transport->get_status_change(context, timeout, states, count)
             : SCardGetStatusChange(context, timeout, states, count);
}
static LONG cnk_test_SCardCancel(SCARDCONTEXT context) {
  return g_cnk_test_transport != NULL && g_cnk_test_transport->cancel != NULL ? g_cnk_test_transport->cancel(context)
                                                                              : SCardCancel(context);
}

#undef SCardEstablishContext
#undef SCardReleaseContext
#undef SCardListReaders
#undef SCardConnect
#undef SCardDisconnect
#undef SCardBeginTransaction
#undef SCardEndTransaction
#undef SCardTransmit
#undef SCardGetStatusChange
#undef SCardCancel
#define SCardEstablishContext cnk_test_SCardEstablishContext
#define SCardReleaseContext cnk_test_SCardReleaseContext
#define SCardListReaders cnk_test_SCardListReaders
#define SCardConnect cnk_test_SCardConnect
#define SCardDisconnect cnk_test_SCardDisconnect
#define SCardBeginTransaction cnk_test_SCardBeginTransaction
#define SCardEndTransaction cnk_test_SCardEndTransaction
#define SCardTransmit cnk_test_SCardTransmit
#define SCardGetStatusChange cnk_test_SCardGetStatusChange
#define SCardCancel cnk_test_SCardCancel

CK_RV cnk_pcsc_set_test_transport(const CNK_PCSC_TEST_TRANSPORT *transport) {
  g_cnk_test_transport = transport;
  return CKR_OK;
}
#endif

// Global variables for reader management
ReaderInfo *g_cnk_readers = NULL; // Array of reader info structs
CK_LONG g_cnk_num_readers = 0;
#if defined(CNK_TEST_EXPORT) && defined(_WIN32)
#define CNK_TEST_DATA_EXPORT __declspec(dllexport)
#else
#define CNK_TEST_DATA_EXPORT
#endif
CNK_TEST_DATA_EXPORT _Atomic CK_BBOOL g_cnk_is_initialized = CK_FALSE;
CNK_TEST_API _Atomic CK_ULONG g_cnk_pcsc_operations = 0;
CNK_PKCS11_MUTEX g_cnk_readers_mutex;
static ReaderInfo *known_readers = NULL;
static CK_LONG known_reader_count = 0;
static CK_SLOT_ID next_reader_slot_id = 0;

typedef struct {
  char *name;
  CK_SLOT_ID slotId;
  DWORD currentState;
} CNK_SLOT_EVENT_READER;

static CNK_PKCS11_MUTEX g_cnk_slot_event_mutex;
static CK_BBOOL backend_mutexes_initialized = CK_FALSE;
static CK_BBOOL readers_mutex_initialized = CK_FALSE;
static CK_BBOOL slot_event_mutex_initialized = CK_FALSE;
static CNK_SLOT_EVENT_READER *slot_event_readers = NULL;
static CK_ULONG slot_event_reader_count = 0;
static CK_BBOOL slot_event_initialized = CK_FALSE;
static DWORD slot_event_pnp_state = SCARD_STATE_UNAWARE;
static CK_SLOT_ID *pending_slot_events = NULL;
static CK_ULONG pending_slot_event_count = 0;
static CK_ULONG pending_slot_event_capacity = 0;

static void freeSlotEventReaders(CNK_SLOT_EVENT_READER *readers, CK_ULONG count);

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

// Helper function to check if a string contains 'canokey' (case-insensitive)
static CK_BBOOL contains_canokey(const char *str) { return str && ck_strcasestr(str, "canokey") ? CK_TRUE : CK_FALSE; }

CK_RV cnk_initialize_backend(void) {
  CNK_ENSURE_OK(cnk_mutex_create(&g_cnk_readers_mutex));
  readers_mutex_initialized = CK_TRUE;
  CK_RV rv = cnk_mutex_create(&g_cnk_slot_event_mutex);
  if (rv != CKR_OK) {
    CK_RV destroyRv = cnk_mutex_destroy(&g_cnk_readers_mutex);
    if (destroyRv == CKR_OK) {
      memset(&g_cnk_readers_mutex, 0, sizeof(g_cnk_readers_mutex));
      readers_mutex_initialized = CK_FALSE;
    }
    backend_mutexes_initialized = readers_mutex_initialized;
    return rv;
  }
  slot_event_mutex_initialized = CK_TRUE;
  backend_mutexes_initialized = CK_TRUE;
  CNK_RET_OK;
}

CK_RV cnk_cleanup_backend(void) {
  if (!backend_mutexes_initialized)
    return CKR_OK;
  CK_RV readersRv = CKR_OK;
  CK_RV eventRv = CKR_OK;
  if (readers_mutex_initialized) {
    readersRv = cnk_mutex_destroy(&g_cnk_readers_mutex);
    if (readersRv == CKR_OK) {
      memset(&g_cnk_readers_mutex, 0, sizeof(g_cnk_readers_mutex));
      readers_mutex_initialized = CK_FALSE;
    }
  }
  if (slot_event_mutex_initialized) {
    eventRv = cnk_mutex_destroy(&g_cnk_slot_event_mutex);
    if (eventRv == CKR_OK) {
      memset(&g_cnk_slot_event_mutex, 0, sizeof(g_cnk_slot_event_mutex));
      slot_event_mutex_initialized = CK_FALSE;
    }
  }
  // Keep failed mutex descriptors and their initialized markers so a later
  // C_Initialize/C_Finalize retry can invoke the destroy callback exactly once
  // more, without double-destroying a mutex that already succeeded.
  backend_mutexes_initialized = readers_mutex_initialized || slot_event_mutex_initialized;
  if (!backend_mutexes_initialized) {
    memset(&g_cnk_readers_mutex, 0, sizeof(g_cnk_readers_mutex));
    memset(&g_cnk_slot_event_mutex, 0, sizeof(g_cnk_slot_event_mutex));
  }
  return readersRv != CKR_OK ? readersRv : eventRv;
}

CK_RV cnk_slot_exists(CK_SLOT_ID slotID, CK_BBOOL *exists) {
  CNK_ENSURE_NONNULL(exists);
  *exists = CK_FALSE;
  if (g_cnk_is_managed_mode) {
    *exists = slotID == 0;
    return CKR_OK;
  }
  CNK_ENSURE_OK(cnk_mutex_lock(&g_cnk_readers_mutex));
  for (CK_LONG i = 0; i < g_cnk_num_readers; i++) {
    if (g_cnk_readers[i].slot_id == slotID) {
      *exists = CK_TRUE;
      break;
    }
  }
  cnk_mutex_unlock(&g_cnk_readers_mutex);
  return CKR_OK;
}

// Initialize PC/SC context only
CK_RV cnk_initialize_pcsc(void) {
  if (g_cnk_pcsc_context != 0)
    CNK_RET_OK;

  LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &g_cnk_pcsc_context);
  if (rv != SCARD_S_SUCCESS) {
    CNK_ERROR("SCardEstablishContext failed with error: 0x%lx", rv);
    return CKR_DEVICE_ERROR;
  }

  CNK_RET_OK;
}

// List readers and populate g_cnk_readers
CK_RV cnk_list_readers(void) {
  CNK_LOG_FUNC();

  CNK_ENSURE_OK(cnk_mutex_lock(&g_cnk_readers_mutex));
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
CK_RV cnk_cleanup_pcsc(void) {
  if (!backend_mutexes_initialized) {
    if (g_cnk_pcsc_context != 0) {
      SCardReleaseContext(g_cnk_pcsc_context);
      g_cnk_pcsc_context = 0;
    }
    return CKR_OK;
  }

  // Wake a blocked waiter before taking its serialization mutex.
  if (g_cnk_pcsc_context)
    SCardCancel(g_cnk_pcsc_context);
  CK_RV rv = cnk_mutex_lock(&g_cnk_slot_event_mutex);
  if (rv != CKR_OK) {
    CNK_ERROR("Failed to lock slot-event state during PC/SC cleanup");
    return rv;
  }
  rv = cnk_mutex_lock(&g_cnk_readers_mutex);
  if (rv != CKR_OK) {
    CNK_ERROR("Failed to lock reader state during PC/SC cleanup");
    cnk_mutex_unlock(&g_cnk_slot_event_mutex);
    return rv;
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
    SCardReleaseContext(g_cnk_pcsc_context);
    g_cnk_pcsc_context = 0;
  }

  g_cnk_num_readers = 0;
  atomic_store(&g_cnk_pcsc_operations, 0);
  freeSlotEventReaders(slot_event_readers, slot_event_reader_count);
  slot_event_readers = NULL;
  slot_event_reader_count = 0;
  slot_event_initialized = CK_FALSE;
  slot_event_pnp_state = SCARD_STATE_UNAWARE;
  ck_free(pending_slot_events);
  pending_slot_events = NULL;
  pending_slot_event_count = 0;
  pending_slot_event_capacity = 0;
  cnk_mutex_unlock(&g_cnk_readers_mutex);
  cnk_mutex_unlock(&g_cnk_slot_event_mutex);
  return CKR_OK;
}

CK_RV cnk_wait_for_pcsc_operations(void) {
  // Finalization disables new API admission before reaching this barrier.
  // Existing card calls keep the count until cnk_disconnect_card completes,
  // so releasing the PC/SC context cannot race an in-flight SCardTransmit.
  while (atomic_load(&g_cnk_pcsc_operations) != 0) {
#ifdef _WIN32
    Sleep(0);
#else
    sched_yield();
#endif
  }
  return CKR_OK;
}

void cnk_pcsc_operation_end(void) {
  CK_ULONG count = atomic_load(&g_cnk_pcsc_operations);
  while (count != 0 && !atomic_compare_exchange_weak(&g_cnk_pcsc_operations, &count, count - 1))
    ;
}

CK_RV cnk_pcsc_operation_begin(void) {
  // Pair the counter with the initialized admission flag. If finalization
  // wins before the increment, the second check removes the provisional
  // count without touching the PC/SC context. If it wins afterward, finalize
  // observes the count and waits for this operation.
  if (!g_cnk_is_initialized)
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  atomic_fetch_add(&g_cnk_pcsc_operations, 1);
  if (!g_cnk_is_initialized) {
    cnk_pcsc_operation_end();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  return CKR_OK;
}

static void release_pcsc_operation_guard(CK_BBOOL *active) {
  if (active != NULL && *active)
    cnk_pcsc_operation_end();
}

CNK_TEST_API void cnk_cancel_pcsc_operations(void) {
  if (g_cnk_pcsc_context != 0)
    SCardCancel(g_cnk_pcsc_context);
}

static void freeSlotEventReaders(CNK_SLOT_EVENT_READER *readers, CK_ULONG count) {
  if (readers != NULL) {
    for (CK_ULONG i = 0; i < count; i++)
      ck_free(readers[i].name);
    ck_free(readers);
  }
}

static CK_RV ensurePendingSlotEventCapacity(CK_ULONG additional) {
  CK_ULONG required = pending_slot_event_count + additional;
  if (required <= pending_slot_event_capacity)
    return CKR_OK;
  CK_ULONG capacity = pending_slot_event_capacity == 0 ? 8 : pending_slot_event_capacity;
  while (capacity < required)
    capacity *= 2;
  CK_SLOT_ID *replacement = ck_malloc(capacity * sizeof(*replacement));
  if (replacement == NULL)
    return CKR_HOST_MEMORY;
  if (pending_slot_event_count > 0)
    memcpy(replacement, pending_slot_events, pending_slot_event_count * sizeof(*replacement));
  ck_free(pending_slot_events);
  pending_slot_events = replacement;
  pending_slot_event_capacity = capacity;
  return CKR_OK;
}

static CK_RV enqueueSlotEvent(CK_SLOT_ID slotId) {
  CNK_ENSURE_OK(ensurePendingSlotEventCapacity(1));
  pending_slot_events[pending_slot_event_count++] = slotId;
  return CKR_OK;
}

static CK_BBOOL popSlotEvent(CK_SLOT_ID_PTR slot) {
  if (pending_slot_event_count == 0)
    return CK_FALSE;
  *slot = pending_slot_events[0];
  pending_slot_event_count--;
  if (pending_slot_event_count > 0)
    memmove(pending_slot_events, pending_slot_events + 1, pending_slot_event_count * sizeof(*pending_slot_events));
  return CK_TRUE;
}

static CK_LONG findSlotEventReaderByName(const CNK_SLOT_EVENT_READER *readers, CK_ULONG count, const char *name) {
  for (CK_ULONG i = 0; i < count; i++)
    if (strcmp(readers[i].name, name) == 0)
      return (CK_LONG)i;
  return -1;
}

// Refresh the persistent logical reader snapshot. Existing entries retain
// their PC/SC baseline; additions and removals are queued by stable slot ID.
static CK_RV refreshSlotEventReaders(CK_BBOOL queueChanges) {
  CNK_ENSURE_OK(cnk_list_readers());
  CNK_ENSURE_OK(cnk_mutex_lock(&g_cnk_readers_mutex));
  CK_ULONG newCount = (CK_ULONG)g_cnk_num_readers;
  CNK_SLOT_EVENT_READER *replacement = ck_calloc(newCount, sizeof(*replacement));
  if (newCount > 0 && replacement == NULL) {
    cnk_mutex_unlock(&g_cnk_readers_mutex);
    return CKR_HOST_MEMORY;
  }
  for (CK_ULONG i = 0; i < newCount; i++) {
    size_t nameLen = strlen(g_cnk_readers[i].name) + 1;
    replacement[i].name = ck_malloc(nameLen);
    if (replacement[i].name == NULL) {
      freeSlotEventReaders(replacement, newCount);
      cnk_mutex_unlock(&g_cnk_readers_mutex);
      return CKR_HOST_MEMORY;
    }
    memcpy(replacement[i].name, g_cnk_readers[i].name, nameLen);
    replacement[i].slotId = g_cnk_readers[i].slot_id;
    replacement[i].currentState = SCARD_STATE_UNAWARE;
    CK_LONG oldIndex = findSlotEventReaderByName(slot_event_readers, slot_event_reader_count, replacement[i].name);
    if (oldIndex >= 0)
      replacement[i].currentState = slot_event_readers[oldIndex].currentState;
  }
  cnk_mutex_unlock(&g_cnk_readers_mutex);

  if (queueChanges) {
    CK_RV capacityRv = ensurePendingSlotEventCapacity(slot_event_reader_count + newCount);
    if (capacityRv != CKR_OK) {
      freeSlotEventReaders(replacement, newCount);
      return capacityRv;
    }
    for (CK_ULONG i = 0; i < slot_event_reader_count; i++)
      if (findSlotEventReaderByName(replacement, newCount, slot_event_readers[i].name) < 0)
        pending_slot_events[pending_slot_event_count++] = slot_event_readers[i].slotId;
    for (CK_ULONG i = 0; i < newCount; i++)
      if (findSlotEventReaderByName(slot_event_readers, slot_event_reader_count, replacement[i].name) < 0)
        pending_slot_events[pending_slot_event_count++] = replacement[i].slotId;
  }

  freeSlotEventReaders(slot_event_readers, slot_event_reader_count);
  slot_event_readers = replacement;
  slot_event_reader_count = newCount;
  return CKR_OK;
}

static CK_RV buildSlotEventStates(SCARD_READERSTATE **statesOut, CK_SLOT_ID **slotIdsOut) {
  CK_ULONG stateCount = slot_event_reader_count + 1;
  SCARD_READERSTATE *states = ck_calloc(stateCount, sizeof(*states));
  CK_SLOT_ID *slotIds = ck_calloc(slot_event_reader_count, sizeof(*slotIds));
  if (states == NULL || (slot_event_reader_count > 0 && slotIds == NULL)) {
    ck_free(states);
    ck_free(slotIds);
    return CKR_HOST_MEMORY;
  }
  for (CK_ULONG i = 0; i < slot_event_reader_count; i++) {
    size_t nameLen = strlen(slot_event_readers[i].name) + 1;
    char *name = ck_malloc(nameLen);
    if (name == NULL) {
      for (CK_ULONG j = 0; j < i; j++)
        ck_free((void *)states[j].szReader);
      ck_free(states);
      ck_free(slotIds);
      return CKR_HOST_MEMORY;
    }
    memcpy(name, slot_event_readers[i].name, nameLen);
    states[i].szReader = name;
    states[i].dwCurrentState = slot_event_readers[i].currentState;
    slotIds[i] = slot_event_readers[i].slotId;
  }
  states[slot_event_reader_count].szReader = "\\\\?PnP?\\Notification";
  states[slot_event_reader_count].dwCurrentState = slot_event_pnp_state;
  *statesOut = states;
  *slotIdsOut = slotIds;
  return CKR_OK;
}

static void freeSlotEventStates(SCARD_READERSTATE *states, CK_SLOT_ID *slotIds, CK_ULONG readerCount) {
  if (states != NULL)
    for (CK_ULONG i = 0; i < readerCount; i++)
      ck_free((void *)states[i].szReader);
  ck_free(states);
  ck_free(slotIds);
}

static CK_RV establishSlotEventBaseline(void) {
  SCARD_READERSTATE *states = NULL;
  CK_SLOT_ID *slotIds = NULL;
  CNK_ENSURE_OK(buildSlotEventStates(&states, &slotIds));
  LONG pcscRv = SCardGetStatusChange(g_cnk_pcsc_context, 0, states, slot_event_reader_count + 1);
  if (pcscRv == SCARD_S_SUCCESS) {
    for (CK_ULONG i = 0; i < slot_event_reader_count; i++)
      slot_event_readers[i].currentState = states[i].dwEventState & ~SCARD_STATE_CHANGED;
    slot_event_pnp_state = states[slot_event_reader_count].dwEventState & ~SCARD_STATE_CHANGED;
  }
  freeSlotEventStates(states, slotIds, slot_event_reader_count);
  return pcscRv == SCARD_S_SUCCESS || pcscRv == SCARD_E_TIMEOUT ? CKR_OK : CKR_DEVICE_ERROR;
}

static CK_RV synchronizeSlotEventReadersAfterPnp(void) {
  // Newly added readers start at UNAWARE, while the PnP state remains the one
  // that woke the waiter. Re-query until PnP is stable: reader states are
  // baselined without duplicate events, and a second PnP transition is diffed
  // rather than absorbed between calls.
  for (;;) {
    CK_ULONG readerCount = slot_event_reader_count;
    SCARD_READERSTATE *states = NULL;
    CK_SLOT_ID *slotIds = NULL;
    CNK_ENSURE_OK(buildSlotEventStates(&states, &slotIds));
    LONG pcscRv = SCardGetStatusChange(g_cnk_pcsc_context, 0, states, readerCount + 1);
    if (pcscRv != SCARD_S_SUCCESS && pcscRv != SCARD_E_TIMEOUT) {
      freeSlotEventStates(states, slotIds, readerCount);
      return CKR_DEVICE_ERROR;
    }
    if (pcscRv == SCARD_E_TIMEOUT) {
      freeSlotEventStates(states, slotIds, readerCount);
      return CKR_OK;
    }
    for (CK_ULONG i = 0; i < readerCount; i++) {
      CK_LONG index = findSlotEventReaderByName(slot_event_readers, slot_event_reader_count, states[i].szReader);
      if (index >= 0)
        slot_event_readers[index].currentState = states[i].dwEventState & ~SCARD_STATE_CHANGED;
    }
    CK_BBOOL pnpChanged = (states[readerCount].dwEventState & SCARD_STATE_CHANGED) != 0;
    slot_event_pnp_state = states[readerCount].dwEventState & ~SCARD_STATE_CHANGED;
    freeSlotEventStates(states, slotIds, readerCount);
    if (!pnpChanged)
      return CKR_OK;
    CNK_ENSURE_OK(refreshSlotEventReaders(CK_TRUE));
  }
}

CK_RV cnk_wait_for_slot_event(CK_FLAGS flags, CK_SLOT_ID_PTR slot) {
  if (g_cnk_is_managed_mode)
    return CKR_FUNCTION_NOT_SUPPORTED;
  if (!g_cnk_is_initialized || g_cnk_pcsc_context == 0)
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  CNK_PKCS11_MUTEX_GUARD eventLock CNK_MUTEX_GUARD = {.mutex = &g_cnk_slot_event_mutex};
  CNK_ENSURE_OK(cnk_mutex_lock_guard(&eventLock));
  if (popSlotEvent(slot))
    return CKR_OK;

  if (!slot_event_initialized) {
    CNK_ENSURE_OK(refreshSlotEventReaders(CK_FALSE));
    CNK_ENSURE_OK(establishSlotEventBaseline());
    slot_event_initialized = CK_TRUE;
    if ((flags & CKF_DONT_BLOCK) != 0)
      return CKR_NO_EVENT;
  }

  for (;;) {
    CK_ULONG oldReaderCount = slot_event_reader_count;
    SCARD_READERSTATE *states = NULL;
    CK_SLOT_ID *slotIds = NULL;
    CNK_ENSURE_OK(buildSlotEventStates(&states, &slotIds));
    DWORD timeout = (flags & CKF_DONT_BLOCK) != 0 ? 0 : INFINITE;
    LONG pcscRv = SCardGetStatusChange(g_cnk_pcsc_context, timeout, states, oldReaderCount + 1);
    if (pcscRv == SCARD_E_TIMEOUT) {
      freeSlotEventStates(states, slotIds, oldReaderCount);
      return CKR_NO_EVENT;
    }
    if (pcscRv == SCARD_E_CANCELLED) {
      freeSlotEventStates(states, slotIds, oldReaderCount);
      return g_cnk_is_initialized ? CKR_FUNCTION_CANCELED : CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pcscRv != SCARD_S_SUCCESS) {
      freeSlotEventStates(states, slotIds, oldReaderCount);
      return CKR_DEVICE_ERROR;
    }

    CK_BBOOL pnpChanged = (states[oldReaderCount].dwEventState & SCARD_STATE_CHANGED) != 0;
    CK_RV rv = CKR_OK;
    for (CK_ULONG i = 0; i < oldReaderCount; i++) {
      CK_LONG snapshotIndex =
          findSlotEventReaderByName(slot_event_readers, slot_event_reader_count, states[i].szReader);
      if (snapshotIndex >= 0)
        slot_event_readers[snapshotIndex].currentState = states[i].dwEventState & ~SCARD_STATE_CHANGED;
      if ((states[i].dwEventState & SCARD_STATE_CHANGED) != 0 && !pnpChanged && rv == CKR_OK)
        rv = enqueueSlotEvent(slotIds[i]);
    }
    slot_event_pnp_state = states[oldReaderCount].dwEventState & ~SCARD_STATE_CHANGED;

    if (pnpChanged) {
      if (rv == CKR_OK)
        rv = refreshSlotEventReaders(CK_TRUE);
      // Reader arrival/removal is already queued. Establish state for new
      // names without absorbing another PnP transition.
      if (rv == CKR_OK)
        rv = synchronizeSlotEventReadersAfterPnp();
      for (CK_ULONG i = 0; i < oldReaderCount && rv == CKR_OK; i++) {
        if ((states[i].dwEventState & SCARD_STATE_CHANGED) == 0)
          continue;
        CK_BBOOL stillPresent = CK_FALSE;
        rv = cnk_slot_exists(slotIds[i], &stillPresent);
        if (rv == CKR_OK && stillPresent)
          rv = enqueueSlotEvent(slotIds[i]);
      }
    }
    freeSlotEventStates(states, slotIds, oldReaderCount);
    if (rv != CKR_OK)
      return rv;

    if (popSlotEvent(slot))
      return CKR_OK;
    if ((flags & CKF_DONT_BLOCK) != 0)
      return CKR_NO_EVENT;
  }
}

// Begin a PC/SC transaction. This helper deliberately does not SELECT an
// applet; callers performing PIV work should use cnk_begin_piv_transaction.
CNK_TEST_API CK_RV cnk_begin_card_transaction(CK_SLOT_ID slotID, SCARDHANDLE *phCard) {
  CNK_ENSURE_NONNULL(phCard);
  CK_RV operationRv = cnk_pcsc_operation_begin();
  if (operationRv != CKR_OK)
    return operationRv;

#if defined(__clang__) || defined(__GNUC__)
  CK_BBOOL releaseOperation __attribute__((cleanup(release_pcsc_operation_guard))) = CK_TRUE;
#else
#error "CanoKey PC/SC lifetime guards require compiler cleanup support"
#endif

  // In managed mode, use the provided card handle
  if (g_cnk_is_managed_mode) {
    *phCard = g_cnk_scard;

    // Begin transaction with default timeout of 2 seconds
    LONG rv = SCardBeginTransaction(*phCard);
    if (rv != SCARD_S_SUCCESS) {
      CNK_ERROR("SCardBeginTransaction failed with error: 0x%lx", rv);
      CNK_RETURN(CKR_DEVICE_ERROR, "SCardBeginTransaction failed");
    }

    releaseOperation = CK_FALSE;
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

  // If readers haven't been listed yet, list them now. Read the globals under
  // the same lock used by the PnP refresh path.
  CNK_ENSURE_OK(cnk_mutex_lock(&g_cnk_readers_mutex));
  CK_BBOOL readersMissing = g_cnk_num_readers == 0 || g_cnk_readers == NULL;
  cnk_mutex_unlock(&g_cnk_readers_mutex);
  if (readersMissing) {
    CK_RV rv = cnk_list_readers();
    if (rv != CKR_OK) {
      CNK_ERROR("Failed to list readers: 0x%lx", rv);
      CNK_RETURN(rv, "cnk_list_readers failed");
    }
  }

  // Copy the selected reader name while holding the reader lock. PnP refresh
  // replaces and frees the global reader array asynchronously.
  char *readerName = NULL;
  CK_BBOOL readerFound = CK_FALSE;
  CNK_ENSURE_OK(cnk_mutex_lock(&g_cnk_readers_mutex));
  for (CK_LONG i = 0; i < g_cnk_num_readers; i++) {
    if (g_cnk_readers[i].slot_id == slotID) {
      readerFound = CK_TRUE;
      size_t nameLen = strlen(g_cnk_readers[i].name) + 1;
      readerName = ck_malloc(nameLen);
      if (readerName != NULL)
        memcpy(readerName, g_cnk_readers[i].name, nameLen);
      break;
    }
  }
  cnk_mutex_unlock(&g_cnk_readers_mutex);

  if (!readerFound) {
    CNK_ERROR("No reader found for slot %lu", slotID);
    CNK_RETURN(CKR_SLOT_ID_INVALID, "Invalid slot ID");
  }
  if (readerName == NULL)
    CNK_RETURN(CKR_HOST_MEMORY, "Failed to copy reader name");

  // Connect to the card
  DWORD active_protocol;
  LONG rv = SCardConnect(g_cnk_pcsc_context, readerName, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                         phCard, &active_protocol);
  ck_free(readerName);
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

  releaseOperation = CK_FALSE;
  CNK_RET_OK;
}

// Begin a card transaction and select PIV before any dependent APDU.
// The returned handle remains in the transaction until cnk_disconnect_card;
// callers must not select another applet before completing their operation.
CK_RV cnk_begin_piv_transaction(CK_SLOT_ID slotID, SCARDHANDLE *phCard) {
  CNK_ENSURE_NONNULL(phCard);
  *phCard = 0;
  CK_RV rv = cnk_begin_card_transaction(slotID, phCard);
  if (rv != CKR_OK)
    return rv;
  rv = cnk_select_piv_application(*phCard);
  if (rv != CKR_OK) {
    cnk_disconnect_card(*phCard);
    *phCard = 0;
  }
  return rv;
}

// Disconnect from a card and end any active transaction.
// In managed mode the caller-owned card handle remains connected.
CNK_TEST_API void cnk_disconnect_card(SCARDHANDLE hCard) {
  if (hCard == 0) {
    return;
  }

  // End transaction first
  SCardEndTransaction(hCard, SCARD_LEAVE_CARD);

  // In managed mode, don't disconnect the card
  if (g_cnk_is_managed_mode) {
    cnk_pcsc_operation_end();
    return;
  }

  // In standalone mode, disconnect the card
  SCardDisconnect(hCard, SCARD_LEAVE_CARD);
  cnk_pcsc_operation_end();
}

// Helper function to transmit APDU commands and log both command and response
CNK_TEST_API LONG cnk_transceive_apdu(SCARDHANDLE hCard, const CK_BYTE *pCommand, CK_ULONG cbCommand,
                                      CK_BYTE *pResponse, DWORD *pcbResponse, CK_BBOOL auto_get_response) {
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

CK_RV cnk_transmit_chained_apdu(SCARDHANDLE hCard, CK_BYTE ins, CK_BYTE p1, CK_BYTE p2, const CK_BYTE *data,
                                CK_ULONG data_len, CK_BYTE *response, CK_ULONG_PTR response_len, CK_BBOOL request_le) {
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
