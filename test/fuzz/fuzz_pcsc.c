#include "backend/pcsc.h"
#include "pkcs11.h"
#include "pkcs11_canokey.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  _Atomic CK_ULONG beginCalls;
  _Atomic CK_ULONG endCalls;
  _Atomic CK_ULONG transmitCalls;
  _Atomic CK_ULONG connectCalls;
  _Atomic CK_ULONG disconnectCalls;
  _Atomic CK_ULONG activeTransactions;
  _Atomic LONG beginStatus;
  _Atomic LONG transmitStatus;
  _Atomic CK_BBOOL shortResponse;
} CNK_FAKE_PCSC_STATE;

static CNK_FAKE_PCSC_STATE fakeState;
static CNK_PCSC_TEST_TRANSPORT fakeTransport;
static CK_SESSION_HANDLE fakeSession = CK_INVALID_HANDLE;

static LONG fakeEstablish(DWORD scope, LPCVOID reserved1, LPCVOID reserved2, LPSCARDCONTEXT context) {
  (void)scope;
  (void)reserved1;
  (void)reserved2;
  *context = 1;
  return SCARD_S_SUCCESS;
}

static LONG fakeRelease(SCARDCONTEXT context) {
  (void)context;
  return SCARD_S_SUCCESS;
}

static LONG fakeListReaders(SCARDCONTEXT context, LPCSTR groups, LPSTR readers, LPDWORD length) {
  (void)context;
  (void)groups;
  const char names[] = "fake-reader\0\0";
  if (readers == NULL) {
    *length = sizeof(names);
    return SCARD_S_SUCCESS;
  }
  if (*length < sizeof(names)) {
    *length = sizeof(names);
    return SCARD_E_INSUFFICIENT_BUFFER;
  }
  memcpy(readers, names, sizeof(names));
  *length = sizeof(names);
  return SCARD_S_SUCCESS;
}

static LONG fakeConnect(SCARDCONTEXT context, LPCSTR reader, DWORD share, DWORD protocols, LPSCARDHANDLE card,
                        LPDWORD activeProtocol) {
  (void)context;
  (void)reader;
  (void)share;
  (void)protocols;
  atomic_fetch_add(&fakeState.connectCalls, 1);
  *card = 2;
  *activeProtocol = SCARD_PROTOCOL_T1;
  return SCARD_S_SUCCESS;
}

static LONG fakeDisconnect(SCARDHANDLE card, DWORD disposition) {
  (void)card;
  (void)disposition;
  atomic_fetch_add(&fakeState.disconnectCalls, 1);
  return SCARD_S_SUCCESS;
}

static LONG fakeBegin(SCARDHANDLE card) {
  (void)card;
  atomic_fetch_add(&fakeState.beginCalls, 1);
  LONG status = atomic_load(&fakeState.beginStatus);
  if (status != SCARD_S_SUCCESS)
    return status;
  atomic_fetch_add(&fakeState.activeTransactions, 1);
  return SCARD_S_SUCCESS;
}

static LONG fakeEnd(SCARDHANDLE card, DWORD disposition) {
  (void)card;
  (void)disposition;
  atomic_fetch_add(&fakeState.endCalls, 1);
  CK_ULONG active = atomic_load(&fakeState.activeTransactions);
  while (active != 0 && !atomic_compare_exchange_weak(&fakeState.activeTransactions, &active, active - 1))
    ;
  return SCARD_S_SUCCESS;
}

static LONG fakeTransmit(SCARDHANDLE card, LPCSCARD_IO_REQUEST sendPci, LPCBYTE sendBuffer, DWORD sendLength,
                         LPSCARD_IO_REQUEST receivePci, LPBYTE receiveBuffer, LPDWORD receiveLength) {
  (void)card;
  (void)sendPci;
  (void)sendBuffer;
  (void)sendLength;
  (void)receivePci;
  atomic_fetch_add(&fakeState.transmitCalls, 1);
  LONG status = atomic_load(&fakeState.transmitStatus);
  if (status != SCARD_S_SUCCESS)
    return status;
  if (*receiveLength < 2)
    return SCARD_E_INSUFFICIENT_BUFFER;
  if (atomic_load(&fakeState.shortResponse)) {
    receiveBuffer[0] = 0x6A;
    *receiveLength = 1;
    return SCARD_S_SUCCESS;
  }
  receiveBuffer[0] = 0x90;
  receiveBuffer[1] = 0x00;
  *receiveLength = 2;
  return SCARD_S_SUCCESS;
}

static LONG fakeStatusChange(SCARDCONTEXT context, DWORD timeout, SCARD_READERSTATE *states, DWORD count) {
  (void)context;
  (void)timeout;
  (void)states;
  (void)count;
  return SCARD_E_TIMEOUT;
}

static LONG fakeCancel(SCARDCONTEXT context) {
  (void)context;
  return SCARD_S_SUCCESS;
}

static void initializeFakeTransport(void) {
  memset(&fakeTransport, 0, sizeof(fakeTransport));
  fakeTransport.establish_context = fakeEstablish;
  fakeTransport.release_context = fakeRelease;
  fakeTransport.list_readers = fakeListReaders;
  fakeTransport.connect = fakeConnect;
  fakeTransport.disconnect = fakeDisconnect;
  fakeTransport.begin_transaction = fakeBegin;
  fakeTransport.end_transaction = fakeEnd;
  fakeTransport.transmit = fakeTransmit;
  fakeTransport.get_status_change = fakeStatusChange;
  fakeTransport.cancel = fakeCancel;
  (void)cnk_pcsc_set_test_transport(&fakeTransport);

  // Expected transport failures are part of this fuzz model. Suppress the
  // library's diagnostic stream so a bounded campaign records failures in
  // return values and counters instead of flooding CI logs.
  (void)C_CNK_ConfigLogging(6, NULL, CK_FALSE);

  CNK_MANAGED_MODE_INIT_ARGS managed = {.malloc_func = malloc, .free_func = free, .hSCardCtx = 1, .hScard = 2};
  (void)C_CNK_EnableManagedMode(&managed);
  if (C_Initialize(NULL) == CKR_OK)
    (void)C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &fakeSession);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  initializeFakeTransport();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (fakeSession == CK_INVALID_HANDLE)
    return 0;
  LONG beginStatus = size > 0 && (data[0] & 1) ? SCARD_E_SHARING_VIOLATION : SCARD_S_SUCCESS;
  LONG transmitStatus = size > 1 && (data[1] & 1) ? SCARD_E_NOT_TRANSACTED : SCARD_S_SUCCESS;
  atomic_store(&fakeState.beginStatus, beginStatus);
  atomic_store(&fakeState.transmitStatus, transmitStatus);
  atomic_store(&fakeState.shortResponse, size > 2 && (data[2] & 1));

  CK_ULONG count = 0;
  (void)C_GetSlotList(CK_TRUE, NULL, &count);

  SCARDHANDLE card = 0;
  CK_RV rv = cnk_begin_card_transaction(0, &card);
  if (rv == CKR_OK) {
    CK_BYTE command[] = {0x00, 0xA4, 0x04, 0x00};
    CK_BYTE response[8] = {0};
    DWORD responseLen = sizeof(response);
    (void)cnk_transceive_apdu(card, command, sizeof(command), response, &responseLen, CK_TRUE);
    cnk_disconnect_card(card);
  }

  // Exercise the cancellation hook even when no transaction is active; the
  // fake callback is idempotent, matching SCardCancel's expected semantics.
  cnk_cancel_pcsc_operations();

  if (atomic_load(&fakeState.activeTransactions) != 0 || atomic_load(&g_cnk_pcsc_operations) != 0)
    abort();
  return 0;
}
