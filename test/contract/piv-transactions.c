// Real PKCS#11 sessions and Rust operations with a deterministic PC/SC card.
// The fake serializes only Begin/EndTransaction, so an early release or a
// dependent APDU on a different connection fails the per-handle transcript.
#include "api/object.h"
#include "api/session.h"
#include "backend/pcsc.h"
#include <nsync_mu.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define THREAD_RESULT DWORD WINAPI
#define THREAD_DONE 0
static void pause_ms(void) { Sleep(1); }
#else
#include <pthread.h>
#include <time.h>
#define THREAD_RESULT void *
#define THREAD_DONE NULL
static void pause_ms(void) {
  struct timespec t = {0, 1000000};
  nanosleep(&t, NULL);
}
#endif

#define CHECK(x)                                                                                                       \
  do {                                                                                                                 \
    if (!(x)) {                                                                                                        \
      fprintf(stderr, "%d: %s\n", __LINE__, #x);                                                                       \
      exit(1);                                                                                                         \
    }                                                                                                                  \
  } while (0)
enum { CONNECTED = 1, BEGUN, ENDED, DISCONNECTED };
typedef struct {
  unsigned stage, applet, selects, verifies, crypto, random;
  CK_BBOOL verified;
  CK_BYTE pending[512];
  size_t pendingLength, pendingOffset;
} Card;
static Card cards[256];
static nsync_mu cardLock;
static SCARDHANDLE activeCard;
static atomic_uint connects, begins, ends, disconnects;
static atomic_bool signPaused, releaseSign, readerWaiting, failSign;
static SCARDHANDLE signCard;
static const CK_BYTE pin[] = "123456";

static void wait_for(atomic_bool *flag) {
  for (unsigned i = 0; i < 10000 && !atomic_load(flag); ++i)
    pause_ms();
  CHECK(atomic_load(flag));
}
static LONG establish(DWORD scope, LPCVOID a, LPCVOID b, LPSCARDCONTEXT context) {
  (void)scope;
  (void)a;
  (void)b;
  *context = 1;
  return SCARD_S_SUCCESS;
}
static LONG release_context(SCARDCONTEXT context) {
  CHECK(context == 1);
  return SCARD_S_SUCCESS;
}
static LONG readers(SCARDCONTEXT context, LPCSTR groups, LPSTR output, LPDWORD length) {
  (void)groups;
  CHECK(context == 1);
  const char names[] = "CanoKey transaction fixture\0";
  if (output) {
    CHECK(*length >= sizeof(names));
    memcpy(output, names, sizeof(names));
  }
  *length = sizeof(names);
  return SCARD_S_SUCCESS;
}
static LONG connect_card(SCARDCONTEXT context, LPCSTR reader, DWORD share, DWORD protocols, LPSCARDHANDLE card,
                         LPDWORD protocol) {
  (void)share;
  (void)protocols;
  CHECK(context == 1 && !strcmp(reader, "CanoKey transaction fixture"));
  *card = atomic_fetch_add(&connects, 1) + 1;
  CHECK(*card < sizeof(cards) / sizeof(cards[0]));
  cards[*card].stage = CONNECTED;
  *protocol = SCARD_PROTOCOL_T1;
  return SCARD_S_SUCCESS;
}
static LONG begin(SCARDHANDLE card) {
  CHECK(cards[card].stage == CONNECTED);
  if (atomic_load(&signPaused))
    atomic_store(&readerWaiting, true);
  nsync_mu_lock(&cardLock);
  CHECK(activeCard == 0);
  activeCard = card;
  cards[card].stage = BEGUN;
  atomic_fetch_add(&begins, 1);
  return SCARD_S_SUCCESS;
}
static LONG end(SCARDHANDLE card, DWORD disposition) {
  (void)disposition;
  CHECK(activeCard == card && cards[card].stage == BEGUN);
  cards[card].stage = ENDED;
  activeCard = 0;
  atomic_fetch_add(&ends, 1);
  nsync_mu_unlock(&cardLock);
  return SCARD_S_SUCCESS;
}
static LONG disconnect_card(SCARDHANDLE card, DWORD disposition) {
  (void)disposition;
  CHECK(cards[card].stage == ENDED);
  cards[card].stage = DISCONNECTED;
  atomic_fetch_add(&disconnects, 1);
  return SCARD_S_SUCCESS;
}
static LONG status_change(SCARDCONTEXT context, DWORD timeout, SCARD_READERSTATE *states, DWORD count) {
  (void)context;
  (void)timeout;
  (void)states;
  (void)count;
  pause_ms();
  return SCARD_E_TIMEOUT;
}
static LONG cancel(SCARDCONTEXT context) {
  (void)context;
  return SCARD_S_SUCCESS;
}

static LONG transmit(SCARDHANDLE card, LPCSCARD_IO_REQUEST sendPci, LPCBYTE command, DWORD commandLen,
                     LPSCARD_IO_REQUEST receivePci, LPBYTE output, LPDWORD length) {
  (void)sendPci;
  (void)receivePci;
  CHECK(activeCard == card && cards[card].stage == BEGUN && commandLen >= 4 && *length >= 300);
  Card *state = &cards[card];
  size_t n = 0;
  if (command[1] == 0xa4) {
    CHECK(commandLen >= 10 && !state->verified && !state->crypto);
    state->applet = command[5] == 0xf0 ? 1 : 2;
    state->selects++;
    state->verified = CK_FALSE;
  } else if (state->applet == 1) {
    if (command[1] == 0x31 && command[2] == 0) {
      memcpy(output, "3.1.0", 5);
      n = 5;
    } else {
      output[0] = 0x6d;
      output[1] = 0;
      *length = 2;
      return SCARD_S_SUCCESS;
    }
  } else {
    CHECK(state->applet == 2);
    switch (command[1]) {
    case 0xfd:
      output[n++] = 6;
      output[n++] = 0;
      output[n++] = 0;
      break;
    case 0xee: {
      const CK_BYTE config[] = {0, 0xe0, 5, 0x16, 0xe1, 0x53, 0x15, 0x54, 0xe2, 0xe3};
      memcpy(output, config, sizeof(config));
      n = sizeof(config);
    } break;
    case 0xf7: {
      CHECK(command[3] == 0x9c || command[3] == 0x9d);
      const CK_BYTE header[] = {1, 1, 7, 2, 2, 2, 1, 3, 1, 1, 4, 0x82, 1, 9, 0x81, 0x82, 1, 0};
      memcpy(output, header, sizeof(header));
      n = sizeof(header);
      memset(output + n, command[3], 256);
      output[n + 255] |= 1;
      n += 256;
      const CK_BYTE exponent[] = {0x82, 3, 1, 0, 1};
      memcpy(output + n, exponent, sizeof(exponent));
      n += sizeof(exponent);
      break;
    }
    case 0x20:
      if (command[2] == 0xff)
        state->verified = CK_FALSE;
      else {
        CHECK(commandLen >= 13 && !memcmp(command + 5, pin, 6));
        state->verifies++;
        state->verified = CK_TRUE;
      }
      break;
    case 0xc0:
      CHECK(state->pendingLength > state->pendingOffset);
      n = state->pendingLength - state->pendingOffset;
      CHECK(n <= 256);
      memcpy(output, state->pending + state->pendingOffset, n);
      state->pendingLength = state->pendingOffset = 0;
      break;
    case 0x87: {
      CHECK(state->verified && state->selects == 1 && state->verifies == 1 && command[3] == 0x9c);
      state->crypto++;
      if (command[0] & 0x10)
        break;
      signCard = card;
      atomic_store(&signPaused, true);
      wait_for(&releaseSign);
      if (atomic_load(&failSign))
        return SCARD_E_COMM_DATA_LOST;
      const CK_BYTE header[] = {0x7c, 0x82, 1, 4, 0x82, 0x82, 1, 0};
      memcpy(output, header, sizeof(header));
      n = sizeof(header);
      memset(output + n, 0xa5, 256);
      n += 256;
      break;
    }
    case 0x84:
      CHECK(!state->verified && state->selects == 1 && commandLen == 5 && command[4] == 32);
      memset(output, 0x5a, 32);
      n = 32;
      state->random++;
      break;
    default:
      CHECK(0);
    }
  }
  if (n > 256) {
    CHECK(n <= sizeof(state->pending));
    memcpy(state->pending, output, n);
    state->pendingLength = n;
    state->pendingOffset = 256;
    output[256] = 0x61;
    output[257] = (CK_BYTE)(n - 256);
    *length = 258;
    return SCARD_S_SUCCESS;
  }
  output[n++] = 0x90;
  output[n++] = 0;
  CHECK(n <= *length);
  *length = (DWORD)n;
  return SCARD_S_SUCCESS;
}

typedef struct {
  CK_SESSION_HANDLE session;
  CK_RV result;
  CK_BYTE output[256];
  CK_ULONG length;
} Worker;
static THREAD_RESULT sign_worker(void *opaque) {
  Worker *worker = opaque;
  CK_BYTE input[256];
  memset(input, 0x11, sizeof(input));
  worker->length = sizeof(worker->output);
  worker->result = C_Sign(worker->session, input, sizeof(input), worker->output, &worker->length);
  return THREAD_DONE;
}
static THREAD_RESULT random_worker(void *opaque) {
  Worker *worker = opaque;
  worker->result = C_GenerateRandom(worker->session, worker->output, 32);
  return THREAD_DONE;
}

int main(void) {
  CNK_PCSC_TEST_TRANSPORT transport = {establish, release_context, readers,       connect_card, disconnect_card, begin,
                                       end,       transmit,        status_change, cancel};
  nsync_mu_init(&cardLock);
  CHECK(cnk_pcsc_set_test_transport(&transport) == CKR_OK);
#ifdef _WIN32
  _putenv_s("CNK_LOG_LEVEL", "none");
  _putenv_s("CNK_PIV_METADATA_CACHE", "0");
#else
  setenv("CNK_LOG_LEVEL", "none", 1);
  setenv("CNK_PIV_METADATA_CACHE", "0", 1);
#endif
  CHECK(C_Initialize(NULL) == CKR_OK);
  if (getenv("CNK_TRANSACTION_TRACE"))
    CHECK(C_CNK_ConfigLogging(1, stderr, CK_FALSE) == CKR_OK);
  CK_ULONG slotCount = 1;
  CK_SLOT_ID slot = 99;
  CHECK(C_GetSlotList(CK_FALSE, &slot, &slotCount) == CKR_OK && slotCount == 1 && slot == 0);
  CK_SESSION_HANDLE sessions[2];
  unsigned before = atomic_load(&connects);
  for (unsigned i = 0; i < 2; i++)
    CHECK(C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &sessions[i]) == CKR_OK);
  CHECK(sessions[0] != sessions[1] && atomic_load(&connects) == before);
  CHECK(C_Login(sessions[0], CKU_USER, (CK_UTF8CHAR_PTR)pin, 6) == CKR_OK);
  CNK_PKCS11_SESSION *first = NULL, *second = NULL;
  CHECK(cnk_session_find(sessions[0], &first) == CKR_OK && cnk_session_find(sessions[1], &second) == CKR_OK);
  CHECK(first != second && first->token == second->token);
  CHECK(cnk_token_begin_user_operation(first) == CKR_OK);
  CHECK(cnk_token_begin_user_operation(second) == CKR_OPERATION_ACTIVE);
  CHECK(C_Logout(sessions[1]) == CKR_OPERATION_ACTIVE);
  CHECK(first->token->managementOperationOwner == sessions[0] && first->token->loginState == TOKEN_LOGIN_USER);
  cnk_token_end_management_operation(first);
  cnk_session_release_ref(&second);
  cnk_session_release_ref(&first);

  for (unsigned failure = 0; failure < 2; failure++) {
    CK_MECHANISM mechanism = {CKM_RSA_X_509, NULL, 0};
    CHECK(C_SignInit(sessions[0], &mechanism, CNK_MakeObjectHandle(0, CKO_PRIVATE_KEY, 2)) == CKR_OK);
    CHECK(C_SignInit(sessions[1], &mechanism, CNK_MakeObjectHandle(0, CKO_PRIVATE_KEY, 3)) == CKR_OK);
    atomic_store(&signPaused, false);
    atomic_store(&releaseSign, false);
    atomic_store(&readerWaiting, false);
    atomic_store(&failSign, failure != 0);
    Worker a = {.session = sessions[0]}, b = {.session = sessions[1]};
    memset(a.output, 0xcc, sizeof(a.output));
#ifdef _WIN32
    HANDLE threadA = CreateThread(NULL, 0, sign_worker, &a, 0, NULL);
    CHECK(threadA);
    wait_for(&signPaused);
    HANDLE threadB = CreateThread(NULL, 0, random_worker, &b, 0, NULL);
    CHECK(threadB);
#else
    pthread_t threadA, threadB;
    CHECK(pthread_create(&threadA, NULL, sign_worker, &a) == 0);
    wait_for(&signPaused);
    CHECK(pthread_create(&threadB, NULL, random_worker, &b) == 0);
#endif
    wait_for(&readerWaiting);
    CHECK(activeCard == signCard && cards[signCard].stage == BEGUN);
    atomic_store(&releaseSign, true);
#ifdef _WIN32
    CHECK(WaitForSingleObject(threadA, 10000) == WAIT_OBJECT_0 && WaitForSingleObject(threadB, 10000) == WAIT_OBJECT_0);
    CloseHandle(threadB);
    CloseHandle(threadA);
#else
    CHECK(pthread_join(threadA, NULL) == 0 && pthread_join(threadB, NULL) == 0);
#endif
    CHECK(a.result == (failure ? CKR_DEVICE_ERROR : CKR_OK) && b.result == CKR_OK);
    CHECK(cards[signCard].stage == DISCONNECTED && cards[signCard].crypto == 2);
    for (unsigned i = 0; i < 32; i++)
      CHECK(b.output[i] == 0x5a);
    for (unsigned i = 0; i < 256; i++)
      CHECK(a.output[i] == (failure ? 0xcc : 0xa5));
    CHECK(atomic_load(&connects) == atomic_load(&disconnects) && atomic_load(&begins) == atomic_load(&ends));
    CHECK(cnk_session_find(sessions[1], &second) == CKR_OK);
    CHECK(second->signingContext.pivSlot == 0x9d && second->signingContext.abModulus[0] == 0x9d);
    CHECK(second->token->loginState == TOKEN_LOGIN_USER && !second->token->managementOperationPending);
    cnk_session_release_ref(&second);
    CK_BYTE input[256] = {0};
    CK_ULONG length = 0;
    CHECK(C_Sign(sessions[1], input, sizeof(input), NULL, &length) == CKR_OK && length == 256);
    CHECK(C_Sign(sessions[0], input, sizeof(input), NULL, &length) == CKR_OPERATION_NOT_INITIALIZED);
    CHECK(C_SessionCancel(sessions[1], CKF_SIGN) == CKR_OK);
  }
  CHECK(C_Logout(sessions[1]) == CKR_OK);
  for (unsigned i = 0; i < 2; i++) {
    CK_SESSION_INFO info;
    CHECK(C_GetSessionInfo(sessions[i], &info) == CKR_OK && info.state == CKS_RW_PUBLIC_SESSION);
    CHECK(C_CloseSession(sessions[i]) == CKR_OK);
  }
  CHECK(C_Finalize(NULL) == CKR_OK);
  CHECK(!activeCard && atomic_load(&connects) == atomic_load(&disconnects) &&
        atomic_load(&begins) == atomic_load(&ends));
  puts("Two-session PIV transactions, context isolation, reservations and failure cleanup passed");
  return 0;
}
