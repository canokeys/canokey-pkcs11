// Real PKCS#11 sessions and Rust operations with a deterministic PC/SC card.
// The fake serializes only Begin/EndTransaction, so an early release or a
// dependent APDU on a different connection fails the per-handle transcript.
#include "api/object.h"
#include "api/session.h"
#include "backend/pcsc.h"
#include "internal/logging.h"
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
static atomic_bool pauseCacheRead, cacheReadPaused, releaseCacheRead;
static atomic_uint revision;
static atomic_bool pauseVerify, verifyPaused, releaseVerify;
static atomic_bool failProfile, churnProfile;
static atomic_bool teardownDone;
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
  CHECK(context == 1 && !activeCard && atomic_load(&connects) == atomic_load(&disconnects));
  return SCARD_S_SUCCESS;
}
static LONG readers(SCARDCONTEXT context, LPCSTR groups, LPSTR output, LPDWORD length) {
  (void)groups;
  CHECK(context == 1);
  const char names[] = "Microsoft Smart Card\0CanoKey transaction fixture\0";
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
  if (atomic_load(&signPaused) || atomic_load(&verifyPaused))
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
  if (cards[card].selects == 2 && atomic_load(&churnProfile))
    atomic_fetch_add(&g_cnk_managed_binding_epoch, 2);
  if (atomic_exchange(&pauseCacheRead, false)) {
    atomic_store(&cacheReadPaused, true);
    wait_for(&releaseCacheRead);
  }
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
      if (atomic_load(&failProfile))
        return SCARD_E_COMM_DATA_LOST;
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
      output[0] = atomic_load(&revision) & 1;
      n = sizeof(config);
    } break;
    case 0xf7: {
      if (command[2] == 1) {
        const CK_BYTE directory[] = {1, 1, 1, 2, 6, 0x9c, 3, 7, 1, 2, 1};
        memcpy(output, directory, sizeof(directory));
        n = sizeof(directory);
        output[8] = (CK_BYTE)atomic_load(&revision);
        break;
      }
      CHECK(command[3] == 0x9c || command[3] == 0x9d);
      const CK_BYTE header[] = {1, 1, 7, 2, 2, 2, 1, 3, 1, 1, 4, 0x82, 1, 9, 0x81, 0x82, 1, 0};
      memcpy(output, header, sizeof(header));
      n = sizeof(header);
      memset(output + n, atomic_load(&revision) ? (CK_BYTE)atomic_load(&revision) : command[3], 256);
      output[n + 255] |= 1;
      n += 256;
      const CK_BYTE exponent[] = {0x82, 3, 1, 0, 1};
      memcpy(output + n, exponent, sizeof(exponent));
      n += sizeof(exponent);
      break;
    }
    case 0xcb: {
      // Framing fixture only; certificate trust/ASN.1 inspection is not involved.
      const CK_BYTE certificate[] = {0x53, 12, 0x70, 5, 0x30, 3, 2, 1, 0, 0x71, 1, 0, 0xfe, 0};
      memcpy(output, certificate, sizeof(certificate));
      n = sizeof(certificate);
      output[8] = (CK_BYTE)atomic_load(&revision);
      break;
    }
    case 0x20:
      if (command[2] == 0xff)
        state->verified = CK_FALSE;
      else {
        CHECK(commandLen >= 13 && !memcmp(command + 5, pin, 6));
        state->verifies++;
        state->verified = CK_TRUE;
        if (atomic_exchange(&pauseVerify, false)) {
          atomic_store(&verifyPaused, true);
          wait_for(&releaseVerify);
        }
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

typedef struct {
  CNK_PKCS11_SESSION *session;
  unsigned kind;
  CK_BYTE value;
  CK_RV result;
} CacheWorker;
static void read_cache(CacheWorker *worker) {
  if (worker->kind == 0) {
    CNK_PIV_PUBLIC_KEY key;
    uint32_t algorithm;
    worker->result = cnk_get_metadata_cached(worker->session, 0x9c, &algorithm, &key, NULL, NULL);
    if (worker->result == CKR_OK)
      worker->value = key.value[0];
  } else if (worker->kind == 1) {
    CK_BYTE certificate[32];
    CK_ULONG length = sizeof(certificate);
    worker->result = cnk_get_piv_data_cached(worker->session, 0x0a, certificate, &length, CK_TRUE);
    if (worker->result == CKR_OK) {
      CHECK(length == 5);
      worker->value = certificate[4];
    }
  } else if (worker->kind == 2) {
    CNK_PIV_METADATA_DIRECTORY_ENTRY directory[24];
    CK_ULONG count = 24;
    worker->result = cnk_get_piv_metadata_directory_cached(worker->session, directory, &count);
    if (worker->result == CKR_OK) {
      CHECK(count == 1);
      worker->value = directory[0].origin;
    }
  } else {
    CNK_PIV_ALGORITHM_EXTENSION_CONFIG config;
    worker->result = cnk_get_piv_algorithm_extension_cached(0, &config);
    if (worker->result == CKR_OK)
      worker->value = config.enabled;
  }
}
static THREAD_RESULT cache_worker(void *opaque) {
  read_cache(opaque);
  return THREAD_DONE;
}
static void invalidate_cache(CacheWorker *worker) {
  if (worker->kind >= 3)
    cnk_piv_algorithm_extension_cache_invalidate();
  else
    cnk_piv_public_cache_invalidate(worker->session);
}
static CK_RV reject_lock(void *opaque) {
  (void)opaque;
  return CKR_CANT_LOCK;
}
static CK_RV (*original_lock)(void *), (*original_unlock)(void *);
static unsigned lock_call, unlock_call, reject_lock_at, reject_unlock_at;
static CK_RV counted_lock(void *opaque) {
  return ++lock_call == reject_lock_at ? CKR_CANT_LOCK : original_lock(opaque);
}
static CK_RV counted_unlock(void *opaque) {
  CK_RV rv = original_unlock(opaque);
  return ++unlock_call == reject_unlock_at ? CKR_CANT_LOCK : rv;
}
static void cache_contract(CK_SESSION_HANDLE handle) {
#ifdef _WIN32
  _putenv_s("CNK_PIV_METADATA_CACHE", "1");
#else
  setenv("CNK_PIV_METADATA_CACHE", "1", 1);
#endif
  cnk_config_logging_from_env();
  CNK_PKCS11_SESSION *session = NULL;
  CHECK(cnk_session_find(handle, &session) == CKR_OK);
  for (unsigned kind = 0; kind < 5; kind++) {
    CacheWorker worker = {.session = session, .kind = kind};
    atomic_store(&revision, 0xa0);
    invalidate_cache(&worker);
    atomic_store(&cacheReadPaused, false);
    atomic_store(&releaseCacheRead, false);
    atomic_store(&pauseCacheRead, true);
#ifdef _WIN32
    HANDLE thread = CreateThread(NULL, 0, cache_worker, &worker, 0, NULL);
    CHECK(thread);
#else
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, cache_worker, &worker) == 0);
#endif
    wait_for(&cacheReadPaused);
    // The old read has released its card transaction, but has not published.
    // Model a concurrent writer and the production invalidation it must issue.
    atomic_store(&revision, 0xb1);
    if (kind == 4)
      atomic_fetch_add(&g_cnk_managed_binding_epoch, 2);
    else
      invalidate_cache(&worker);
    atomic_store(&releaseCacheRead, true);
#ifdef _WIN32
    CHECK(WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0);
    CloseHandle(thread);
#else
    CHECK(pthread_join(thread, NULL) == 0);
#endif
    CHECK(worker.result == CKR_OK && worker.value == (kind >= 3 ? 0 : 0xa0));
    read_cache(&worker);
    CHECK(worker.result == CKR_OK && worker.value == (kind >= 3 ? 1 : 0xb1));
    unsigned before = atomic_load(&connects);
    read_cache(&worker);
    CHECK(worker.result == CKR_OK && atomic_load(&connects) == before);
    if (kind < 3) {
      original_lock = session->token->lock.lock;
      atomic_store(&revision, 0xc2);
      session->token->lock.lock = reject_lock;
      invalidate_cache(&worker);
      session->token->lock.lock = original_lock;
      read_cache(&worker);
      CHECK(worker.result == CKR_OK && worker.value == 0xc2);
      atomic_store(&revision, 0xd3);
      session->token->lock.lock = reject_lock;
      CHECK(cnk_token_invalidate_public_cache(0) == CKR_CANT_LOCK);
      session->token->lock.lock = original_lock;
      read_cache(&worker);
      CHECK(worker.result == CKR_OK && worker.value == 0xd3);
      // Fail every token lock/unlock in a cache miss, including publication.
      // Wrappers release before reporting an unlock failure, as a faulty host
      // callback may do; all card transactions still have to drain correctly.
      for (unsigned unlock = 0; unlock < 2; unlock++) {
        for (unsigned site = 1; site <= (kind == 0 ? 5u : 4u); site++) {
          CHECK(cnk_ensure_libcanokey_profile(session) == CKR_OK);
          invalidate_cache(&worker);
          worker.value = 0xcc;
          lock_call = unlock_call = 0;
          reject_lock_at = unlock ? 0 : site;
          reject_unlock_at = unlock ? site : 0;
          original_unlock = session->token->lock.unlock;
          session->token->lock.lock = counted_lock;
          session->token->lock.unlock = counted_unlock;
          read_cache(&worker);
          session->token->lock.lock = original_lock;
          session->token->lock.unlock = original_unlock;
          CHECK(worker.result == CKR_CANT_LOCK && worker.value == 0xcc);
          CHECK(atomic_load(&connects) == atomic_load(&disconnects));
        }
      }
      read_cache(&worker);
      CHECK(worker.result == CKR_OK);
      // Expiry applies independently to each public snapshot kind.
      if (kind == 0)
        session->token->pivPublicCache.slots[1].metadataRefreshedAtMs = 0;
      else if (kind == 1)
        session->token->pivPublicCache.slots[1].certificateRefreshedAtMs = 0;
      else
        session->token->pivPublicCache.directoryRefreshedAtMs = 0;
      atomic_store(&revision, 0xe4);
      before = atomic_load(&connects);
      read_cache(&worker);
      CHECK(worker.result == CKR_OK && worker.value == 0xe4 && atomic_load(&connects) == before + 1);
      if (kind == 1) {
        CK_BYTE output = 0xcc;
        CK_ULONG length = 1;
        CHECK(cnk_get_piv_data_cached(session, 0x0a, &output, &length, CK_TRUE) == CKR_BUFFER_TOO_SMALL);
        CHECK(length == 5 && output == 0xcc);
        CHECK(cnk_get_piv_data_cached(session, 0x0a, NULL, NULL, CK_FALSE) == CKR_OK);
      } else if (kind == 2) {
        CNK_PIV_METADATA_DIRECTORY_ENTRY output;
        memset(&output, 0xcc, sizeof(output));
        CK_ULONG count = 0;
        CHECK(cnk_get_piv_metadata_directory_cached(session, &output, &count) == CKR_BUFFER_TOO_SMALL);
        CHECK(count == 1 && output.pivSlot == 0xcc);
      }
    }
  }
  cnk_session_release_ref(&session);
  puts("Public cache invalidation cannot republish a superseded read");
}

static THREAD_RESULT profile_worker(void *opaque) {
  CacheWorker *worker = opaque;
  worker->result = cnk_ensure_libcanokey_profile(worker->session);
  return THREAD_DONE;
}
static void profile_contract(CK_SESSION_HANDLE a, CK_SESSION_HANDLE b) {
  CNK_PKCS11_SESSION *first = NULL, *second = NULL;
  CHECK(cnk_session_find(a, &first) == CKR_OK && cnk_session_find(b, &second) == CKR_OK);
  CHECK(cnk_ensure_libcanokey_profile(first) == CKR_OK);
  CNK_LIBCANO_PROFILE *previous = first->token->libcanokeyProfile;
  first->token->libcanokeyProfileRefreshedAtMs = 0;
  atomic_store(&failProfile, true);
  for (unsigned retry = 0; retry < 2; retry++) {
    CHECK(cnk_ensure_libcanokey_profile(first) == CKR_DEVICE_ERROR);
    CHECK(first->token->libcanokeyProfile == previous && first->token->libcanokeyProfileRefreshedAtMs == 0);
  }
  atomic_store(&failProfile, false);
  atomic_store(&churnProfile, true);
  unsigned before = atomic_load(&connects);
  CHECK(cnk_ensure_libcanokey_profile(first) == CKR_OPERATION_ACTIVE);
  CHECK(atomic_load(&connects) == before + 3 && first->token->libcanokeyProfile == previous);
  atomic_store(&churnProfile, false);
  CHECK(cnk_ensure_libcanokey_profile(first) == CKR_OK);
  original_lock = first->token->lock.lock;
  original_unlock = first->token->lock.unlock;
  for (unsigned at = 1; at <= 2; at++) {
    if (at == 2)
      first->token->libcanokeyProfileRefreshedAtMs = 0;
    unlock_call = 0;
    reject_unlock_at = at;
    first->token->lock.unlock = counted_unlock;
    CHECK(cnk_ensure_libcanokey_profile(first) == CKR_CANT_LOCK);
    first->token->lock.unlock = original_unlock;
    CHECK(cnk_ensure_libcanokey_profile(first) == CKR_OK);
  }
  first->token->libcanokeyProfileRefreshedAtMs = 0;
  lock_call = 0;
  reject_lock_at = 2;
  first->token->lock.lock = counted_lock;
  CHECK(cnk_ensure_libcanokey_profile(first) == CKR_CANT_LOCK);
  first->token->lock.lock = original_lock;
  CHECK(cnk_ensure_libcanokey_profile(first) == CKR_OK);

  CK_MECHANISM mechanism = {CKM_RSA_X_509, NULL, 0};
  CHECK(C_SignInit(a, &mechanism, CNK_MakeObjectHandle(0, CKO_PRIVATE_KEY, 2)) == CKR_OK);
  atomic_store(&signPaused, false);
  atomic_store(&failSign, false);
  atomic_store(&releaseSign, true);
  atomic_store(&verifyPaused, false);
  atomic_store(&releaseVerify, false);
  atomic_store(&pauseVerify, true);
  atomic_store(&readerWaiting, false);
  Worker signing = {.session = a};
  CacheWorker refreshing = {.session = second};
#ifdef _WIN32
  HANDLE signer = CreateThread(NULL, 0, sign_worker, &signing, 0, NULL);
  CHECK(signer);
#else
  pthread_t signer, refresher;
  CHECK(pthread_create(&signer, NULL, sign_worker, &signing) == 0);
#endif
  wait_for(&verifyPaused);
  CHECK(cnk_mutex_lock(&first->token->lock) == CKR_OK);
  first->token->libcanokeyProfileRefreshedAtMs = 0;
  CHECK(cnk_mutex_unlock(&first->token->lock) == CKR_OK);
#ifdef _WIN32
  HANDLE refresher = CreateThread(NULL, 0, profile_worker, &refreshing, 0, NULL);
  CHECK(refresher);
#else
  CHECK(pthread_create(&refresher, NULL, profile_worker, &refreshing) == 0);
#endif
  wait_for(&readerWaiting);
  CHECK(cnk_mutex_lock(&first->token->lock) == CKR_OK);
  CHECK(first->token->libcanokeyProfile != NULL);
  CHECK(cnk_mutex_unlock(&first->token->lock) == CKR_OK);
  atomic_store(&releaseVerify, true);
#ifdef _WIN32
  CHECK(WaitForSingleObject(signer, 10000) == WAIT_OBJECT_0 && WaitForSingleObject(refresher, 10000) == WAIT_OBJECT_0);
  CloseHandle(refresher);
  CloseHandle(signer);
#else
  CHECK(pthread_join(signer, NULL) == 0 && pthread_join(refresher, NULL) == 0);
#endif
  CHECK(signing.result == CKR_OK && refreshing.result == CKR_OK && signing.output[0] == 0xa5);
  cnk_session_release_ref(&second);
  cnk_session_release_ref(&first);
  puts("Profile expiry and failed callbacks preserve admitted transactions and ownership");
}

static THREAD_RESULT close_worker(void *opaque) {
  Worker *worker = opaque;
  worker->result = C_CloseSession(worker->session);
  atomic_store(&teardownDone, true);
  return THREAD_DONE;
}
static THREAD_RESULT finalize_worker(void *opaque) {
  Worker *worker = opaque;
  worker->result = C_Finalize(NULL);
  atomic_store(&teardownDone, true);
  return THREAD_DONE;
}
static void teardown_contract(CK_SESSION_HANDLE session, CK_BBOOL finalize) {
  CK_MECHANISM mechanism = {CKM_RSA_X_509, NULL, 0};
  CHECK(C_SignInit(session, &mechanism, CNK_MakeObjectHandle(0, CKO_PRIVATE_KEY, 2)) == CKR_OK);
  atomic_store(&signPaused, false);
  atomic_store(&releaseSign, false);
  atomic_store(&failSign, false);
  atomic_store(&teardownDone, false);
  Worker signing = {.session = session}, closing = {.session = session};
#ifdef _WIN32
  HANDLE signer = CreateThread(NULL, 0, sign_worker, &signing, 0, NULL);
  CHECK(signer);
#else
  pthread_t signer, closer;
  CHECK(pthread_create(&signer, NULL, sign_worker, &signing) == 0);
#endif
  wait_for(&signPaused);
  CNK_PKCS11_SESSION *reference = NULL;
  CHECK(cnk_session_find(session, &reference) == CKR_OK);
  CNK_PKCS11_SESSION *pinned = reference;
  cnk_session_release_ref(&reference);
  // The paused signer pins this pointer until released. Closing may reject new
  // references now, but must not free its context, token or Rust operation.
#ifdef _WIN32
  HANDLE closer = CreateThread(NULL, 0, finalize ? finalize_worker : close_worker, &closing, 0, NULL);
  CHECK(closer);
#else
  CHECK(pthread_create(&closer, NULL, finalize ? finalize_worker : close_worker, &closing) == 0);
#endif
  for (unsigned i = 0; i < 10000; i++) {
    if (finalize ? !atomic_load(&g_cnk_is_initialized) : atomic_load(&pinned->closing))
      break;
    pause_ms();
  }
  CHECK(finalize ? !atomic_load(&g_cnk_is_initialized) : atomic_load(&pinned->closing));
  CHECK(!atomic_load(&teardownDone) && activeCard == signCard && cards[signCard].stage == BEGUN);
  if (finalize) {
    CK_SESSION_HANDLE rejected = 0;
    CHECK(C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &rejected) == CKR_CRYPTOKI_NOT_INITIALIZED);
  }
  atomic_store(&releaseSign, true);
#ifdef _WIN32
  CHECK(WaitForSingleObject(signer, 10000) == WAIT_OBJECT_0 && WaitForSingleObject(closer, 10000) == WAIT_OBJECT_0);
  CloseHandle(closer);
  CloseHandle(signer);
#else
  CHECK(pthread_join(signer, NULL) == 0 && pthread_join(closer, NULL) == 0);
#endif
  CHECK(signing.result == CKR_OK && signing.length == 256 && signing.output[0] == 0xa5 && closing.result == CKR_OK);
  CHECK(!activeCard && atomic_load(&connects) == atomic_load(&disconnects));
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
  cache_contract(sessions[0]);
  profile_contract(sessions[0], sessions[1]);
  teardown_contract(sessions[0], CK_FALSE);
  CK_SESSION_INFO survivor;
  CHECK(C_GetSessionInfo(sessions[1], &survivor) == CKR_OK && survivor.state == CKS_RW_USER_FUNCTIONS);
  CHECK(C_Logout(sessions[1]) == CKR_OK);
  for (unsigned i = 1; i < 2; i++) {
    CK_SESSION_INFO info;
    CHECK(C_GetSessionInfo(sessions[i], &info) == CKR_OK && info.state == CKS_RW_PUBLIC_SESSION);
    CHECK(C_CloseSession(sessions[i]) == CKR_OK);
  }
  CHECK(C_Finalize(NULL) == CKR_OK);
  CHECK(!activeCard && atomic_load(&connects) == atomic_load(&disconnects) &&
        atomic_load(&begins) == atomic_load(&ends));
  // Finalization must drain a card call and free both active and idle sessions.
  CHECK(C_Initialize(NULL) == CKR_OK);
  slotCount = 1;
  CHECK(C_GetSlotList(CK_FALSE, &slot, &slotCount) == CKR_OK && slotCount == 1);
  for (unsigned i = 0; i < 2; i++)
    CHECK(C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &sessions[i]) == CKR_OK);
  CHECK(C_Login(sessions[0], CKU_USER, (CK_UTF8CHAR_PTR)pin, 6) == CKR_OK);
  teardown_contract(sessions[0], CK_TRUE);
  puts("Two-session PIV transactions, cache/profile refresh, close/finalize and failure cleanup passed");
  return 0;
}
