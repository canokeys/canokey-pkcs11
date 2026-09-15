#include "api/session.h"
#include "backend/libcanokey.h"
#include "backend/pcsc.h"
#include "backend/piv_operation.h"
#include "internal/logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x)                                                                                                       \
  do {                                                                                                                 \
    if (!(x)) {                                                                                                        \
      fprintf(stderr, "%d: %s\n", __LINE__, #x);                                                                       \
      exit(1);                                                                                                         \
    }                                                                                                                  \
  } while (0)

static CNK_PKCS11_TOKEN_STATE token;
static CNK_PKCS11_SESSION keySession;
_Atomic CK_ULONG g_cnk_managed_binding_epoch;
atomic_int g_cnk_log_level = CNK_LOG_LEVEL_NONE;
void cnk_printlogf(const int l, const char *fn, const char *file, const int line, const char *format, ...) {
  (void)l;
  (void)fn;
  (void)file;
  (void)line;
  (void)format;
}
CK_RV cnk_mutex_lock(CNK_PKCS11_MUTEX *mutex) {
  (void)mutex;
  return CKR_OK;
}
CK_RV cnk_mutex_unlock(CNK_PKCS11_MUTEX *mutex) {
  (void)mutex;
  return CKR_OK;
}
CK_RV cnk_ensure_libcanokey_profile(CNK_PKCS11_SESSION *session) {
  (void)session;
  abort();
}
static void make_profile(void) {
  CNK_LIBCANO_OPERATION *op = NULL;
  uint32_t step = 0;
  CHECK(cnk_probe_device_new(1, NULL, &op, NULL) == CNK_LIBCANO_OK);
  CHECK(cnk_operation_start(op, &step, NULL) == CNK_LIBCANO_OK);
  const CK_BYTE ok[] = {0x90, 0}, unavailable[] = {0x6d, 0}, fw[] = {'3', '.', '1', '.', '0', 0x90, 0};
  const CK_BYTE version[] = {6, 0, 0, 0x90, 0},
                config[] = {1, 0xe0, 5, 0x16, 0xe1, 0x53, 0x15, 0x54, 0xe2, 0xe3, 0x90, 0};
  unsigned exchanges = 0;
  while (step == CNK_LIBCANO_STEP_EXCHANGE) {
    CK_BYTE command[300];
    size_t length = sizeof(command);
    CHECK(++exchanges <= 16);
    CHECK(cnk_operation_command(op, command, &length) == CNK_LIBCANO_OK && length >= 4);
    const CK_BYTE *response = unavailable;
    size_t responseLen = sizeof(unavailable);
    if (command[1] == 0xa4) {
      response = ok;
      responseLen = sizeof(ok);
    } else if (command[1] == 0x31 && command[2] == 0) {
      response = fw;
      responseLen = sizeof(fw);
    } else if (command[1] == 0xfd) {
      response = version;
      responseLen = sizeof(version);
    } else if (command[1] == 0xee) {
      response = config;
      responseLen = sizeof(config);
    }
    CHECK(cnk_operation_advance(op, response, responseLen, &step, NULL) == CNK_LIBCANO_OK);
  }
  CHECK(step == CNK_LIBCANO_STEP_DONE);
  void *profile = NULL;
  CHECK(cnk_operation_take_profile(op, &profile) == CNK_LIBCANO_OK);
  cnk_operation_free(op);
  token.libcanokeyProfile = profile;
  keySession.token = &token;
}
_Atomic CK_BBOOL g_cnk_is_managed_mode = CK_TRUE;
static CK_RV authRv;
static LONG transportRv;
static unsigned connections, sends;
static CK_BYTE response[8];
static DWORD responseLen;

CK_RV cnk_authenticate_admin_for_write(CK_SLOT_ID id, CNK_PKCS11_SESSION *session, SCARDHANDLE *card) {
  (void)session;
  CHECK(id == 0 && connections == 0);
  *card = 0;
  if (authRv != CKR_OK)
    return authRv;
  connections++;
  *card = 123;
  return CKR_OK;
}

void cnk_disconnect_card(SCARDHANDLE card) {
  CHECK(card == 123 && connections == 1);
  connections--;
}

LONG cnk_transceive_apdu(SCARDHANDLE card, const CK_BYTE *apdu, CK_ULONG len, CK_BYTE *out, DWORD *outLen) {
  const CK_BYTE expected[] = {0, 0xF7, 0, 0x9C, 0};
  CHECK(card == 123 && connections == 1);
  CHECK(len == sizeof(expected) && memcmp(apdu, expected, len) == 0);
  sends++;
  if (transportRv != SCARD_S_SUCCESS)
    return transportRv;
  CHECK(*outLen >= responseLen);
  memcpy(out, response, responseLen);
  *outLen = responseLen;
  return SCARD_S_SUCCESS;
}

static void check(unsigned sw, CK_RV expected) {
  response[0] = (CK_BYTE)(sw >> 8);
  response[1] = (CK_BYTE)sw;
  responseLen = 2;
  SCARDHANDLE card = 0;
  CHECK(cnk_begin_key_write(0, &keySession, 0x9C, &card) == expected);
  if (expected == CKR_OK) {
    // Ownership transfers to the writer without ending the transaction.
    CHECK(card == 123 && connections == 1);
    cnk_disconnect_card(card);
  } else {
    CHECK(card == 0 && connections == 0);
  }
}

int main(void) {
  make_profile();
  check(0x6A88, CKR_OK);
  check(0x6A82, CKR_OK);                // legacy empty-key status
  check(0x9000, CKR_ACTION_PROHIBITED); // no algorithm parsing can grant access
  const unsigned unknown[] = {0x6D00, 0x6A81, 0x6A86, 0x6982, 0x6400, 0x6900};
  for (unsigned i = 0; i < sizeof(unknown) / sizeof(unknown[0]); i++)
    check(unknown[i], CKR_DEVICE_ERROR);
  SCARDHANDLE card = 0;
  responseLen = 1;
  CHECK(cnk_begin_key_write(0, &keySession, 0x9C, &card) == CKR_DEVICE_ERROR);
  CHECK(card == 0 && connections == 0);
  // A malformed reply with an absence suffix is not proof of an empty slot.
  response[0] = 0x01;
  response[1] = 0x6A;
  response[2] = 0x88;
  responseLen = 3;
  CHECK(cnk_begin_key_write(0, &keySession, 0x9C, &card) == CKR_DEVICE_ERROR);
  CHECK(card == 0 && connections == 0);
  transportRv = SCARD_E_COMM_DATA_LOST;
  unsigned before = sends;
  check(0x6A88, CKR_DEVICE_ERROR);
  CHECK(sends == before + 1); // no retry or second SELECT
  transportRv = SCARD_S_SUCCESS;
  authRv = CKR_USER_NOT_LOGGED_IN;
  before = sends;
  check(0x6A88, CKR_USER_NOT_LOGGED_IN);
  CHECK(sends == before);
  authRv = CKR_OK;
  g_cnk_is_managed_mode = CK_FALSE;
  check(0x9000, CKR_OK); // standalone replacement behavior is unchanged
  CHECK(sends == before);
  cnk_profile_free(token.libcanokeyProfile);
  puts("Managed key-write occupancy contract tests passed.");
  return 0;
}
