#include "backend/pcsc.h"
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

LONG cnk_transceive_apdu(SCARDHANDLE card, const CK_BYTE *apdu, CK_ULONG len, CK_BYTE *out, DWORD *outLen,
                         CK_BBOOL getResponse) {
  const CK_BYTE expected[] = {0, 0xF7, 0, 0x9C, 0};
  CHECK(card == 123 && connections == 1 && getResponse);
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
  CHECK(cnk_begin_key_write(0, NULL, 0x9C, &card) == expected);
  if (expected == CKR_OK) {
    // Ownership transfers to the writer without ending the transaction.
    CHECK(card == 123 && connections == 1);
    cnk_disconnect_card(card);
  } else {
    CHECK(card == 0 && connections == 0);
  }
}

int main(void) {
  check(0x6A88, CKR_OK);
  check(0x6A82, CKR_OK);                // legacy empty-key status
  check(0x9000, CKR_ACTION_PROHIBITED); // no algorithm parsing can grant access
  const unsigned unknown[] = {0x6D00, 0x6A81, 0x6A86, 0x6982, 0x6400, 0x6900};
  for (unsigned i = 0; i < sizeof(unknown) / sizeof(unknown[0]); i++)
    check(unknown[i], CKR_DEVICE_ERROR);
  SCARDHANDLE card = 0;
  responseLen = 1;
  CHECK(cnk_begin_key_write(0, NULL, 0x9C, &card) == CKR_DEVICE_ERROR);
  CHECK(card == 0 && connections == 0);
  // A malformed reply with an absence suffix is not proof of an empty slot.
  response[0] = 0x01;
  response[1] = 0x6A;
  response[2] = 0x88;
  responseLen = 3;
  CHECK(cnk_begin_key_write(0, NULL, 0x9C, &card) == CKR_DEVICE_ERROR);
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
  puts("Managed key-write occupancy contract tests passed.");
  return 0;
}
