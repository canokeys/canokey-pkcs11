// Exercise the production extension with isolated lifecycle/session/transport
// seams. No PIN, key, or metadata write reaches a real card.
#include "api/session.h"
#include "backend/pcsc.h"
#include "internal/lifecycle.h"
#include "pkcs11_canokey.h"
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

static CNK_PKCS11_SESSION session;
static CK_RV admissionRv, findRv, reserveRv, authRv;
static unsigned admissions, refs, reservations, connections, sends, invalidations;
static CK_BYTE response[258], request[84];
static DWORD responseSize, requestSize;
static LONG transportRv;
static CK_BBOOL isWrite;
static CK_BBOOL v6Supported = CK_TRUE;
static CK_RV versionRv;
CK_RV cnk_piv_v6_supported_on_card(SCARDHANDLE card, CK_BBOOL *supported) {
  CHECK(card == 123 && connections == 1);
  *supported = v6Supported;
  return versionRv;
}

CK_RV cnk_api_admission_begin(CNK_API_ADMISSION_GUARD *g) {
  if (admissionRv)
    return admissionRv;
  g->active = CK_TRUE;
  admissions++;
  return CKR_OK;
}
void cnk_api_admission_end(CNK_API_ADMISSION_GUARD *g) {
  if (g->active)
    admissions--;
}
CK_RV cnk_session_find(CK_SESSION_HANDLE handle, CNK_PKCS11_SESSION **out) {
  CHECK(handle == 1);
  if (findRv)
    return findRv;
  *out = &session;
  refs++;
  return CKR_OK;
}
void cnk_session_release_ref(CNK_PKCS11_SESSION **s) {
  if (*s) {
    refs--;
    *s = NULL;
  }
}
CK_RV cnk_token_begin_management_operation(CNK_PKCS11_SESSION *s) {
  CHECK(s == &session && refs == 1);
  if (reserveRv)
    return reserveRv;
  reservations++;
  return CKR_OK;
}
void cnk_token_end_management_operation(CNK_PKCS11_SESSION *s) {
  CHECK(s == &session && reservations == 1);
  reservations--;
}
CK_RV cnk_begin_piv_transaction(CK_SLOT_ID id, SCARDHANDLE *card) {
  CHECK(id == session.slotId && refs == 1);
  connections++;
  *card = 123;
  return CKR_OK;
}
CK_RV cnk_authenticate_admin_for_write(CK_SLOT_ID id, CNK_PKCS11_SESSION *s, SCARDHANDLE *card) {
  CHECK(s == &session && reservations == 1);
  if (authRv)
    return authRv;
  return cnk_begin_piv_transaction(id, card);
}
void cnk_disconnect_card(SCARDHANDLE card) {
  CHECK(card == 123 && connections == 1);
  connections--;
}
void cnk_piv_public_cache_invalidate(CNK_PKCS11_SESSION *s) {
  CHECK(s == &session);
  invalidations++;
}
LONG cnk_transceive_apdu(SCARDHANDLE card, const CK_BYTE *send, CK_ULONG sendLen, CK_BYTE *recv, DWORD *recvLen,
                         CK_BBOOL sensitive) {
  (void)sensitive;
  CHECK(card == 123 && connections == 1 && refs == 1 && admissions == 1);
  CHECK(sendLen <= sizeof(request) && send[0] == 0 && send[1] == 0xF5);
  CHECK(send[2] == (isWrite ? 1 : 0));
  CHECK(!isWrite || reservations == 1);
  sends++;
  memcpy(request, send, sendLen);
  requestSize = sendLen;
  if (transportRv)
    return transportRv;
  CHECK(*recvLen >= responseSize);
  memcpy(recv, response, responseSize);
  *recvLen = responseSize;
  return SCARD_S_SUCCESS;
}

static void reply(unsigned sw, const CK_BYTE *data, unsigned len) {
  if (len)
    memcpy(response, data, len);
  response[len] = (CK_BYTE)(sw >> 8);
  response[len + 1] = (CK_BYTE)sw;
  responseSize = len + 2;
}
static void clean(void) { CHECK(admissions == 0 && refs == 0 && reservations == 0 && connections == 0); }

int main(void) {
  session.flags = CKF_RW_SESSION;
  CK_BYTE name[] = {'t', 0, 'q', 0, '-', 0, 0x3D, 0xD8, 0, 0xDE}; // includes a surrogate pair
  CK_BYTE out[80];
  CK_ULONG len;
  reply(0x9000, name, sizeof(name));
  len = 0;
  CHECK(C_CNK_GetContainerName(1, 0x9C, NULL, &len) == CKR_OK && len == sizeof(name));
  clean();
  CHECK(requestSize == 5 && request[2] == 0 && request[3] == 0x9C && request[4] == 0);
  memset(out, 0xCC, sizeof(out));
  len = 1;
  CHECK(C_CNK_GetContainerName(1, 0x9C, out, &len) == CKR_BUFFER_TOO_SMALL && len == sizeof(name));
  CHECK(out[0] == 0xCC);
  clean();
  len = sizeof(out);
  CHECK(C_CNK_GetContainerName(1, 0x9C, out, &len) == CKR_OK && !memcmp(out, name, sizeof(name)));
  clean();
  reply(0x9000, NULL, 0);
  for (unsigned slot = 0; slot <= 255; slot++) {
    CK_BBOOL valid =
        slot == 0x9A || slot == 0x9C || slot == 0x9D || slot == 0x9E || (slot >= 0x82 && slot <= 0x95) || slot == 0xF9;
    len = sizeof(out);
    CHECK(C_CNK_GetContainerName(1, (CK_BYTE)slot, out, &len) == (valid ? CKR_OK : CKR_ARGUMENTS_BAD));
    clean();
  }
  const unsigned statuses[] = {0x6D00, 0x6A81, 0x6A88, 0x6982, 0x6A80, 0x6A86, 0x6700, 0x6900, 0x6A82};
  const CK_RV errors[] = {CKR_DEVICE_ERROR,       CKR_DEVICE_ERROR, CKR_KEY_HANDLE_INVALID,
                          CKR_USER_NOT_LOGGED_IN, CKR_DATA_INVALID, CKR_ARGUMENTS_BAD,
                          CKR_DATA_LEN_RANGE,     CKR_DEVICE_ERROR, CKR_DEVICE_ERROR};
  for (unsigned i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++) {
    reply(statuses[i], NULL, 0);
    len = sizeof(out);
    CHECK(C_CNK_GetContainerName(1, 0x9A, out, &len) == errors[i]);
    clean();
  }
  CK_BYTE invalid[][4] = {{0, 0, 0, 0}, {0, 0xD8, 'a', 0}, {0, 0xDC, 'a', 0}};
  for (unsigned i = 0; i < 3; i++) {
    reply(0x9000, invalid[i], 4);
    len = sizeof(out);
    CHECK(C_CNK_GetContainerName(1, 0x9A, out, &len) == CKR_DATA_INVALID);
    clean();
    CHECK(C_CNK_SetContainerName(1, 0x9A, invalid[i], 4) == CKR_DATA_INVALID);
    clean();
  }
  reply(0x9000, name, 1);
  len = sizeof(out);
  CHECK(C_CNK_GetContainerName(1, 0x9A, out, &len) == CKR_DATA_INVALID);
  clean();
  responseSize = 1;
  CHECK(C_CNK_GetContainerName(1, 0x9A, out, &len) == CKR_DEVICE_ERROR);
  clean();
  isWrite = CK_TRUE;
  reply(0x9000, NULL, 0);
  CHECK(C_CNK_SetContainerName(1, 0xF9, name, sizeof(name)) == CKR_OK);
  clean();
  CHECK(requestSize == 5 + sizeof(name) && request[3] == 0xF9 && request[4] == sizeof(name));
  CHECK(!memcmp(request + 5, name, sizeof(name)) && invalidations == 1);
  CHECK(C_CNK_SetContainerName(1, 0x82, NULL, 0) == CKR_OK);
  clean();
  CHECK(requestSize == 5 && request[4] == 0);
  session.flags = 0;
  CHECK(C_CNK_SetContainerName(1, 0x82, name, sizeof(name)) == CKR_SESSION_READ_ONLY);
  clean();
  session.flags = CKF_RW_SESSION;
  v6Supported = CK_FALSE;
  unsigned oldSends = sends;
  CHECK(C_CNK_SetContainerName(1, 0x82, name, sizeof(name)) == CKR_FUNCTION_NOT_SUPPORTED);
  clean();
  CHECK(C_CNK_GetContainerName(1, 0x82, out, &len) == CKR_FUNCTION_NOT_SUPPORTED);
  clean();
  CHECK(sends == oldSends); // old firmware is never probed with F5
  versionRv = CKR_DEVICE_ERROR;
  CHECK(C_CNK_GetContainerName(1, 0x82, out, &len) == CKR_DEVICE_ERROR);
  clean();
  CHECK(C_CNK_SetContainerName(1, 0x82, name, sizeof(name)) == CKR_DEVICE_ERROR);
  clean();
  CHECK(sends == oldSends);
  versionRv = CKR_OK;
  v6Supported = CK_TRUE;
  reserveRv = CKR_USER_NOT_LOGGED_IN;
  CHECK(C_CNK_SetContainerName(1, 0x82, name, sizeof(name)) == reserveRv);
  clean();
  reserveRv = CKR_OPERATION_ACTIVE;
  CHECK(C_CNK_SetContainerName(1, 0x82, name, sizeof(name)) == reserveRv);
  clean();
  reserveRv = CKR_OK;
  authRv = CKR_DEVICE_ERROR;
  CHECK(C_CNK_SetContainerName(1, 0x82, name, sizeof(name)) == authRv);
  clean();
  authRv = CKR_OK;
  transportRv = SCARD_E_COMM_DATA_LOST;
  unsigned before = sends;
  CHECK(C_CNK_SetContainerName(1, 0x82, name, sizeof(name)) == CKR_DEVICE_ERROR);
  clean();
  CHECK(sends == before + 1); // never retry a possibly committed write
  transportRv = 0;
  reply(0x6900, NULL, 0);
  CHECK(C_CNK_SetContainerName(1, 0x82, name, sizeof(name)) == CKR_DEVICE_ERROR);
  clean();
  findRv = CKR_SESSION_HANDLE_INVALID;
  CHECK(C_CNK_SetContainerName(1, 0x82, name, sizeof(name)) == findRv);
  clean();
  admissionRv = CKR_CRYPTOKI_NOT_INITIALIZED;
  CHECK(C_CNK_GetContainerName(1, 0x82, out, &len) == admissionRv);
  clean();
  puts("F5 container-name API/transport contract tests passed.");
  return 0;
}
