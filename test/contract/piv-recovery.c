/* Production PUK policy entry point and Rust parser; the card mutation is a
 * counted test seam so malformed policy can never consume a real PUK retry. */
#include "pkcs11.h"
// Internal linkage drops unrelated vendor entry points from this focused host.
#undef CK_DEFINE_FUNCTION
#define CK_DEFINE_FUNCTION(returnType, name) static returnType name
#include "../../src/api/canokey_ext.c"
#include "api/session.h"
#include "backend/pcsc.h"
#include "internal/lifecycle.h"
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
static CNK_PKCS11_SESSION session;
static unsigned admissions, refs, reservations, mutations, reads, cards;
static CK_RV readStatus, reserveStatus, profileStatus, connectStatus, mutationStatus;
static const CK_BYTE *policy;
static CK_ULONG policyLen;
atomic_int g_cnk_log_level = CNK_LOG_LEVEL_NONE;
void cnk_printlogf(const int l, const char *fn, const char *file, const int line, const char *format, ...) {
  (void)l;
  (void)fn;
  (void)file;
  (void)line;
  (void)format;
}
static CK_RV C_CNK_Login(CK_SESSION_HANDLE handle, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pin, CK_ULONG pinLen,
                         CK_BYTE_PTR tries) {
  (void)handle;
  (void)userType;
  (void)pin;
  (void)pinLen;
  (void)tries;
  abort();
}
static CK_RV C_CNK_LoginProtectedManagementKey(CK_SESSION_HANDLE handle, CK_BYTE_PTR key, CK_ULONG keyLen) {
  (void)handle;
  (void)key;
  (void)keyLen;
  abort();
}
CK_RV cnk_mutex_lock(CNK_PKCS11_MUTEX *mutex) {
  (void)mutex;
  abort();
}
CK_RV cnk_mutex_unlock(CNK_PKCS11_MUTEX *mutex) {
  (void)mutex;
  abort();
}
CK_RV cnk_ensure_libcanokey_profile(CNK_PKCS11_SESSION *s) {
  CHECK(s == &session && reservations == 1 && !cards);
  return profileStatus;
}
CK_RV cnk_begin_piv_transaction(CK_SLOT_ID slot, SCARDHANDLE *card) {
  CHECK(slot == session.slotId && reservations == 1 && !cards);
  if (connectStatus)
    return connectStatus;
  cards++;
  *card = 1;
  return CKR_OK;
}
void cnk_disconnect_card(SCARDHANDLE card) {
  CHECK(card == 1 && cards == 1 && reservations == 1);
  cards--;
}
LONG cnk_transceive_apdu(SCARDHANDLE card, const CK_BYTE *command, CK_ULONG commandLen, CK_BYTE *response,
                         DWORD *responseLen) {
  (void)card;
  (void)command;
  (void)commandLen;
  (void)response;
  (void)responseLen;
  abort();
}
CK_RV cnk_api_admission_begin(CNK_API_ADMISSION_GUARD *g) {
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
CK_RV cnk_token_begin_card_operation(CNK_PKCS11_SESSION *s) {
  CHECK(s == &session && refs == 1);
  if (reserveStatus)
    return reserveStatus;
  reservations++;
  return CKR_OK;
}
void cnk_token_end_management_operation(CNK_PKCS11_SESSION *s) {
  CHECK(s == &session && reservations == 1);
  reservations--;
}
CK_RV cnk_get_public_piv_data_on_card(CNK_PKCS11_SESSION *s, SCARDHANDLE card, const CK_BYTE *tag, CK_ULONG tagLen,
                                      CK_BYTE *out, CK_ULONG *len) {
  const CK_BYTE expected[] = {0x5f, 0xff, 0};
  CHECK(s == &session && reservations == 1 && card == 1 && cards == 1 && tagLen == 3 && !memcmp(tag, expected, 3));
  reads++;
  if (readStatus)
    return readStatus;
  CHECK(*len >= policyLen);
  memcpy(out, policy, policyLen);
  *len = policyLen;
  return CKR_OK;
}
CK_RV cnk_unblock_piv_pin_on_card(CNK_PKCS11_SESSION *s, SCARDHANDLE card, CK_UTF8CHAR_PTR puk, CK_ULONG pukLen,
                                  CK_UTF8CHAR_PTR pin, CK_ULONG pinLen, CK_BYTE_PTR tries) {
  (void)tries;
  CHECK(s == &session && reservations == 1 && card == 1 && cards == 1 && reads == 1 && pukLen == 8 && pinLen == 6 &&
        puk && pin);
  mutations++;
  return mutationStatus;
}
static void run(CK_RV expected, unsigned expectedMutations) {
  CK_BYTE puk[] = "fixture8", pin[] = "123456";
  reads = mutations = 0;
  CHECK(C_CNK_UnblockPIN(1, puk, 8, pin, 6, NULL) == expected);
  CHECK(mutations == expectedMutations && !admissions && !refs && !reservations && !cards);
}
int main(void) {
  session.flags = CKF_RW_SESSION;
  const CK_BYTE empty[] = {0x53, 0};
  policy = empty;
  policyLen = sizeof(empty);
  run(CKR_OK, 1);
  mutationStatus = CKR_PIN_INCORRECT;
  run(CKR_PIN_INCORRECT, 1);
  mutationStatus = CKR_OK;
  profileStatus = CKR_DEVICE_ERROR;
  run(CKR_DEVICE_ERROR, 0);
  CHECK(!reads);
  profileStatus = CKR_OK;
  connectStatus = CKR_DEVICE_ERROR;
  run(CKR_DEVICE_ERROR, 0);
  CHECK(!reads);
  connectStatus = CKR_OK;
  readStatus = CKR_DATA_INVALID;
  run(CKR_OK, 1);
  readStatus = CKR_OK;
  CK_BYTE protected[] = {0x53, 5, 0x80, 3, 0x81, 1, 3};
  policy = protected;
  policyLen = sizeof(protected);
  run(CKR_ACTION_PROHIBITED, 0);
  protected[6] = 2;
  run(CKR_ACTION_PROHIBITED, 0);
  const CK_BYTE malformed[] = {0x53, 2, 0x80, 1};
  policy = malformed;
  policyLen = sizeof(malformed);
  run(CKR_DEVICE_ERROR, 0);
  const CK_BYTE duplicate[] = {0x53, 8, 0x80, 6, 0x81, 1, 0, 0x81, 1, 3};
  policy = duplicate;
  policyLen = sizeof(duplicate);
  run(CKR_DEVICE_ERROR, 0);
  const CK_BYTE missingFlags[] = {0x53, 4, 0x80, 2, 0x82, 0};
  policy = missingFlags;
  policyLen = sizeof(missingFlags);
  run(CKR_DEVICE_ERROR, 0);
  readStatus = CKR_DEVICE_ERROR;
  run(CKR_DEVICE_ERROR, 0);
  readStatus = CKR_OK;
  session.flags = 0;
  run(CKR_SESSION_READ_ONLY, 0);
  CHECK(!reads);
  session.flags = CKF_RW_SESSION;
  reserveStatus = CKR_OPERATION_ACTIVE;
  run(CKR_OPERATION_ACTIVE, 0);
  CHECK(!reads);
  puts("PUK recovery protection and reservation contracts passed");
  return 0;
}
