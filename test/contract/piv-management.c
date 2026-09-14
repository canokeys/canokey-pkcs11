/* Known-answer authentication through the production C backend and Rust ABI.
 * The only replacements are the caller-owned token lock and card transport. */
#include "api/session.h"
#include "backend/piv_operation.h"
#include "backend/protocol.h"
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
static CNK_PKCS11_SESSION session;
static unsigned cards, sends, locked, failAt, malformedAt, deniedAt;
static CK_RV lockError, credentialError;
static CK_BYTE key[24], plain[16], cipher[16];
static size_t blockLen;
static const char *firmware;
_Atomic CK_ULONG g_cnk_managed_binding_epoch;
atomic_int g_cnk_log_level = CNK_LOG_LEVEL_NONE;
void cnk_printlogf(const int level, const char *function, const char *file, const int line, const char *format, ...) {
  (void)level;
  (void)function;
  (void)file;
  (void)line;
  (void)format;
}
CK_RV cnk_mutex_lock(CNK_PKCS11_MUTEX *mutex) {
  (void)mutex;
  if (lockError)
    return lockError;
  CHECK(!locked);
  locked++;
  return CKR_OK;
}
CK_RV cnk_mutex_unlock(CNK_PKCS11_MUTEX *mutex) {
  (void)mutex;
  CHECK(locked == 1);
  locked--;
  return CKR_OK;
}
CK_RV cnk_ensure_libcanokey_profile(CNK_PKCS11_SESSION *s) {
  CHECK(s == &session && !cards && token.libcanokeyProfile);
  return CKR_OK;
}
CK_RV cnk_begin_card_transaction(CK_SLOT_ID slot, SCARDHANDLE *card) {
  (void)slot;
  (void)card;
  abort();
}
CK_RV cnk_begin_piv_transaction(CK_SLOT_ID slot, SCARDHANDLE *card) {
  CHECK(slot == 0 && !cards);
  cards++;
  *card = 1;
  return CKR_OK;
}
void cnk_disconnect_card(SCARDHANDLE card) {
  CHECK(card == 1 && cards == 1 && !locked);
  cards--;
}
CK_RV cnk_token_copy_management_key(CNK_PKCS11_SESSION *s, CK_BYTE *out) {
  CHECK(s == &session && !cards);
  if (credentialError)
    return credentialError;
  memcpy(out, key, 24);
  return CKR_OK;
}
CK_RV cnk_token_copy_pin(CNK_PKCS11_SESSION *s, CK_BYTE *p, CK_ULONG *n) {
  (void)s;
  (void)p;
  (void)n;
  abort();
}
CK_RV cnk_token_cache_pin(CNK_PKCS11_SESSION *s, CK_BYTE *p, CK_ULONG n) {
  (void)s;
  (void)p;
  (void)n;
  abort();
}
CK_RV cnk_token_update_cached_pin(CNK_PKCS11_SESSION *s, CK_BYTE *p, CK_ULONG n, CK_BYTE *q, CK_ULONG m) {
  (void)s;
  (void)p;
  (void)n;
  (void)q;
  (void)m;
  abort();
}
static size_t unhex(const char *s, CK_BYTE *out) {
  size_t n = 0;
  while (*s) {
    unsigned v;
    CHECK(sscanf(s, "%2x", &v) == 1);
    out[n++] = (CK_BYTE)v;
    s += 2;
  }
  return n;
}
static uint32_t probe(void *unused, const uint8_t *command, size_t n, uint8_t *out, size_t *len) {
  (void)unused;
  CHECK(!cards && n >= 4 && *len >= 32);
  size_t size = 0;
  if (command[1] == 0x31 && command[2] == 0) {
    size = strlen(firmware);
    memcpy(out, firmware, size);
  } else if (command[1] == 0xfd) {
    out[0] = 6;
    out[1] = out[2] = 0;
    size = 3;
  } else if (command[1] != 0xa4) {
    out[0] = 0x6d;
    out[1] = 0;
    *len = 2;
    return 0;
  }
  out[size++] = 0x90;
  out[size++] = 0;
  *len = size;
  return 0;
}
LONG cnk_transceive_apdu(SCARDHANDLE card, const CK_BYTE *command, CK_ULONG n, CK_BYTE *out, DWORD *len,
                         CK_BBOOL continuation) {
  CHECK(card == 1 && cards == 1 && !locked && *len >= 32);
  sends++;
  // A second SELECT here would erase management authorization.
  CHECK(command[1] != 0xa4);
  if (sends == 1) {
    const CK_BYTE expected[] = {0, 0xf7, 0, 0x9b, 0};
    CHECK(n == 5 && !memcmp(command, expected, 5));
    out[0] = 1;
    out[1] = 1;
    out[2] = blockLen == 8 ? 3 : 10;
    out[3] = 0x90;
    out[4] = 0;
    *len = 5;
  } else {
    CHECK(!continuation);
    CK_BYTE expected[32] = {0, 0x87, blockLen == 8 ? 3 : 10, 0x9b, 4, 0x7c, 2, 0x81, 0};
    size_t size = 9;
    if (sends == 3) {
      expected[4] = (CK_BYTE)(4 + blockLen);
      expected[6] = (CK_BYTE)(2 + blockLen);
      expected[7] = 0x82;
      expected[8] = (CK_BYTE)blockLen;
      memcpy(expected + 9, cipher, blockLen);
      size += blockLen;
    }
    if (blockLen == 8)
      expected[size++] = 0;
    CHECK(sends <= 3 && n == size && !memcmp(command, expected, size));
    if (sends == 2) {
      out[0] = 0x7c;
      out[1] = (CK_BYTE)(2 + blockLen);
      out[2] = 0x81;
      out[3] = (CK_BYTE)blockLen;
      memcpy(out + 4, plain, blockLen);
      out[4 + blockLen] = 0x90;
      out[5 + blockLen] = 0;
      *len = (DWORD)(6 + blockLen);
    } else {
      out[0] = 0x90;
      out[1] = 0;
      *len = 2;
    }
  }
  if (sends == failAt)
    return SCARD_E_COMM_DATA_LOST;
  if (sends == malformedAt) {
    out[0] = 0x90;
    out[1] = 0;
    *len = 2;
  }
  if (sends == deniedAt) {
    out[0] = 0x69;
    out[1] = 0x82;
    *len = 2;
  }
  return SCARD_S_SUCCESS;
}
int main(void) {
  session.token = &token;
  const char *versions[] = {"3.0.3", "3.1.0", "1.3"};
  for (unsigned v = 0; v < 3; v++) {
    firmware = versions[v];
    blockLen = v == 1 ? 16 : 8;
    unhex(v == 1 ? "000102030405060708090a0b0c0d0e0f1011121314151617"
                 : "0123456789abcdef23456789abcdef01456789abcdef0123",
          key);
    unhex(v == 1 ? "00112233445566778899aabbccddeeff" : "fedcba9876543210", plain);
    unhex(v == 1 ? "dda97ca4864cdfe06eaf70a0ec0d7191" : "0737f6c53750d4a4", cipher);
    CK_BYTE scratch[8192];
    CHECK(cnk_profile_probe(probe, NULL, scratch, sizeof(scratch), &token.libcanokeyProfile) == 0);
    for (unsigned write = 0; write < 2; write++) {
      for (unsigned fail = 0; fail <= 3; fail++) {
        failAt = fail;
        sends = 0;
        SCARDHANDLE card = 0;
        CK_RV rv = write ? cnk_authenticate_admin_for_write(0, &session, &card) : cnkVerifyManagementKey(&session, key);
        CHECK(rv == (fail ? CKR_DEVICE_ERROR : CKR_OK));
        CHECK(sends == (fail ? fail : 3));
        CHECK(cards == (write && !fail));
        if (cards)
          cnk_disconnect_card(card);
        CHECK(!cards && !locked);
      }
      failAt = 0;
      sends = 0;
      malformedAt = 2;
      SCARDHANDLE card = 0;
      CHECK((write ? cnk_authenticate_admin_for_write(0, &session, &card) : cnkVerifyManagementKey(&session, key)) ==
            CKR_DEVICE_ERROR);
      CHECK(!cards && sends == 2);
      malformedAt = 0;
      sends = 0;
      deniedAt = 3;
      CHECK((write ? cnk_authenticate_admin_for_write(0, &session, &card) : cnkVerifyManagementKey(&session, key)) ==
            CKR_PIN_INCORRECT);
      CHECK(!cards && sends == 3);
      deniedAt = 0;
      sends = 0;
      lockError = CKR_CANT_LOCK;
      CHECK((write ? cnk_authenticate_admin_for_write(0, &session, &card) : cnkVerifyManagementKey(&session, key)) ==
            CKR_CANT_LOCK);
      CHECK(!cards && sends == 1);
      lockError = 0;
    }
    cnk_profile_free(token.libcanokeyProfile);
    token.libcanokeyProfile = NULL;
  }
  puts("PIV management known-answer and transaction contracts passed");
  return 0;
}
