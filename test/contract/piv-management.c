/* Known-answer authentication through the production C backend and Rust ABI.
 * The only replacements are the caller-owned token lock and card transport. */
#include "api/session.h"
#include "backend/libcanokey.h"
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

#include "profile.h"
static CNK_PKCS11_TOKEN_STATE token;
static CNK_PKCS11_SESSION session;
static unsigned cards, sends, locked, failAt, malformedAt, deniedAt, invalidations;
static CK_BYTE generateWire, generatedResponse[400];
static unsigned credentialAction, credentialSw, cacheWrites, metadataProbes = 1;
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
CK_RV cnk_begin_key_write(CK_SLOT_ID slot, CNK_PKCS11_SESSION *s, CK_BYTE reference, SCARDHANDLE *card) {
  CHECK(reference == 0x9c);
  return cnk_authenticate_admin_for_write(slot, s, card);
}
void cnk_piv_public_cache_invalidate(CNK_PKCS11_SESSION *s) {
  CHECK(s == &session);
  invalidations++;
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
CK_RV cnk_token_cache_pin(CNK_PKCS11_SESSION *s, CK_BYTE *pin, CK_ULONG len) {
  CHECK(credentialAction && s == &session && pin && len >= 1 && len <= 8);
  cacheWrites++;
  return CKR_OK;
}
CK_RV cnk_token_update_cached_pin(CNK_PKCS11_SESSION *s, CK_BYTE *old, CK_ULONG oldLen, CK_BYTE *pin, CK_ULONG len) {
  CHECK(credentialAction == 3 && s == &session && old && oldLen == 6 && pin && len == 6);
  cacheWrites++;
  return CKR_OK;
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

LONG cnk_transceive_apdu(SCARDHANDLE card, const CK_BYTE *command, CK_ULONG n, CK_BYTE *out, DWORD *len) {
  CHECK(card == 1 && cards == 1 && !locked && *len >= 32);
  sends++;
  // A second SELECT here would erase management authorization.
  CHECK(command[1] != 0xa4);
  if (credentialAction) {
    static const char *const commands[] = {NULL,
                                           "0020008008313233343536ffff",
                                           "0020ff8000",
                                           "0024008010313233343536ffff363534333231ffff",
                                           "002400811031323334353637383837363534333231",
                                           "002c0080103132333435363738363534333231ffff"};
    CK_BYTE expected[32];
    size_t size = unhex(commands[credentialAction], expected);
    CHECK(sends == 1 && n == size && !memcmp(command, expected, size));
    if (failAt)
      return SCARD_E_COMM_DATA_LOST;
    out[0] = credentialSw >> 8;
    out[1] = credentialSw;
    *len = 2;
    return SCARD_S_SUCCESS;
  }
  if (generateWire && sends == 4) {
    const CK_BYTE expected[] = {0, 0x47, 0, 0x9c, 11, 0xac, 9, 0x80, 1, generateWire, 0xaa, 1, 1, 0xab, 1, 1};
    CHECK(n == sizeof(expected) && !memcmp(command, expected, sizeof(expected)));
    CHECK(*len >= 258);
    const CK_BYTE prefix[] = {0x7f, 0x49, 0x82, 1, 0x89, 0x81, 0x82, 1, 0x80};
    memcpy(generatedResponse, prefix, sizeof(prefix));
    memset(generatedResponse + sizeof(prefix), 0xa5, 384);
    generatedResponse[sizeof(prefix) + 383] = 0xa7;
    const CK_BYTE suffix[] = {0x82, 3, 1, 0, 1, 0x90, 0};
    memcpy(generatedResponse + sizeof(prefix) + 384, suffix, sizeof(suffix));
    memcpy(out, generatedResponse, 256);
    out[256] = 0x61;
    out[257] = 142;
    *len = 258;
  } else if (generateWire && sends == 5) {
    const CK_BYTE expected[] = {0, 0xc0, 0, 0, 142};
    CHECK(n == sizeof(expected) && !memcmp(command, expected, sizeof(expected)));
    CHECK(*len >= 144);
    memcpy(out, generatedResponse + 256, 144);
    *len = 144;
  } else if (metadataProbes && sends == 1) {
    const CK_BYTE expected[] = {0, 0xf7, 0, 0x9b, 0};
    CHECK(n == 5 && !memcmp(command, expected, 5));
    out[0] = 1;
    out[1] = 1;
    out[2] = blockLen == 8 ? 3 : 10;
    out[3] = 0x90;
    out[4] = 0;
    *len = 5;
  } else {
    CK_BYTE expected[32] = {0, 0x87, blockLen == 8 ? 3 : 10, 0x9b, 4, 0x7c, 2, 0x81, 0};
    size_t size = 9;
    if (sends == metadataProbes + 2) {
      expected[4] = (CK_BYTE)(4 + blockLen);
      expected[6] = (CK_BYTE)(2 + blockLen);
      expected[7] = 0x82;
      expected[8] = (CK_BYTE)blockLen;
      memcpy(expected + 9, cipher, blockLen);
      size += blockLen;
    }
    if (blockLen == 8)
      expected[size++] = 0;
    CHECK(sends <= metadataProbes + 2 && n == size && !memcmp(command, expected, size));
    if (sends == metadataProbes + 1) {
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
static void make_profile(cnk_profile_t **profile) {
  CHECK(!cards);
  *profile = test_profile(firmware, generateWire);
}

static void protocol_contract(void) {
  cnk_operation_t *op = NULL;
  cnk_error_v1 error = {.struct_size = sizeof(error)};
  uint32_t step = 0;
  CHECK(cnk_piv_read_version_selected_new(NULL, &op, &error) == CNK_OK);
  CHECK(cnk_operation_start(op, &step, &error) == CNK_OK && step == CNK_STEP_EXCHANGE);
  const CK_BYTE first[] = {0, 0xfd, 0, 0, 0}, next[] = {0, 0xc0, 0, 0, 2};
  CK_BYTE command[8];
  size_t size = sizeof(command);
  CHECK(cnk_operation_command(op, command, &size) == CNK_OK && size == 5 && !memcmp(command, first, 5));
  const CK_BYTE partial[] = {6, 0x61, 2};
  CHECK(cnk_operation_advance(op, partial, sizeof(partial), &step, &error) == CNK_OK);
  size = sizeof(command);
  CHECK(cnk_operation_command(op, command, &size) == CNK_OK && size == 5 && !memcmp(command, next, 5));
  const CK_BYTE final[] = {0, 0, 0x90, 0};
  CHECK(cnk_operation_advance(op, final, sizeof(final), &step, &error) == CNK_OK && step == CNK_STEP_DONE);
  size = 0;
  CHECK(cnk_operation_result_copy_bytes(op, NULL, &size) == CNK_OK && size == 3);
  CK_BYTE result[4] = {0xcc, 0xcc, 0xcc, 0xcc};
  size = 2;
  CHECK(cnk_operation_result_copy_bytes(op, result, &size) == CNK_BUFFER_TOO_SMALL && size == 3 && result[0] == 0xcc);
  CHECK(cnk_operation_result_copy_bytes(op, result, &size) == CNK_OK && !memcmp(result, "\6\0\0", 3) &&
        result[3] == 0xcc);
  cnk_operation_free(op);
}

int main(void) {
  protocol_contract();
  session.token = &token;
  const char *versions[] = {"3.0.3", "3.1.0", "1.3"};
  for (unsigned v = 0; v < 3; v++) {
    firmware = versions[v];
    blockLen = v == 1 ? 16 : 8;
    metadataProbes = v == 2 ? 0 : 1;
    unhex(v == 1 ? "000102030405060708090a0b0c0d0e0f1011121314151617"
                 : "0123456789abcdef23456789abcdef01456789abcdef0123",
          key);
    unhex(v == 1 ? "00112233445566778899aabbccddeeff" : "fedcba9876543210", plain);
    unhex(v == 1 ? "dda97ca4864cdfe06eaf70a0ec0d7191" : "0737f6c53750d4a4", cipher);
    make_profile(&token.libcanokeyProfile);
    for (unsigned write = 0; write < 2; write++) {
      for (unsigned fail = 0; fail <= metadataProbes + 2; fail++) {
        failAt = fail;
        sends = 0;
        SCARDHANDLE card = 0;
        CK_RV rv = write ? cnk_authenticate_admin_for_write(0, &session, &card) : cnkVerifyManagementKey(&session, key);
        CHECK(rv == (fail ? CKR_DEVICE_ERROR : CKR_OK));
        CHECK(sends == (fail ? fail : metadataProbes + 2));
        CHECK(cards == (write && !fail));
        if (cards)
          cnk_disconnect_card(card);
        CHECK(!cards && !locked);
      }
      failAt = 0;
      sends = 0;
      malformedAt = metadataProbes + 1;
      SCARDHANDLE card = 0;
      CHECK((write ? cnk_authenticate_admin_for_write(0, &session, &card) : cnkVerifyManagementKey(&session, key)) ==
            CKR_DEVICE_ERROR);
      CHECK(!cards && sends == metadataProbes + 1);
      malformedAt = 0;
      sends = 0;
      deniedAt = metadataProbes + 2;
      CHECK((write ? cnk_authenticate_admin_for_write(0, &session, &card) : cnkVerifyManagementKey(&session, key)) ==
            CKR_PIN_INCORRECT);
      CHECK(!cards && sends == metadataProbes + 2);
      deniedAt = 0;
      sends = 0;
      lockError = CKR_CANT_LOCK;
      CHECK((write ? cnk_authenticate_admin_for_write(0, &session, &card) : cnkVerifyManagementKey(&session, key)) ==
            CKR_CANT_LOCK);
      CHECK(!cards && sends == 0);
      lockError = 0;
    }
    cnk_profile_free(token.libcanokeyProfile);
    token.libcanokeyProfile = NULL;
  }
  // The actual Rust profile maps D1 to RSA-3072. The C adapter must pass
  // the semantic type to generation and complete the chained Rust key parser.
  generateWire = 0xd1;
  metadataProbes = 1;
  firmware = "3.1.0";
  blockLen = 16;
  unhex("000102030405060708090a0b0c0d0e0f1011121314151617", key);
  unhex("00112233445566778899aabbccddeeff", plain);
  unhex("dda97ca4864cdfe06eaf70a0ec0d7191", cipher);
  make_profile(&token.libcanokeyProfile);
  sends = failAt = malformedAt = deniedAt = 0;
  lockError = credentialError = CKR_OK;
  CK_RV generateRv = cnk_piv_generate_keypair(0, &session, CNK_ALGORITHM_RSA3072, 0x9c, 1, 1);
  if (generateRv != CKR_OK)
    fprintf(stderr, "Generation failed: rv=%lx sends=%u\n", generateRv, sends);
  CHECK(generateRv == CKR_OK);
  CHECK(sends == 5 && invalidations == 1 && !cards && !locked);
  sends = 0;
  CHECK(cnk_piv_generate_keypair(0, &session, 0xfe, 0x9c, 1, 1) == CKR_MECHANISM_INVALID);
  CHECK(!sends && !cards && !locked);
  cnk_profile_free(token.libcanokeyProfile);
  generateWire = 0;
  make_profile(&token.libcanokeyProfile);
  CK_BYTE pin[] = "123456", replacement[] = "654321", puk[] = "12345678", nextPuk[] = "87654321";
  for (credentialAction = 1; credentialAction <= 5; credentialAction++) {
    for (unsigned failure = 0; failure < 4; failure++) {
      sends = cacheWrites = 0;
      failAt = failure == 3;
      credentialSw = failure == 1 ? 0x63c2 : failure == 2 ? 0x6983 : 0x9000;
      CK_BYTE tries = 99;
      SCARDHANDLE card = 0;
      CK_RV rv;
      switch (credentialAction) {
      case 1:
        rv = cnk_verify_piv_pin_with_session_ex(0, &session, pin, 6, &tries, &card);
        break;
      case 2:
        rv = cnk_logout_piv_pin_with_session(&session);
        break;
      case 3:
        rv = cnk_change_piv_secret_with_session(0, &session, CNK_PIV_PIN_TYPE_PIN, pin, 6, replacement, 6, &tries);
        break;
      case 4:
        rv = cnk_change_piv_secret_with_session(0, &session, CNK_PIV_PIN_TYPE_PUK, puk, 8, nextPuk, 8, &tries);
        break;
      default:
        CHECK(cnk_begin_piv_transaction(0, &card) == CKR_OK);
        rv = cnk_unblock_piv_pin_on_card(&session, card, puk, 8, replacement, 6, &tries);
        break;
      }
      CK_RV expected = !failure                                ? CKR_OK
                       : credentialAction == 2 || failure == 3 ? CKR_DEVICE_ERROR
                       : failure == 1                          ? CKR_PIN_INCORRECT
                                                               : CKR_PIN_LOCKED;
      CHECK(rv == expected && sends == 1);
      CHECK(cacheWrites == (!failure && (credentialAction == 1 || credentialAction == 3 || credentialAction == 5)));
      if (card) {
        CHECK((!failure && credentialAction == 1) || credentialAction == 5);
        cnk_disconnect_card(card);
      }
      CHECK(!cards && !locked);
      if (failure == 1 && credentialAction != 2)
        CHECK(tries == 2);
    }
  }
  credentialAction = 1;
  credentialSw = 0x9000;
  failAt = sends = cacheWrites = 0;
  CHECK(cnk_verify_piv_pin_for_context(&session, pin, 6, NULL) == CKR_OK);
  CHECK(sends == 1 && !cacheWrites && !cards && !locked);
  sends = 0;
  CHECK(cnk_verify_piv_pin_with_session(0, &session, pin, 0, NULL) == CKR_PIN_LEN_RANGE && !sends);
  cnk_profile_free(token.libcanokeyProfile);
  puts("PIV management, configured algorithm and transaction contracts passed");
  return 0;
}
