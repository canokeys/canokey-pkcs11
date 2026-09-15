/* Failure injection at the C ABI/transport boundary exercises production
 * callers, including their cleanup and result-publication paths. */
#include "../../src/api/container_name.c"
#include "../../src/backend/piv_crypto.c"
#include "../../src/backend/piv_data.c"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(x)                                                                                                       \
  do {                                                                                                                 \
    if (!(x)) {                                                                                                        \
      fprintf(stderr, "%d: %s\n", __LINE__, #x);                                                                       \
      exit(1);                                                                                                         \
    }                                                                                                                  \
  } while (0)

struct CnkOperation {
  unsigned unused;
};
struct CnkPivContext {
  unsigned unused;
};
static struct CnkOperation op;
static struct CnkPivContext ctx;
static CNK_PKCS11_TOKEN_STATE token;
static CNK_PKCS11_SESSION session;
static unsigned cards, operations, contexts, sends, invalidations, locked, pinCopies;
static unsigned failAt, phase, endless, responseSize = 2, badCommand;
static uint32_t errorKind, profileStatus, publicAlgorithmStatus, finalStep = CNK_STEP_DONE;
static CK_RV lockError, unlockError;
static uint32_t publicFieldFailure;
_Atomic CK_ULONG g_cnk_managed_binding_epoch;
atomic_int g_cnk_log_level = CNK_LOG_LEVEL_NONE;
static char lastLog[1024], transcript[8192];

void cnk_printlogf(const int level, const char *function, const char *file, const int line, const char *format, ...) {
  (void)level;
  (void)function;
  (void)file;
  (void)line;
  va_list args;
  va_start(args, format);
  vsnprintf(lastLog, sizeof(lastLog), format, args);
  va_end(args);
  size_t used = strlen(transcript);
  snprintf(transcript + used, sizeof(transcript) - used, "%s\n", lastLog);
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
  return unlockError;
}
CK_RV cnk_ensure_libcanokey_profile(CNK_PKCS11_SESSION *s) {
  CHECK(s == &session && !cards);
  return CKR_OK;
}
CK_RV cnk_begin_piv_transaction(CK_SLOT_ID slot, SCARDHANDLE *card) {
  CHECK(slot == 0 && !cards);
  cards++;
  *card = 1;
  return CKR_OK;
}
CK_RV cnk_authenticate_admin_for_write(CK_SLOT_ID slot, CNK_PKCS11_SESSION *s, SCARDHANDLE *card) {
  CHECK(cnk_ensure_libcanokey_profile(s) == CKR_OK);
  return cnk_begin_piv_transaction(slot, card);
}
CK_RV cnk_begin_key_write(CK_SLOT_ID slot, CNK_PKCS11_SESSION *s, CK_BYTE pivSlot, SCARDHANDLE *card) {
  CHECK(pivSlot == 0x9c);
  return cnk_authenticate_admin_for_write(slot, s, card);
}
void cnk_disconnect_card(SCARDHANDLE card) {
  CHECK(card == 1 && cards == 1 && !locked);
  cards--;
}
void cnk_piv_public_cache_invalidate(CNK_PKCS11_SESSION *s) {
  CHECK(s == &session && cards == 1);
  invalidations++;
}
CK_RV cnk_token_copy_pin(CNK_PKCS11_SESSION *s, CK_BYTE *pin, CK_ULONG *len) {
  (void)s;
  (void)pin;
  (void)len;
  pinCopies++;
  return CKR_USER_NOT_LOGGED_IN;
}
CK_RV cnk_verify_piv_pin_with_session_ex(CK_SLOT_ID slot, CNK_PKCS11_SESSION *s, CK_UTF8CHAR_PTR pin, CK_ULONG len,
                                         CK_BYTE_PTR tries, SCARDHANDLE *card) {
  (void)slot;
  (void)s;
  (void)pin;
  (void)len;
  (void)tries;
  (void)card;
  abort();
}
static uint32_t status(cnk_error_v1 *error) {
  if (++phase != failAt)
    return CNK_OK;
  if (error) {
    error->kind = errorKind;
    error->reference = 3;
  }
  return CNK_PROTOCOL_ERROR;
}
uint32_t cnk_piv_context_new(const cnk_profile_t *profile, uint32_t state, cnk_piv_context_t **out,
                             cnk_error_v1 *error) {
  CHECK(profile && locked == 1 && state);
  uint32_t rv = status(error);
  if (!rv) {
    *out = &ctx;
    contexts++;
  }
  return rv;
}
void cnk_piv_context_free(cnk_piv_context_t *context) {
  CHECK(context == &ctx && contexts == 1);
  contexts--;
}
static uint32_t construct(const cnk_piv_context_t *context, cnk_operation_t **out, cnk_error_v1 *error) {
  CHECK(context == &ctx && cards == 1 && !operations && !locked);
  uint32_t rv = status(error);
  if (!rv) {
    *out = &op;
    operations++;
  }
  return rv;
}
CK_RV cnk_probe_device_profile(CK_SLOT_ID slot, uint32_t mode, cnk_profile_t **profile) {
  (void)slot;
  (void)mode;
  (void)profile;
  abort();
}
uint32_t cnk_profile_firmware_version(const cnk_profile_t *profile, uint32_t *version) {
  (void)profile;
  (void)version;
  abort();
}
uint32_t cnk_profile_model_copy(const cnk_profile_t *profile, uint8_t *output, size_t *length) {
  (void)profile;
  (void)output;
  (void)length;
  abort();
}
uint32_t cnk_profile_serial_u32(const cnk_profile_t *profile, uint32_t *serial) {
  (void)profile;
  (void)serial;
  abort();
}
void cnk_profile_free(cnk_profile_t *profile) {
  (void)profile;
  abort();
}
uint32_t cnk_profile_piv_require_algorithm(const cnk_profile_t *profile, uint32_t algorithm, cnk_error_v1 *error) {
  CHECK(profile == (void *)1 && (algorithm == CNK_ALGORITHM_RSA2048 || algorithm == CNK_ALGORITHM_P256) &&
        locked == 1 && !cards);
  if (error)
    error->kind = errorKind;
  return profileStatus;
}
uint32_t cnk_operation_key_algorithm(const cnk_operation_t *operation, uint32_t *algorithm) {
  CHECK(operation == &op && operations == 1);
  if (publicAlgorithmStatus)
    return publicAlgorithmStatus;
  *algorithm = CNK_ALGORITHM_RSA2048;
  return CNK_OK;
}
uint32_t cnk_piv_get_metadata_in_context_new(const cnk_piv_context_t *c, uint32_t ref,
                                             const cnk_operation_options_v1 *o, cnk_operation_t **out,
                                             cnk_error_v1 *e) {
  (void)c;
  (void)ref;
  (void)o;
  (void)out;
  (void)e;
  abort();
}
uint32_t cnk_operation_metadata(const cnk_operation_t *o, cnk_metadata_v1 *metadata) {
  (void)o;
  (void)metadata;
  abort();
}
uint32_t cnk_piv_generate_key_in_context_new(const cnk_piv_context_t *c, const cnk_piv_key_parameters_v1 *p,
                                             const cnk_operation_options_v1 *o, cnk_operation_t **out,
                                             cnk_error_v1 *e) {
  (void)p;
  (void)o;
  return construct(c, out, e);
}
uint32_t cnk_piv_import_key_in_context_new(const cnk_piv_context_t *c, const cnk_piv_key_parameters_v1 *p,
                                           const cnk_bytes_t *b, size_t n, const cnk_operation_options_v1 *o,
                                           cnk_operation_t **out, cnk_error_v1 *e) {
  CHECK(p->slot == 0x9c && p->algorithm == CNK_ALGORITHM_P256 && p->pin_policy == 1);
  CHECK(n == 1 && b[0].len == 32 && b[0].data[31] == 1);
  (void)o;
  return construct(c, out, e);
}
uint32_t cnk_piv_write_object_container_in_context_new(const cnk_piv_context_t *c, const uint8_t *tag, size_t tn,
                                                       const uint8_t *d, size_t n, const cnk_operation_options_v1 *o,
                                                       cnk_operation_t **out, cnk_error_v1 *e) {
  (void)tag;
  (void)tn;
  (void)d;
  (void)n;
  (void)o;
  return construct(c, out, e);
}
uint32_t cnk_piv_write_certificate_in_context_new(const cnk_piv_context_t *c, uint32_t slot, const uint8_t *der,
                                                  size_t len, const cnk_operation_options_v1 *o, cnk_operation_t **out,
                                                  cnk_error_v1 *e) {
  CHECK(slot == 0x9c && len == 3 && der[0] == 0x30 && der[1] == 1 && der[2] == 0);
  (void)o;
  return construct(c, out, e);
}
uint32_t cnk_piv_delete_certificate_in_context_new(const cnk_piv_context_t *c, uint32_t slot,
                                                   const cnk_operation_options_v1 *o, cnk_operation_t **out,
                                                   cnk_error_v1 *e) {
  (void)slot;
  (void)o;
  return construct(c, out, e);
}
uint32_t cnk_piv_set_container_name_in_context_new(const cnk_piv_context_t *c, uint32_t slot, const uint8_t *name,
                                                   size_t len, const cnk_operation_options_v1 *o, cnk_operation_t **out,
                                                   cnk_error_v1 *e) {
  (void)slot;
  (void)name;
  (void)len;
  (void)o;
  return construct(c, out, e);
}
uint32_t cnk_piv_container_name_validate(const uint8_t *name, size_t len, cnk_error_v1 *e) {
  (void)name;
  (void)len;
  (void)e;
  return CNK_OK;
}
uint32_t cnk_piv_read_container_name_in_context_new(const cnk_piv_context_t *c, uint32_t slot,
                                                    const cnk_operation_options_v1 *o, cnk_operation_t **out,
                                                    cnk_error_v1 *e) {
  (void)slot;
  (void)o;
  return construct(c, out, e);
}
uint32_t cnk_piv_read_object_container_in_context_new(const cnk_piv_context_t *c, const uint8_t *tag, size_t n,
                                                      const cnk_operation_options_v1 *o, cnk_operation_t **out,
                                                      cnk_error_v1 *e) {
  (void)tag;
  (void)n;
  (void)o;
  return construct(c, out, e);
}
uint32_t cnk_operation_start(cnk_operation_t *o, uint32_t *step, cnk_error_v1 *e) {
  CHECK(o == &op);
  *step = CNK_STEP_EXCHANGE;
  return status(e);
}
uint32_t cnk_operation_command(const cnk_operation_t *o, uint8_t *data, size_t *len) {
  CHECK(o == &op);
  uint32_t rv = status(NULL);
  if (rv)
    return rv;
  if (data) {
    CHECK(*len >= 5);
    memset(data, 0xAA, 5);
  }
  *len = badCommand ? (badCommand == 1 ? 0 : 2049) : 5;
  return CNK_OK;
}
LONG cnk_transceive_apdu(SCARDHANDLE card, const CK_BYTE *command, CK_ULONG len, CK_BYTE *out, DWORD *outLen) {
  CHECK(card == 1 && cards == 1 && !locked && len == 5 && command[0] == 0xAA);
  sends++;
  if (status(NULL))
    return SCARD_E_COMM_DATA_LOST;
  CHECK(*outLen >= 2);
  out[0] = 0x90;
  out[1] = 0;
  *outLen = responseSize;
  return SCARD_S_SUCCESS;
}
uint32_t cnk_operation_advance(cnk_operation_t *o, const uint8_t *r, size_t n, uint32_t *step, cnk_error_v1 *e) {
  CHECK(o == &op && r[0] == 0x90 && n >= 2 && n <= 8192);
  *step = endless ? CNK_STEP_EXCHANGE : finalStep;
  return status(e);
}
void cnk_operation_free(cnk_operation_t *o) {
  CHECK(o == &op && operations == 1);
  operations--;
}
uint32_t cnk_operation_error(const cnk_operation_t *o, cnk_error_v1 *e) {
  (void)o;
  (void)e;
  return CNK_INVALID_STATE;
}
uint32_t cnk_operation_result_copy_bytes(const cnk_operation_t *o, uint8_t *out, size_t *len) {
  CHECK(o == &op);
  uint32_t rv = status(NULL);
  if (rv)
    return rv;
  if (out) {
    CHECK(*len >= 2);
    out[0] = 'A';
    out[1] = 0;
  }
  *len = 2;
  return CNK_OK;
}
uint32_t cnk_operation_public_key_copy(const cnk_operation_t *o, uint32_t field, uint8_t *out, size_t *len) {
  CHECK(o == &op);
  if (field == publicFieldFailure)
    return CNK_RESULT_TYPE_MISMATCH;
  size_t n = field == CNK_PUBLIC_MODULUS ? 256 : 3;
  if (out) {
    CHECK(*len >= n);
    memset(out, field == CNK_PUBLIC_MODULUS ? 0xDD : 1, n);
  }
  *len = n;
  return CNK_OK;
}

/* Unused routes abort rather than silently granting authorization. */
CK_RV cnk_connect_for_private_key_operation(CK_SLOT_ID slot, CNK_PKCS11_SESSION *s, CK_BYTE policy, const CK_BYTE *pin,
                                            CK_ULONG n, SCARDHANDLE *card, const char *name) {
  (void)slot;
  (void)s;
  (void)policy;
  (void)pin;
  (void)n;
  (void)card;
  (void)name;
  abort();
}
#define PRIVATE_STUB(name)                                                                                             \
  uint32_t name(const cnk_piv_context_t *c, uint32_t slot, uint32_t algorithm, const uint8_t *data, size_t n,          \
                const cnk_operation_options_v1 *options, cnk_operation_t **out, cnk_error_v1 *e) {                     \
    (void)c;                                                                                                           \
    (void)slot;                                                                                                        \
    (void)algorithm;                                                                                                   \
    (void)data;                                                                                                        \
    (void)n;                                                                                                           \
    (void)options;                                                                                                     \
    (void)out;                                                                                                         \
    (void)e;                                                                                                           \
    abort();                                                                                                           \
  }
PRIVATE_STUB(cnk_piv_decrypt_in_context_new)
PRIVATE_STUB(cnk_piv_derive_in_context_new)
uint32_t cnk_piv_decapsulate_in_context_new(const cnk_piv_context_t *c, uint32_t slot, const uint8_t *data, size_t n,
                                            const cnk_operation_options_v1 *options, cnk_operation_t **out,
                                            cnk_error_v1 *e) {
  (void)c;
  (void)slot;
  (void)data;
  (void)n;
  (void)options;
  (void)out;
  (void)e;
  abort();
}
uint32_t cnk_piv_sign_in_context_new(const cnk_piv_context_t *c, uint32_t slot, uint32_t algorithm, uint32_t kind,
                                     const uint8_t *data, size_t n, const cnk_operation_options_v1 *options,
                                     cnk_operation_t **out, cnk_error_v1 *e) {
  (void)c;
  (void)slot;
  (void)algorithm;
  (void)kind;
  (void)data;
  (void)n;
  (void)options;
  (void)out;
  (void)e;
  abort();
}
uint32_t cnk_piv_sign_streaming_in_context_new(const cnk_piv_context_t *c, uint32_t slot, uint32_t mode,
                                               const uint8_t *data, size_t n, const uint8_t *context, size_t cn,
                                               const cnk_operation_options_v1 *options, cnk_operation_t **out,
                                               cnk_error_v1 *e) {
  (void)c;
  (void)slot;
  (void)mode;
  (void)data;
  (void)n;
  (void)context;
  (void)cn;
  (void)options;
  (void)out;
  (void)e;
  abort();
}
uint32_t cnk_operation_signature_p1363(const cnk_operation_t *o, uint8_t *out, size_t *n) {
  (void)o;
  (void)out;
  (void)n;
  abort();
}
CK_RV cnk_begin_card_transaction(CK_SLOT_ID slot, SCARDHANDLE *card) {
  (void)slot;
  (void)card;
  abort();
}
CK_RV cnk_api_admission_begin(CNK_API_ADMISSION_GUARD *g) {
  (void)g;
  abort();
}
void cnk_api_admission_end(CNK_API_ADMISSION_GUARD *g) {
  (void)g;
  abort();
}
CK_RV cnk_session_find(CK_SESSION_HANDLE h, CNK_PKCS11_SESSION **s) {
  (void)h;
  (void)s;
  abort();
}
void cnk_session_release_ref(CNK_PKCS11_SESSION **s) {
  (void)s;
  abort();
}
CK_RV cnk_token_begin_management_operation(CNK_PKCS11_SESSION *s) {
  (void)s;
  abort();
}
void cnk_token_end_management_operation(CNK_PKCS11_SESSION *s) {
  (void)s;
  abort();
}
CK_RV cnk_piv_v6_supported_on_card(SCARDHANDLE card, CK_BBOOL *supported) {
  CHECK(card != 0);
  *supported = CK_TRUE;
  return CKR_OK;
}

static void reset(void) {
  CHECK(!cards && !operations && !contexts && !locked);
  sends = invalidations = phase = failAt = errorKind = endless = badCommand = 0;
  lockError = unlockError = 0;
  profileStatus = publicAlgorithmStatus = pinCopies = 0;
  responseSize = 2;
  finalStep = CNK_STEP_DONE;
  session.token = &token;
  token.libcanokeyProfile = (void *)1;
  token.libcanokeyProfileEpoch = atomic_load(&g_cnk_managed_binding_epoch);
}
static CK_RV call(unsigned kind, CK_BYTE *out, CK_ULONG *len) {
  const CK_BYTE tag[] = {0x5f, 0xc1, 0x05};
  CK_BYTE value[] = {0x06, 1, 1};
  switch (kind) {
  case 0:
    return cnk_put_piv_data_libcanokey(0, &session, tag, 3, value, 3);
  case 1:
    return cnk_delete_piv_certificate_libcanokey(0, &session, 0x9c);
  case 2:
    return cnk_piv_generate_keypair(0, &session, CNK_ALGORITHM_RSA2048, 0x9c, 1, 1);
  case 3: {
    CK_BYTE scalar[32] = {0};
    scalar[31] = 1;
    CNK_PIV_IMPORT material = {.parameters = {sizeof(cnk_piv_key_parameters_v1), 0x9c, CNK_ALGORITHM_P256, 1, 1},
                               .components = {{scalar, sizeof(scalar)}},
                               .count = 1};
    return cnk_piv_import_key(0, &session, &material);
  }
  case 4:
    return container_name_operation(&session, 0x9c, CK_FALSE, NULL, 0, out, len);
  case 7:
    return container_name_operation(&session, 0x9c, CK_TRUE, value, 2, NULL, NULL);
  case 6: {
    CK_BYTE der[] = {0x30, 1, 0};
    return cnk_write_piv_certificate(0, &session, 0x9c, der, sizeof(der));
  }
  default:
    return cnk_get_piv_data_by_tag_with_session(0, &session, tag, 3, out, len, CK_TRUE);
  }
}
int main(void) {
  CK_BYTE output[512];
  CK_ULONG len;
  for (unsigned kind = 0; kind < 8; kind++) {
    // Every failure from context construction through advance must release all
    // resources and must not publish a read result or a successful mutation.
    for (unsigned failure = 1; failure <= 7; failure++) {
      reset();
      failAt = failure;
      memset(output, 0xCC, sizeof(output));
      len = sizeof(output);
      CHECK(call(kind, output, &len) == CKR_DEVICE_ERROR);
      CHECK(output[0] == 0xCC && len == sizeof(output));
      CHECK(invalidations == (kind == 7 ? failure >= 3 : (kind < 4 || kind == 6) && sends != 0));
      reset();
    }
    reset();
    lockError = CKR_CANT_LOCK;
    len = sizeof(output);
    CHECK(call(kind, output, &len) == CKR_CANT_LOCK && !sends && !invalidations);
    reset();
    token.libcanokeyProfileEpoch++;
    len = sizeof(output);
    CHECK(call(kind, output, &len) == CKR_DEVICE_ERROR && !sends);
    reset();
    len = sizeof(output);
    CHECK(call(kind, output, &len) == CKR_OK);
    CHECK(sends == 1 && invalidations == (kind < 4 || kind >= 6));
    reset();
  }
  reset();
  unlockError = CKR_CANT_LOCK;
  len = sizeof(output);
  CHECK(call(0, output, &len) == CKR_CANT_LOCK && !sends && !invalidations);
  reset();
  unlockError = CKR_CANT_LOCK;
  CHECK(call(2, output, &len) == CKR_CANT_LOCK && !sends && !invalidations);
  reset();
  profileStatus = CNK_INVALID_ARGUMENT;
  len = sizeof(output);
  CHECK(call(2, output, &len) == CKR_MECHANISM_INVALID && !sends && !invalidations);
  reset();
  // Unsupported and unknown firmware evidence must fail before authentication.
  profileStatus = CNK_PROTOCOL_ERROR;
  errorKind = CNK_ERROR_UNSUPPORTED_FEATURE;
  CHECK(call(2, output, &len) == CKR_MECHANISM_INVALID && !sends && !invalidations);
  reset();
  profileStatus = CNK_PROTOCOL_ERROR;
  errorKind = 14; // CapabilityUnknown has no guessed algorithm fallback.
  CHECK(call(2, output, &len) == CKR_DEVICE_ERROR && !sends && !invalidations);
  reset();
  // Getter failures, including a failure after copying the modulus, must
  // leave the complete caller snapshot untouched.
  CNK_PIV_PUBLIC_KEY publicKey, original;
  memset(&original, 0xcc, sizeof(original));
  for (unsigned failure = 0; failure < 3; failure++) {
    publicKey = original;
    operations = 1;
    publicAlgorithmStatus = failure == 0 ? CNK_RESULT_TYPE_MISMATCH : 0;
    publicFieldFailure = failure;
    CHECK(cnk_copy_piv_public_key(&op, &publicKey) == CKR_DEVICE_ERROR);
    CHECK(!memcmp(&publicKey, &original, sizeof(original)) && !sends);
    cnk_operation_free(&op);
    reset();
  }
  publicFieldFailure = 0;
  operations = 1;
  CHECK(cnk_copy_piv_public_key(&op, &publicKey) == CKR_OK);
  CHECK(publicKey.algorithm == CNK_ALGORITHM_RSA2048 && publicKey.valueLen == 256 && publicKey.exponentLen == 3);
  cnk_operation_free(&op);
  reset();
  for (unsigned n = 0; n < 2; n++) {
    reset();
    badCommand = n + 1;
    len = sizeof(output);
    CHECK(call(0, output, &len) == CKR_DEVICE_ERROR && sends == 0);
    reset();
  }
  for (unsigned n = 0; n < 2; n++) {
    reset();
    responseSize = n ? 8193 : 1;
    len = sizeof(output);
    CHECK(call(0, output, &len) == CKR_DEVICE_ERROR && sends == 1 && invalidations == 1);
    reset();
  }
  reset();
  endless = 1;
  len = sizeof(output);
  CHECK(call(0, output, &len) == CKR_DATA_LEN_RANGE && sends == 4096 && invalidations == 1);
  reset();
  reset();
  finalStep = 99;
  len = sizeof(output);
  CHECK(call(0, output, &len) == CKR_DEVICE_ERROR && sends == 1 && invalidations == 1);
  reset();
  for (unsigned k = 4; k < 6; k++) {
    reset();
    len = 1;
    memset(output, 0xCC, sizeof(output));
    CHECK(call(k, output, &len) == CKR_BUFFER_TOO_SMALL && len == 2 && output[0] == 0xCC && sends == 1);
    reset();
    len = 0;
    CHECK(call(k, NULL, &len) == CKR_OK && len == 2 && sends == 1);
    reset();
    for (unsigned failure = 8; failure <= 9; failure++) {
      reset();
      failAt = failure;
      len = sizeof(output);
      memset(output, 0xCC, sizeof(output));
      CHECK(call(k, output, &len) == CKR_DEVICE_ERROR && output[0] == 0xCC);
      reset();
    }
  }
  reset();
  const CK_BYTE adminTag[] = {0x5f, 0xff, 0};
  len = sizeof(output);
  SCARDHANDLE recoveryCard = 0;
  CHECK(cnk_begin_piv_transaction(0, &recoveryCard) == CKR_OK);
  CHECK(cnk_get_public_piv_data_on_card(&session, recoveryCard, adminTag, sizeof(adminTag), output, &len) == CKR_OK);
  CHECK(pinCopies == 0 && sends == 1 && cards == 1);
  cnk_disconnect_card(recoveryCard);
  reset();
  atomic_store(&g_cnk_log_level, CNK_LOG_LEVEL_DEBUG);
  transcript[0] = 0;
  len = sizeof(output);
  CHECK(call(5, output, &len) == CKR_OK);
  const char *cursor = transcript;
  const char *const boundaries[] = {"cnk_piv_context_new completed: status=0x0",
                                    "cnk_piv_read_object_container_in_context_new completed: status=0x0",
                                    "cnk_operation_start completed: status=0x0",
                                    "cnk_operation_command completed: status=0x0",
                                    "cnk_operation_command completed: status=0x0",
                                    "cnk_operation_advance completed: status=0x0",
                                    "cnk_operation_result_copy_bytes completed: status=0x0",
                                    "cnk_operation_result_copy_bytes completed: status=0x0",
                                    "cnk_operation_free completed",
                                    "cnk_piv_context_free completed"};
  for (size_t i = 0; i < sizeof(boundaries) / sizeof(boundaries[0]); ++i) {
    cursor = strstr(cursor, boundaries[i]);
    CHECK(cursor != NULL);
    cursor += strlen(boundaries[i]);
  }
  reset();
  transcript[0] = 0;
  failAt = 2;
  len = sizeof(output);
  CHECK(call(5, output, &len) == CKR_DEVICE_ERROR && sends == 0);
  CHECK(strstr(transcript, "cnk_piv_read_object_container_in_context_new completed: status=0x5"));
  CHECK(!strstr(transcript, "cnk_operation_start completed"));
  CHECK(strstr(transcript, "cnk_piv_context_free completed"));
  reset();
  cnk_error_v1 e = {.struct_size = sizeof(e), .kind = CNK_ERROR_NOT_FOUND};
  CHECK(cnk_piv_operation_status(CNK_OK, &e, CKR_DATA_INVALID) == CKR_OK);
  CHECK(cnk_piv_operation_status(CNK_PANIC, &e, CKR_DATA_INVALID) == CKR_DEVICE_ERROR);
  CHECK(cnk_piv_operation_status(CNK_PROTOCOL_ERROR, &e, CKR_DATA_INVALID) == CKR_DATA_INVALID);
  CHECK(cnk_piv_operation_status(CNK_PROTOCOL_ERROR, &e, CKR_KEY_HANDLE_INVALID) == CKR_KEY_HANDLE_INVALID);
  e.kind = CNK_ERROR_SECURITY_STATUS;
  CHECK(cnk_piv_operation_status(CNK_PROTOCOL_ERROR, &e, CKR_DATA_INVALID) == CKR_USER_NOT_LOGGED_IN);
  atomic_store(&g_cnk_log_level, CNK_LOG_LEVEL_DEBUG);
  e.kind = 3;
  e.phase = 4;
  e.reference = 0;
  e.presence_flags = 0;
  CHECK(cnk_piv_operation_status(CNK_PROTOCOL_ERROR, &e, CKR_DATA_INVALID) == CKR_DEVICE_ERROR);
  CHECK(strstr(lastLog, "InvalidResponse") && strstr(lastLog, "Parsing"));
  CHECK(strstr(lastLog, "SW=absent") && strstr(lastLog, "retries=absent"));
  e.kind = 6;
  e.phase = 3;
  e.reference = 1;
  e.presence_flags = 3;
  e.status_word = 0x63C2;
  e.retries_remaining = 2;
  CHECK(cnk_piv_operation_status(CNK_PROTOCOL_ERROR, &e, CKR_DATA_INVALID) == CKR_USER_NOT_LOGGED_IN);
  CHECK(strstr(lastLog, "AuthenticationFailed") && strstr(lastLog, "reference=PIN"));
  CHECK(strstr(lastLog, "SW=63C2") && strstr(lastLog, "retries=2"));
  e.kind = 1;
  e.phase = 0;
  e.presence_flags = 0;
  CHECK(cnk_piv_operation_status(CNK_INVALID_ARGUMENT, &e, CKR_DATA_INVALID) == CKR_ARGUMENTS_BAD);
  CHECK(strstr(lastLog, "InvalidArgument") && strstr(lastLog, "Construction"));
  CHECK(cnk_piv_operation_status(CNK_PANIC, NULL, CKR_DATA_INVALID) == CKR_DEVICE_ERROR);
  CHECK(strstr(lastLog, "Panic"));
  puts("PIV operation failure and ownership contracts passed");
  return 0;
}
