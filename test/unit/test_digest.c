// clang-format off
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
// clang-format on

#include "logging.h"
#include "pcsc_backend.h"
#include "pkcs11.h"

#include <stdlib.h>
#include <string.h>

static void test_digest_sha1_one_shot(void **state) {
  CK_RV rv;
  CK_SESSION_HANDLE hSession;
  CNK_MANAGED_MODE_INIT_ARGS args = {.malloc_func = malloc, .free_func = free, .hSCardCtx = 1, .hScard = 1};
  rv = C_CNK_EnableManagedMode(&args);
  assert_int_equal(rv, CKR_OK);
  rv = C_Initialize(NULL);
  assert_int_equal(rv, CKR_OK);
  rv = C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
  assert_int_equal(rv, CKR_OK);

  CK_MECHANISM mechanism = {.mechanism = CKM_SHA_1, .pParameter = NULL, .ulParameterLen = 0};
  rv = C_DigestInit(hSession, &mechanism);
  assert_int_equal(rv, CKR_OK);

  const char *msg = "hello world";
  CK_ULONG msg_len = strlen(msg);
  CK_ULONG digest_len = 0;
  rv = C_Digest(hSession, (CK_BYTE_PTR)msg, msg_len, NULL, &digest_len);
  assert_int_equal(rv, CKR_OK);
  assert_int_equal(digest_len, 20);

  CK_BYTE digest[64];
  CK_ULONG buf_len = digest_len;
  rv = C_Digest(hSession, (CK_BYTE_PTR)msg, msg_len, digest, &buf_len);
  assert_int_equal(rv, CKR_OK);
  assert_int_equal(buf_len, digest_len);

  static const CK_BYTE expected[20] = {0x2a, 0xae, 0x6c, 0x35, 0xc9, 0x4f, 0xcf, 0xb4, 0x15, 0xdb,
                                       0xe9, 0x5f, 0x40, 0x8b, 0x9c, 0xe9, 0x1e, 0xe8, 0x46, 0xed};
  assert_memory_equal(digest, expected, digest_len);

  rv = C_CloseSession(hSession);
  assert_int_equal(rv, CKR_OK);
  rv = C_Finalize(NULL);
  assert_int_equal(rv, CKR_OK);
}

static void test_digest_sha1_buffer_too_small(void **state) {
  CK_RV rv;
  CK_SESSION_HANDLE hSession;
  CNK_MANAGED_MODE_INIT_ARGS args = {.malloc_func = malloc, .free_func = free, .hSCardCtx = 1, .hScard = 1};
  rv = C_CNK_EnableManagedMode(&args);
  assert_int_equal(rv, CKR_OK);
  rv = C_Initialize(NULL);
  assert_int_equal(rv, CKR_OK);
  rv = C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
  assert_int_equal(rv, CKR_OK);

  CK_MECHANISM mechanism = {.mechanism = CKM_SHA_1, .pParameter = NULL, .ulParameterLen = 0};
  rv = C_DigestInit(hSession, &mechanism);
  assert_int_equal(rv, CKR_OK);

  const char *msg = "abc";
  CK_ULONG msg_len = strlen(msg);
  CK_ULONG digest_len = 2;
  CK_BYTE buf[2];
  rv = C_Digest(hSession, (CK_BYTE_PTR)msg, msg_len, buf, &digest_len);
  assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);

  rv = C_CloseSession(hSession);
  assert_int_equal(rv, CKR_OK);
  rv = C_Finalize(NULL);
  assert_int_equal(rv, CKR_OK);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_digest_sha1_one_shot),
      cmocka_unit_test(test_digest_sha1_buffer_too_small),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
