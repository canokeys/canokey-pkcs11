// clang-format off
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
// clang-format on

#include "backend/pcsc.h"
#include "internal/logging.h"
#include "pkcs11.h"

#include <stdbool.h>
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

// Added SHA256 tests
static void test_digest_sha256_one_shot(void **state) {
  CK_RV rv;
  CK_SESSION_HANDLE hSession;
  CNK_MANAGED_MODE_INIT_ARGS args = {.malloc_func = malloc, .free_func = free, .hSCardCtx = 1, .hScard = 1};
  rv = C_CNK_EnableManagedMode(&args);
  assert_int_equal(rv, CKR_OK);
  rv = C_Initialize(NULL);
  assert_int_equal(rv, CKR_OK);
  rv = C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
  assert_int_equal(rv, CKR_OK);

  CK_MECHANISM mech = {.mechanism = CKM_SHA256, .pParameter = NULL, .ulParameterLen = 0};
  rv = C_DigestInit(hSession, &mech);
  assert_int_equal(rv, CKR_OK);

  const char *msg = "hello world";
  CK_ULONG msg_len = strlen(msg);
  CK_ULONG digest_len = 0;
  rv = C_Digest(hSession, (CK_BYTE_PTR)msg, msg_len, NULL, &digest_len);
  assert_int_equal(rv, CKR_OK);
  assert_int_equal(digest_len, 32);

  CK_BYTE digest[64];
  CK_ULONG buf_len = digest_len;
  rv = C_Digest(hSession, (CK_BYTE_PTR)msg, msg_len, digest, &buf_len);
  assert_int_equal(rv, CKR_OK);
  assert_int_equal(buf_len, digest_len);

  static const CK_BYTE expected256[32] = {0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52,
                                          0xd7, 0xda, 0x7d, 0xab, 0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53,
                                          0x80, 0xee, 0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef, 0xcd, 0xe9};
  assert_memory_equal(digest, expected256, digest_len);

  rv = C_CloseSession(hSession);
  assert_int_equal(rv, CKR_OK);
  rv = C_Finalize(NULL);
  assert_int_equal(rv, CKR_OK);
}

static void test_digest_sha256_buffer_too_small(void **state) {
  CK_RV rv;
  CK_SESSION_HANDLE hSession;
  CNK_MANAGED_MODE_INIT_ARGS args = {.malloc_func = malloc, .free_func = free, .hSCardCtx = 1, .hScard = 1};
  rv = C_CNK_EnableManagedMode(&args);
  assert_int_equal(rv, CKR_OK);
  rv = C_Initialize(NULL);
  assert_int_equal(rv, CKR_OK);
  rv = C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
  assert_int_equal(rv, CKR_OK);

  CK_MECHANISM mech = {.mechanism = CKM_SHA256, .pParameter = NULL, .ulParameterLen = 0};
  rv = C_DigestInit(hSession, &mech);
  assert_int_equal(rv, CKR_OK);

  const char *msg = "abc";
  CK_ULONG msg_len = strlen(msg);
  CK_ULONG digest_len = 2;
  CK_BYTE buf[2];
  rv = C_Digest(hSession, (CK_BYTE_PTR)msg, msg_len, buf, &digest_len);
  assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);
  CK_BYTE digest[32] = {0};
  digest_len = sizeof(digest);
  rv = C_Digest(hSession, (CK_BYTE_PTR)msg, msg_len, digest, &digest_len);
  assert_int_equal(rv, CKR_OK);
  static const CK_BYTE expected[32] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
                                       0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
                                       0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
  assert_memory_equal(digest, expected, sizeof(expected));

  rv = C_CloseSession(hSession);
  assert_int_equal(rv, CKR_OK);
  rv = C_Finalize(NULL);
  assert_int_equal(rv, CKR_OK);
}

static void test_digest_sha256_multi_update(void **state) {
  CK_RV rv;
  CK_SESSION_HANDLE hSession;
  CNK_MANAGED_MODE_INIT_ARGS args = {.malloc_func = malloc, .free_func = free, .hSCardCtx = 1, .hScard = 1};
  rv = C_CNK_EnableManagedMode(&args);
  assert_int_equal(rv, CKR_OK);
  rv = C_Initialize(NULL);
  assert_int_equal(rv, CKR_OK);
  rv = C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
  assert_int_equal(rv, CKR_OK);

  CK_MECHANISM mech = {.mechanism = CKM_SHA256, .pParameter = NULL, .ulParameterLen = 0};
  rv = C_DigestInit(hSession, &mech);
  assert_int_equal(rv, CKR_OK);

  const char *part1 = "hello ";
  rv = C_DigestUpdate(hSession, (CK_BYTE_PTR)part1, 6);
  assert_int_equal(rv, CKR_OK);
  const char *part2 = "world";
  rv = C_DigestUpdate(hSession, (CK_BYTE_PTR)part2, 5);
  assert_int_equal(rv, CKR_OK);

  CK_ULONG digest_len = 32;
  CK_BYTE digest[64] = {0};
  rv = C_DigestFinal(hSession, digest, &digest_len);
  assert_int_equal(rv, CKR_OK);
  assert_int_equal(digest_len, 32);

  static const CK_BYTE expected256[32] = {0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52,
                                          0xd7, 0xda, 0x7d, 0xab, 0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53,
                                          0x80, 0xee, 0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef, 0xcd, 0xe9};
  assert_memory_equal(digest, expected256, digest_len);

  rv = C_CloseSession(hSession);
  assert_int_equal(rv, CKR_OK);
  rv = C_Finalize(NULL);
  assert_int_equal(rv, CKR_OK);
}

// Added SHA3-256 tests
static void test_digest_sha3_256_one_shot(void **state) {
  CK_RV rv;
  CK_SESSION_HANDLE hSession;
  CNK_MANAGED_MODE_INIT_ARGS args = {.malloc_func = malloc, .free_func = free, .hSCardCtx = 1, .hScard = 1};
  rv = C_CNK_EnableManagedMode(&args);
  assert_int_equal(rv, CKR_OK);
  rv = C_Initialize(NULL);
  assert_int_equal(rv, CKR_OK);
  rv = C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
  assert_int_equal(rv, CKR_OK);

  CK_MECHANISM mech = {.mechanism = CKM_SHA3_256, .pParameter = NULL, .ulParameterLen = 0};
  rv = C_DigestInit(hSession, &mech);
  assert_int_equal(rv, CKR_OK);

  const char *msg = "hello world";
  CK_ULONG msg_len = strlen(msg);
  CK_ULONG digest_len = 0;
  rv = C_Digest(hSession, (CK_BYTE_PTR)msg, msg_len, NULL, &digest_len);
  assert_int_equal(rv, CKR_OK);
  assert_int_equal(digest_len, 32);

  CK_BYTE digest[64] = {0};
  CK_ULONG buf_len = digest_len;
  rv = C_Digest(hSession, (CK_BYTE_PTR)msg, msg_len, digest, &buf_len);
  assert_int_equal(rv, CKR_OK);
  assert_int_equal(buf_len, digest_len);

  bool nonzero = false;
  for (size_t i = 0; i < digest_len; i++)
    if (digest[i])
      nonzero = true;
  assert_true(nonzero);

  rv = C_CloseSession(hSession);
  assert_int_equal(rv, CKR_OK);
  rv = C_Finalize(NULL);
  assert_int_equal(rv, CKR_OK);
}

static void test_digest_sha3_256_buffer_too_small(void **state) {
  CK_RV rv;
  CK_SESSION_HANDLE hSession;
  CNK_MANAGED_MODE_INIT_ARGS args = {.malloc_func = malloc, .free_func = free, .hSCardCtx = 1, .hScard = 1};
  rv = C_CNK_EnableManagedMode(&args);
  assert_int_equal(rv, CKR_OK);
  rv = C_Initialize(NULL);
  assert_int_equal(rv, CKR_OK);
  rv = C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
  assert_int_equal(rv, CKR_OK);

  CK_MECHANISM mech = {.mechanism = CKM_SHA3_256, .pParameter = NULL, .ulParameterLen = 0};
  rv = C_DigestInit(hSession, &mech);
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

static void test_digest_argument_error_terminates_operation(void **state) {
  (void)state;
  CK_SESSION_HANDLE session;
  CNK_MANAGED_MODE_INIT_ARGS args = {.malloc_func = malloc, .free_func = free, .hSCardCtx = 1, .hScard = 1};
  assert_int_equal(C_CNK_EnableManagedMode(&args), CKR_OK);
  assert_int_equal(C_Initialize(NULL), CKR_OK);
  assert_int_equal(C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &session), CKR_OK);

  CK_MECHANISM mechanism = {.mechanism = CKM_SHA256, .pParameter = NULL, .ulParameterLen = 0};
  CK_BYTE data[] = {1, 2, 3};
  CK_BYTE digest[32];
  CK_ULONG digestLen = sizeof(digest);
  assert_int_equal(C_DigestInit(session, &mechanism), CKR_OK);
  assert_int_equal(C_Digest(session, data, sizeof(data), digest, NULL), CKR_ARGUMENTS_BAD);
  assert_int_equal(C_Digest(session, data, sizeof(data), digest, &digestLen), CKR_OPERATION_NOT_INITIALIZED);

  assert_int_equal(C_DigestInit(session, &mechanism), CKR_OK);
  assert_int_equal(C_DigestFinal(session, digest, NULL), CKR_ARGUMENTS_BAD);
  assert_int_equal(C_DigestFinal(session, digest, &digestLen), CKR_OPERATION_NOT_INITIALIZED);

  assert_int_equal(C_CloseSession(session), CKR_OK);
  assert_int_equal(C_Finalize(NULL), CKR_OK);
}

static void test_digest_rejects_mixed_completion_modes(void **state) {
  (void)state;
  CK_SESSION_HANDLE session;
  CNK_MANAGED_MODE_INIT_ARGS args = {.malloc_func = malloc, .free_func = free, .hSCardCtx = 1, .hScard = 1};
  assert_int_equal(C_CNK_EnableManagedMode(&args), CKR_OK);
  assert_int_equal(C_Initialize(NULL), CKR_OK);
  assert_int_equal(C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &session), CKR_OK);

  CK_MECHANISM mechanism = {.mechanism = CKM_SHA256, .pParameter = NULL, .ulParameterLen = 0};
  CK_BYTE data[] = {1, 2, 3};
  CK_BYTE digest[32];
  CK_ULONG digestLen = sizeof(digest);
  assert_int_equal(C_DigestInit(session, &mechanism), CKR_OK);
  assert_int_equal(C_DigestUpdate(session, data, 1), CKR_OK);
  assert_int_equal(C_Digest(session, data + 1, sizeof(data) - 1, digest, &digestLen), CKR_OPERATION_ACTIVE);
  assert_int_equal(C_DigestFinal(session, digest, &digestLen), CKR_OPERATION_NOT_INITIALIZED);

  assert_int_equal(C_DigestInit(session, &mechanism), CKR_OK);
  digestLen = 0;
  assert_int_equal(C_Digest(session, data, sizeof(data), NULL, &digestLen), CKR_OK);
  assert_int_equal(digestLen, sizeof(digest));
  assert_int_equal(C_DigestFinal(session, digest, &digestLen), CKR_OPERATION_ACTIVE);
  assert_int_equal(C_Digest(session, data, sizeof(data), digest, &digestLen), CKR_OPERATION_NOT_INITIALIZED);

  assert_int_equal(C_CloseSession(session), CKR_OK);
  assert_int_equal(C_Finalize(NULL), CKR_OK);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_digest_sha1_one_shot),
      cmocka_unit_test(test_digest_sha1_buffer_too_small),
      cmocka_unit_test(test_digest_sha256_one_shot),
      cmocka_unit_test(test_digest_sha256_buffer_too_small),
      cmocka_unit_test(test_digest_sha256_multi_update),
      cmocka_unit_test(test_digest_sha3_256_one_shot),
      cmocka_unit_test(test_digest_sha3_256_buffer_too_small),
      cmocka_unit_test(test_digest_argument_error_terminates_operation),
      cmocka_unit_test(test_digest_rejects_mixed_completion_modes),
  };
  C_CNK_ConfigLogging(CNK_LOG_LEVEL_DEBUG, NULL, CK_TRUE);
  return cmocka_run_group_tests(tests, NULL, NULL);
}
