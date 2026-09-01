// clang-format off
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
// clang-format on

#include "api/session.h"
#include "pkcs11.h"
#include "pkcs11_canokey.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <sched.h>
#endif

typedef struct {
  CK_SESSION_HANDLE session;
  CK_BYTE *data;
  CK_ULONG dataLen;
  CK_RV rv;
  atomic_bool entered;
} DigestThreadContext;

typedef struct {
  CK_SESSION_HANDLE session;
  CK_RV rv;
  atomic_bool entered;
} FindThreadContext;

typedef struct {
  CK_SESSION_HANDLE session;
  CK_RV rv;
} ProtectedLoginThreadContext;

static atomic_bool managementVerifyEntered;
static atomic_bool releaseManagementVerify;

CK_RV __wrap_cnk_verify_piv_pin_with_session(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_UTF8CHAR_PTR pin,
                                             CK_ULONG pinLen, CK_BYTE_PTR pinTries) {
  (void)slotID;
  (void)session;
  (void)pin;
  (void)pinLen;
  (void)pinTries;
  return cnk_token_cache_pin(session, pin, pinLen);
}

CK_RV __wrap_cnkVerifyManagementKey(CNK_PKCS11_SESSION *session, CK_BYTE_PTR key) {
  (void)session;
  (void)key;
  atomic_store(&managementVerifyEntered, true);
  while (!atomic_load(&releaseManagementVerify)) {
#ifdef _WIN32
    Sleep(1);
#else
    sched_yield();
#endif
  }
  return CKR_OK;
}

#ifdef _WIN32
static DWORD WINAPI digestThread(void *opaque)
#else
static void *digestThread(void *opaque)
#endif
{
  DigestThreadContext *ctx = opaque;
  atomic_store(&ctx->entered, true);
  ctx->rv = C_DigestUpdate(ctx->session, ctx->data, ctx->dataLen);
#ifdef _WIN32
  return 0;
#else
  return NULL;
#endif
}

#ifdef _WIN32
static DWORD WINAPI findThread(void *opaque)
#else
static void *findThread(void *opaque)
#endif
{
  FindThreadContext *ctx = opaque;
  atomic_store(&ctx->entered, true);
  CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
  CK_ATTRIBUTE findTemplate = {CKA_CLASS, &secretClass, sizeof(secretClass)};
  ctx->rv = C_FindObjectsInit(ctx->session, &findTemplate, 1);
  if (ctx->rv == CKR_OK)
    ctx->rv = C_FindObjectsFinal(ctx->session);
#ifdef _WIN32
  return 0;
#else
  return NULL;
#endif
}

static void waitForWorker(atomic_bool *entered) {
  for (int i = 0; i < 5000 && !atomic_load(entered); i++) {
#ifdef _WIN32
    Sleep(1);
#else
    sched_yield();
#endif
  }
  assert_true(atomic_load(entered));
}

#ifdef _WIN32
static DWORD WINAPI protectedLoginThread(void *opaque)
#else
static void *protectedLoginThread(void *opaque)
#endif
{
  ProtectedLoginThreadContext *ctx = opaque;
  CK_BYTE managementKey[24] = {0};
  ctx->rv = C_CNK_LoginProtectedManagementKey(ctx->session, managementKey, sizeof(managementKey));
#ifdef _WIN32
  return 0;
#else
  return NULL;
#endif
}

static int setup(void **state) {
  (void)state;
  CNK_MANAGED_MODE_INIT_ARGS args = {.malloc_func = malloc, .free_func = free, .hSCardCtx = 1, .hScard = 1};
  assert_int_equal(C_CNK_EnableManagedMode(&args), CKR_OK);
  assert_int_equal(C_Initialize(NULL), CKR_OK);
  return 0;
}

static int teardown(void **state) {
  (void)state;
  assert_int_equal(C_Finalize(NULL), CKR_OK);
  return 0;
}

static void test_close_does_not_deadlock_template_find(void **state) {
  (void)state;
  CK_SESSION_HANDLE session;
  assert_int_equal(C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK);

  CK_MECHANISM mechanism = {CKM_GENERIC_SECRET_KEY_GEN, NULL, 0};
  CK_ULONG valueLen = 32;
  CK_BBOOL privateValue = CK_FALSE;
  CK_ATTRIBUTE keyTemplate[] = {
      {CKA_VALUE_LEN, &valueLen, sizeof(valueLen)},
      {CKA_PRIVATE, &privateValue, sizeof(privateValue)},
  };
  CK_OBJECT_HANDLE key;
  assert_int_equal(C_GenerateKey(session, &mechanism, keyTemplate, 2, &key), CKR_OK);

  FindThreadContext ctx = {.session = session, .rv = CKR_GENERAL_ERROR, .entered = false};
#ifdef _WIN32
  HANDLE thread = CreateThread(NULL, 0, findThread, &ctx, 0, NULL);
  assert_non_null(thread);
  waitForWorker(&ctx.entered);
  assert_int_equal(C_CloseSession(session), CKR_OK);
  assert_int_equal(WaitForSingleObject(thread, 5000), WAIT_OBJECT_0);
  CloseHandle(thread);
#else
  pthread_t thread;
  assert_int_equal(pthread_create(&thread, NULL, findThread, &ctx), 0);
  waitForWorker(&ctx.entered);
  assert_int_equal(C_CloseSession(session), CKR_OK);
  assert_int_equal(pthread_join(thread, NULL), 0);
#endif
  assert_true(ctx.rv == CKR_OK || ctx.rv == CKR_SESSION_HANDLE_INVALID);
}

static void test_cancel_serializes_with_digest_update(void **state) {
  (void)state;
  CK_SESSION_HANDLE session;
  assert_int_equal(C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &session), CKR_OK);
  CK_MECHANISM mechanism = {CKM_SHA256, NULL, 0};
  assert_int_equal(C_DigestInit(session, &mechanism), CKR_OK);

  CK_ULONG dataLen = 8 * 1024 * 1024;
  CK_BYTE *data = malloc(dataLen);
  assert_non_null(data);
  memset(data, 0xA5, dataLen);
  DigestThreadContext ctx = {
      .session = session, .data = data, .dataLen = dataLen, .rv = CKR_GENERAL_ERROR, .entered = false};

#ifdef _WIN32
  HANDLE thread = CreateThread(NULL, 0, digestThread, &ctx, 0, NULL);
  assert_non_null(thread);
  waitForWorker(&ctx.entered);
  assert_int_equal(C_SessionCancel(session, CKF_DIGEST), CKR_OK);
  assert_int_equal(WaitForSingleObject(thread, 5000), WAIT_OBJECT_0);
  CloseHandle(thread);
#else
  pthread_t thread;
  assert_int_equal(pthread_create(&thread, NULL, digestThread, &ctx), 0);
  waitForWorker(&ctx.entered);
  assert_int_equal(C_SessionCancel(session, CKF_DIGEST), CKR_OK);
  assert_int_equal(pthread_join(thread, NULL), 0);
#endif
  assert_true(ctx.rv == CKR_OK || ctx.rv == CKR_OPERATION_NOT_INITIALIZED);
  free(data);
  assert_int_equal(C_CloseSession(session), CKR_OK);
}

static void test_close_waits_for_digest_update(void **state) {
  (void)state;
  CK_SESSION_HANDLE session;
  assert_int_equal(C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &session), CKR_OK);
  CK_MECHANISM mechanism = {CKM_SHA256, NULL, 0};
  assert_int_equal(C_DigestInit(session, &mechanism), CKR_OK);

  CK_ULONG dataLen = 8 * 1024 * 1024;
  CK_BYTE *data = malloc(dataLen);
  assert_non_null(data);
  memset(data, 0x5A, dataLen);
  DigestThreadContext ctx = {
      .session = session, .data = data, .dataLen = dataLen, .rv = CKR_GENERAL_ERROR, .entered = false};

#ifdef _WIN32
  HANDLE thread = CreateThread(NULL, 0, digestThread, &ctx, 0, NULL);
  assert_non_null(thread);
  waitForWorker(&ctx.entered);
  assert_int_equal(C_CloseSession(session), CKR_OK);
  assert_int_equal(WaitForSingleObject(thread, 5000), WAIT_OBJECT_0);
  CloseHandle(thread);
#else
  pthread_t thread;
  assert_int_equal(pthread_create(&thread, NULL, digestThread, &ctx), 0);
  waitForWorker(&ctx.entered);
  assert_int_equal(C_CloseSession(session), CKR_OK);
  assert_int_equal(pthread_join(thread, NULL), 0);
#endif
  assert_true(ctx.rv == CKR_OK || ctx.rv == CKR_SESSION_HANDLE_INVALID);
  free(data);
}

static void test_logout_cannot_race_protected_management_login(void **state) {
  (void)state;
  CK_SESSION_HANDLE session;
  assert_int_equal(C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK);
  CK_UTF8CHAR pin[] = "123456";
  assert_int_equal(C_Login(session, CKU_USER, pin, sizeof(pin) - 1), CKR_OK);
  atomic_store(&managementVerifyEntered, false);
  atomic_store(&releaseManagementVerify, false);
  ProtectedLoginThreadContext ctx = {.session = session, .rv = CKR_GENERAL_ERROR};

#ifdef _WIN32
  HANDLE thread = CreateThread(NULL, 0, protectedLoginThread, &ctx, 0, NULL);
  assert_non_null(thread);
  waitForWorker(&managementVerifyEntered);
  assert_int_equal(C_Logout(session), CKR_OPERATION_ACTIVE);
  atomic_store(&releaseManagementVerify, true);
  assert_int_equal(WaitForSingleObject(thread, 5000), WAIT_OBJECT_0);
  CloseHandle(thread);
#else
  pthread_t thread;
  assert_int_equal(pthread_create(&thread, NULL, protectedLoginThread, &ctx), 0);
  waitForWorker(&managementVerifyEntered);
  assert_int_equal(C_Logout(session), CKR_OPERATION_ACTIVE);
  atomic_store(&releaseManagementVerify, true);
  assert_int_equal(pthread_join(thread, NULL), 0);
#endif
  assert_int_equal(ctx.rv, CKR_OK);
  assert_int_equal(C_CloseSession(session), CKR_OK);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(test_close_does_not_deadlock_template_find, setup, teardown),
      cmocka_unit_test_setup_teardown(test_cancel_serializes_with_digest_update, setup, teardown),
      cmocka_unit_test_setup_teardown(test_close_waits_for_digest_update, setup, teardown),
      cmocka_unit_test_setup_teardown(test_logout_cannot_race_protected_management_login, setup, teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
