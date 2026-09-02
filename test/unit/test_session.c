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
#include <time.h>
#endif

typedef struct {
  CK_SESSION_HANDLE session;
  CK_BYTE *data;
  CK_ULONG dataLen;
  CK_RV rv;
  CNK_PKCS11_SESSION *held;
  atomic_bool entered;
} DigestThreadContext;

typedef struct {
  CK_SESSION_HANDLE session;
  CK_RV rv;
  CNK_PKCS11_SESSION *held;
  atomic_bool entered;
} FindThreadContext;

#ifdef _WIN32
static DWORD WINAPI digestThread(void *opaque)
#else
static void *digestThread(void *opaque)
#endif
{
  DigestThreadContext *ctx = opaque;
  CK_RV heldRv = cnk_session_find(ctx->session, &ctx->held);
  atomic_store(&ctx->entered, true);
  if (heldRv != CKR_OK)
    ctx->rv = heldRv;
  else {
    ctx->rv = C_DigestUpdate(ctx->session, ctx->data, ctx->dataLen);
    cnk_session_release_ref(&ctx->held);
  }
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
  CK_RV heldRv = cnk_session_find(ctx->session, &ctx->held);
  atomic_store(&ctx->entered, true);
  if (heldRv != CKR_OK)
    ctx->rv = heldRv;
  else {
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_ATTRIBUTE findTemplate = {CKA_CLASS, &secretClass, sizeof(secretClass)};
    ctx->rv = C_FindObjectsInit(ctx->session, &findTemplate, 1);
    if (ctx->rv == CKR_OK)
      ctx->rv = C_FindObjectsFinal(ctx->session);
    cnk_session_release_ref(&ctx->held);
  }
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
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000};
    nanosleep(&delay, NULL);
#endif
  }
  assert_true(atomic_load(entered));
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
  assert_int_equal(C_SessionCancel(session, CKF_SIGN_RECOVER), CKR_OPERATION_CANCEL_FAILED);
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
  CNK_PKCS11_SESSION *internal = NULL;
  assert_int_equal(cnk_session_find(session, &internal), CKR_OK);
  cnk_mutex_lock(&internal->token->lock);
  internal->token->loginState = TOKEN_LOGIN_USER;
  internal->token->pin[0] = '1';
  internal->token->cbPin = 1;
  cnk_mutex_unlock(&internal->token->lock);
  assert_int_equal(cnk_token_begin_protected_management_login(internal), CKR_OK);
  assert_int_equal(C_Logout(session), CKR_OPERATION_ACTIVE);
  CK_BYTE managementKey[24] = {0};
  assert_int_equal(
      cnk_token_complete_protected_management_login(internal, managementKey, sizeof(managementKey), CKR_OK), CKR_OK);
  CK_BBOOL managementKeyCached = CK_FALSE;
  assert_int_equal(cnk_token_management_key_is_cached(internal, &managementKeyCached), CKR_OK);
  assert_true(managementKeyCached);
  cnk_mutex_lock(&internal->token->lock);
  memset(internal->token->pin, 0xFF, sizeof(internal->token->pin));
  internal->token->cbPin = 0;
  memset(internal->token->managementKey, 0, sizeof(internal->token->managementKey));
  internal->token->cbManagementKey = 0;
  internal->token->loginState = TOKEN_LOGIN_PUBLIC;
  cnk_mutex_unlock(&internal->token->lock);
  cnk_session_release_ref(&internal);
  assert_int_equal(C_CloseSession(session), CKR_OK);
}

static void test_logout_revokes_context_specific_authorization(void **state) {
  (void)state;
  CK_SESSION_HANDLE session;
  assert_int_equal(C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK);
  CNK_PKCS11_SESSION *internal = NULL;
  assert_int_equal(cnk_session_find(session, &internal), CKR_OK);
  cnk_mutex_lock(&internal->lock);
  internal->signingContext.hKey = 1;
  internal->signingContext.pinPolicy = CNK_PIV_PIN_POLICY_ALWAYS;
  internal->signingContext.contextAuthenticated = CK_TRUE;
  internal->signingContext.contextPin[0] = '1';
  internal->signingContext.contextPinLen = 1;
  cnk_mutex_unlock(&internal->lock);

  assert_int_equal(cnk_token_revoke_private_operations(internal->token), CKR_OK);
  cnk_mutex_lock(&internal->lock);
  assert_int_equal(internal->signingContext.hKey, 0);
  assert_false(internal->signingContext.contextAuthenticated);
  assert_int_equal(internal->signingContext.contextPinLen, 0);
  cnk_mutex_unlock(&internal->lock);
  cnk_session_release_ref(&internal);
  assert_int_equal(C_CloseSession(session), CKR_OK);
}

static void test_context_login_rejects_two_pin_always_operations(void **state) {
  (void)state;
  CK_SESSION_HANDLE session;
  assert_int_equal(C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK);
  CNK_PKCS11_SESSION *internal = NULL;
  assert_int_equal(cnk_session_find(session, &internal), CKR_OK);
  cnk_mutex_lock(&internal->lock);
  internal->signingContext.hKey = 1;
  internal->signingContext.pinPolicy = CNK_PIV_PIN_POLICY_ALWAYS;
  internal->decryptingContext.hKey = 2;
  internal->decryptingContext.pinPolicy = CNK_PIV_PIN_POLICY_ALWAYS;
  cnk_mutex_unlock(&internal->lock);

  CK_BYTE pin = '1';
  assert_int_equal(C_Login(session, CKU_CONTEXT_SPECIFIC, &pin, sizeof(pin)), CKR_OPERATION_ACTIVE);
  cnk_session_release_ref(&internal);
  assert_int_equal(C_CloseSession(session), CKR_OK);
}

static void test_encapsulation_query_validates_session(void **state) {
  (void)state;
  CK_MECHANISM mechanism = {CKM_ML_KEM, NULL, 0};
  CK_ULONG ciphertextLen = 0;
  CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
  assert_int_equal(C_EncapsulateKey(CK_INVALID_HANDLE, &mechanism, 1, NULL, 0, NULL, &ciphertextLen, &key),
                   CKR_SESSION_HANDLE_INVALID);
}

static void test_invalid_finalize_does_not_consume_reference(void **state) {
  (void)state;
  CK_INFO info;
  assert_int_equal(C_Finalize((void *)1), CKR_ARGUMENTS_BAD);
  assert_int_equal(C_GetInfo(&info), CKR_OK);
}

static CK_RV failTokenLock(void *mutex) {
  (void)mutex;
  return CKR_GENERAL_ERROR;
}

static void test_cached_auth_check_propagates_lock_failure(void **state) {
  (void)state;
  CK_SESSION_HANDLE session;
  assert_int_equal(C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK);
  CNK_PKCS11_SESSION *internal = NULL;
  assert_int_equal(cnk_session_find(session, &internal), CKR_OK);
  CK_RV (*savedLock)(void *) = internal->token->lock.lock;
  internal->token->lock.lock = failTokenLock;
  CK_BBOOL cached = CK_TRUE;
  assert_int_equal(cnk_token_pin_is_cached(internal, &cached), CKR_GENERAL_ERROR);
  internal->token->lock.lock = savedLock;
  cnk_session_release_ref(&internal);
  assert_int_equal(C_CloseSession(session), CKR_OK);
}

static void test_data_object_template_rejects_null_object_id(void **state) {
  (void)state;
  CK_SESSION_HANDLE session;
  assert_int_equal(C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK);
  CNK_PKCS11_SESSION *internal = NULL;
  assert_int_equal(cnk_session_find(session, &internal), CKR_OK);
  cnk_mutex_lock(&internal->token->lock);
  internal->token->loginState = TOKEN_LOGIN_SO;
  memset(internal->token->managementKey, 0xA5, sizeof(internal->token->managementKey));
  internal->token->cbManagementKey = sizeof(internal->token->managementKey);
  cnk_mutex_unlock(&internal->token->lock);

  CK_OBJECT_CLASS objectClass = CKO_DATA;
  CK_ATTRIBUTE template[] = {{CKA_CLASS, &objectClass, sizeof(objectClass)}, {CKA_OBJECT_ID, NULL, 3}};
  CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
  assert_int_equal(C_CreateObject(session, template, sizeof(template) / sizeof(template[0]), &object),
                   CKR_ATTRIBUTE_VALUE_INVALID);
  cnk_session_release_ref(&internal);
  assert_int_equal(C_CloseSession(session), CKR_OK);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(test_close_does_not_deadlock_template_find, setup, teardown),
      cmocka_unit_test_setup_teardown(test_cancel_serializes_with_digest_update, setup, teardown),
      cmocka_unit_test_setup_teardown(test_close_waits_for_digest_update, setup, teardown),
      cmocka_unit_test_setup_teardown(test_logout_cannot_race_protected_management_login, setup, teardown),
      cmocka_unit_test_setup_teardown(test_logout_revokes_context_specific_authorization, setup, teardown),
      cmocka_unit_test_setup_teardown(test_context_login_rejects_two_pin_always_operations, setup, teardown),
      cmocka_unit_test_setup_teardown(test_encapsulation_query_validates_session, setup, teardown),
      cmocka_unit_test_setup_teardown(test_invalid_finalize_does_not_consume_reference, setup, teardown),
      cmocka_unit_test_setup_teardown(test_cached_auth_check_propagates_lock_failure, setup, teardown),
      cmocka_unit_test_setup_teardown(test_data_object_template_rejects_null_object_id, setup, teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
