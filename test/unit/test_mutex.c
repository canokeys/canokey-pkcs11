// clang-format off
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
// clang-format on

#include "api/session.h"
#include "backend/pcsc.h"
#include "internal/mutex.h"
#include "pkcs11_canokey.h"

#include <stdlib.h>

static CK_ULONG unlockCalls;
static CK_ULONG destroyCalls;
static CK_ULONG failDestroyCall;

static void *alternate_malloc(size_t size) { return malloc(size); }

static CK_RV createMutex(void **mutex) {
  *mutex = (void *)0x1;
  return CKR_OK;
}

static CK_RV destroyMutex(void *mutex) {
  (void)mutex;
  destroyCalls++;
  if (failDestroyCall != 0 && destroyCalls == failDestroyCall)
    return CKR_GENERAL_ERROR;
  return CKR_OK;
}

static CK_RV failLock(void *mutex) {
  (void)mutex;
  return CKR_GENERAL_ERROR;
}

static CK_RV okLock(void *mutex) {
  (void)mutex;
  return CKR_OK;
}

static CK_RV okUnlock(void *mutex) {
  (void)mutex;
  return CKR_OK;
}

static CK_RV countUnlock(void *mutex) {
  (void)mutex;
  unlockCalls++;
  return CKR_OK;
}

static void test_failed_application_lock_does_not_unlock(void **state) {
  (void)state;
  CK_INFO info;
  assert_int_equal(C_GetInfo(&info), CKR_OK);
  assert_int_equal(C_GetOperationState(CK_INVALID_HANDLE, NULL, NULL), CKR_FUNCTION_NOT_SUPPORTED);
  unlockCalls = 0;
  CK_C_INITIALIZE_ARGS args = {
      .CreateMutex = createMutex,
      .DestroyMutex = destroyMutex,
      .LockMutex = failLock,
      .UnlockMutex = countUnlock,
  };
  assert_int_equal(cnk_mutex_system_init(&args), CKR_OK);
  CNK_PKCS11_MUTEX mutex = {0};
  assert_int_equal(cnk_mutex_create(&mutex), CKR_OK);
  {
    CNK_PKCS11_MUTEX_GUARD guard = {.mutex = &mutex};
    assert_int_equal(cnk_mutex_lock_guard(&guard), CKR_GENERAL_ERROR);
  }
  assert_int_equal(unlockCalls, 0);
  assert_int_equal(cnk_mutex_destroy(&mutex), CKR_OK);
  cnk_mutex_system_cleanup();
}

static void test_session_manager_propagates_application_lock_failure(void **state) {
  (void)state;
  CK_C_INITIALIZE_ARGS args = {
      .CreateMutex = createMutex,
      .DestroyMutex = destroyMutex,
      .LockMutex = failLock,
      .UnlockMutex = countUnlock,
  };
  assert_int_equal(cnk_mutex_system_init(&args), CKR_OK);
  assert_int_equal(cnk_session_manager_init(), CKR_GENERAL_ERROR);
  cnk_mutex_system_cleanup();
}

static void test_serialized_initialize_args_still_create_internal_mutexes(void **state) {
  (void)state;
  CNK_MANAGED_MODE_INIT_ARGS managed = {.malloc_func = malloc, .free_func = free, .hSCardCtx = 1, .hScard = 1};
  CK_C_INITIALIZE_ARGS args = {0};
  assert_int_equal(C_CNK_EnableManagedMode(&managed), CKR_OK);
  assert_int_equal(C_Initialize(&args), CKR_OK);
  CK_SESSION_HANDLE session;
  assert_int_equal(C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &session), CKR_OK);
  assert_int_equal(C_GenerateRandom(session, NULL, 0), CKR_OK);
  assert_int_equal(C_CloseSession(session), CKR_OK);
  assert_int_equal(C_Finalize(NULL), CKR_OK);
}

static void test_managed_mode_accepts_different_allocator(void **state) {
  (void)state;
  CNK_MANAGED_MODE_INIT_ARGS first = {.malloc_func = malloc, .free_func = free, .hSCardCtx = 1, .hScard = 1};
  CNK_MANAGED_MODE_INIT_ARGS second = {.malloc_func = alternate_malloc, .free_func = free, .hSCardCtx = 2, .hScard = 2};
  assert_int_equal(C_CNK_EnableManagedMode(&first), CKR_OK);
  assert_int_equal(C_Initialize(NULL), CKR_OK);
  assert_int_equal(C_CNK_EnableManagedMode(&second), CKR_OK);
  assert_int_equal(C_Finalize(NULL), CKR_OK);
}

static void test_managed_mode_accepts_rotated_card_handle(void **state) {
  (void)state;
  CNK_MANAGED_MODE_INIT_ARGS first = {.malloc_func = malloc, .free_func = free, .hSCardCtx = 1, .hScard = 1};
  CNK_MANAGED_MODE_INIT_ARGS second = {.malloc_func = malloc, .free_func = free, .hSCardCtx = 2, .hScard = 2};
  assert_int_equal(C_CNK_EnableManagedMode(&first), CKR_OK);
  assert_int_equal(C_Initialize(NULL), CKR_OK);
  assert_int_equal(C_CNK_EnableManagedMode(&second), CKR_OK);
  assert_int_equal(g_cnk_scard, 2);
  assert_int_equal(C_Finalize(NULL), CKR_OK);
}

static void test_managed_mode_cannot_replace_initialized_standalone(void **state) {
  (void)state;
  CNK_MANAGED_MODE_INIT_ARGS args = {.malloc_func = malloc, .free_func = free, .hSCardCtx = 1, .hScard = 1};
  CK_BBOOL savedInitialized = g_cnk_is_initialized;
  CK_BBOOL savedManaged = g_cnk_is_managed_mode;
  g_cnk_is_initialized = CK_TRUE;
  g_cnk_is_managed_mode = CK_FALSE;
  assert_int_equal(C_CNK_EnableManagedMode(&args), CKR_OPERATION_ACTIVE);
  g_cnk_is_initialized = savedInitialized;
  g_cnk_is_managed_mode = savedManaged;
}

static void test_uninitialized_managed_binding_can_be_reset(void **state) {
  (void)state;
  CNK_MANAGED_MODE_INIT_ARGS first = {.malloc_func = malloc, .free_func = free, .hSCardCtx = 11, .hScard = 11};
  CNK_MANAGED_MODE_INIT_ARGS second = {.malloc_func = malloc, .free_func = free, .hSCardCtx = 22, .hScard = 22};
  assert_int_equal(C_CNK_EnableManagedMode(&first), CKR_OK);
  assert_int_equal(C_CNK_ResetManagedMode(), CKR_OK);
  assert_int_equal(C_CNK_EnableManagedMode(&second), CKR_OK);
  assert_int_equal(C_CNK_ResetManagedMode(), CKR_OK);
}

static void test_backend_cleanup_retries_only_failed_mutex(void **state) {
  (void)state;
  CK_C_INITIALIZE_ARGS args = {
      .CreateMutex = createMutex,
      .DestroyMutex = destroyMutex,
      .LockMutex = okLock,
      .UnlockMutex = okUnlock,
  };
  destroyCalls = 0;
  failDestroyCall = 0;
  assert_int_equal(cnk_mutex_system_init(&args), CKR_OK);
  assert_int_equal(cnk_initialize_backend(), CKR_OK);
  failDestroyCall = 2;
  assert_int_equal(cnk_cleanup_backend(), CKR_GENERAL_ERROR);
  assert_int_equal(destroyCalls, 2);
  failDestroyCall = 0;
  assert_int_equal(cnk_cleanup_backend(), CKR_OK);
  assert_int_equal(destroyCalls, 3);
  cnk_mutex_system_cleanup();
}

static void test_session_manager_cleanup_retries_mutex_destroy(void **state) {
  (void)state;
  destroyCalls = 0;
  failDestroyCall = 0;
  CK_C_INITIALIZE_ARGS args = {
      .CreateMutex = createMutex,
      .DestroyMutex = destroyMutex,
      .LockMutex = okLock,
      .UnlockMutex = okUnlock,
  };
  // The manager must be usable with callbacks that can later fail destroy.
  assert_int_equal(cnk_mutex_system_init(&args), CKR_OK);
  assert_int_equal(cnk_session_manager_init(), CKR_OK);
  failDestroyCall = 1;
  assert_int_equal(cnk_session_manager_cleanup(), CKR_GENERAL_ERROR);
  failDestroyCall = 0;
  assert_int_equal(cnk_session_manager_cleanup(), CKR_OK);
  cnk_mutex_system_cleanup();
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_failed_application_lock_does_not_unlock),
      cmocka_unit_test(test_session_manager_propagates_application_lock_failure),
      cmocka_unit_test(test_serialized_initialize_args_still_create_internal_mutexes),
      cmocka_unit_test(test_managed_mode_accepts_different_allocator),
      cmocka_unit_test(test_managed_mode_accepts_rotated_card_handle),
      cmocka_unit_test(test_managed_mode_cannot_replace_initialized_standalone),
      cmocka_unit_test(test_uninitialized_managed_binding_can_be_reset),
      cmocka_unit_test(test_backend_cleanup_retries_only_failed_mutex),
      cmocka_unit_test(test_session_manager_cleanup_retries_mutex_destroy),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
