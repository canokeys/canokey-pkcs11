#include "pkcs11_mutex.h"
#include "pcsc_backend.h"
#include "pkcs11_macros.h"
#include "utils.h"

#include <nsync_mu.h>

#undef CreateMutex // avoid conflicts with Windows API

#define CNK_PRINTLOGF // avoid too many log messages

// Global variables for mutex system
static CK_BBOOL g_mutex_system_initialized = CK_FALSE;
static CK_BBOOL g_using_app_mutexes = CK_FALSE;

// Application-supplied mutex function pointers
static CK_CREATEMUTEX g_create_mutex = NULL;
static CK_DESTROYMUTEX g_destroy_mutex = NULL;
static CK_LOCKMUTEX g_lock_mutex = NULL;
static CK_UNLOCKMUTEX g_unlock_mutex = NULL;

// OS mutex implementation using nsync
static CK_RV os_create_mutex(void **mutex) {
  nsync_mu *mu = ck_malloc(sizeof(nsync_mu));
  if (mu == NULL) {
    CNK_RETURN(CKR_HOST_MEMORY, "Failed to allocate memory for mutex");
  }

  nsync_mu_init(mu); // Initialize the mutex
  *mutex = mu;
  CNK_RET_OK;
}

static CK_RV os_destroy_mutex(void *mutex) {
  CNK_ENSURE_NONNULL(mutex);
  ck_free(mutex);
  CNK_RET_OK;
}

static CK_RV os_lock_mutex(void *mutex) {
  CNK_ENSURE_NONNULL(mutex);
  nsync_mu_lock((nsync_mu *)mutex);
  CNK_RET_OK;
}

static CK_RV os_unlock_mutex(void *mutex) {
  CNK_ENSURE_NONNULL(mutex);
  nsync_mu_unlock((nsync_mu *)mutex);
  CNK_RET_OK;
}

// Initialize the mutex system
CK_RV cnk_mutex_system_init(CK_C_INITIALIZE_ARGS_PTR mutex_funcs) {
  if (g_mutex_system_initialized) {
    return CKR_CRYPTOKI_ALREADY_INITIALIZED;
  }

  // Check if we should use application-supplied mutex functions
  if (mutex_funcs != NULL && mutex_funcs->CreateMutex != NULL_PTR && mutex_funcs->DestroyMutex != NULL_PTR &&
      mutex_funcs->LockMutex != NULL_PTR && mutex_funcs->UnlockMutex != NULL_PTR) {

    // Store the application-supplied mutex functions
    g_create_mutex = mutex_funcs->CreateMutex;
    g_destroy_mutex = mutex_funcs->DestroyMutex;
    g_lock_mutex = mutex_funcs->LockMutex;
    g_unlock_mutex = mutex_funcs->UnlockMutex;
    g_using_app_mutexes = CK_TRUE;
  } else {
    // Use OS primitives
    g_using_app_mutexes = CK_FALSE;
  }

  g_mutex_system_initialized = CK_TRUE;
  CNK_RET_OK;
}

// Clean up the mutex system
void cnk_mutex_system_cleanup(void) {
  g_mutex_system_initialized = CK_FALSE;
  g_using_app_mutexes = CK_FALSE;
  g_create_mutex = NULL;
  g_destroy_mutex = NULL;
  g_lock_mutex = NULL;
  g_unlock_mutex = NULL;
}

// Create a new mutex
CK_RV cnk_mutex_create(CNK_PKCS11_MUTEX *mutex) {
  CNK_ENSURE_NONNULL(mutex);

  if (!g_mutex_system_initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (g_using_app_mutexes) {
    // Use application-supplied mutex functions
    mutex->create = (CK_RV (*)(void **))g_create_mutex;
    mutex->destroy = (CK_RV (*)(void *))g_destroy_mutex;
    mutex->lock = (CK_RV (*)(void *))g_lock_mutex;
    mutex->unlock = (CK_RV (*)(void *))g_unlock_mutex;
  } else {
    // Use OS primitives
    mutex->create = os_create_mutex;
    mutex->destroy = os_destroy_mutex;
    mutex->lock = os_lock_mutex;
    mutex->unlock = os_unlock_mutex;
  }

  // Create the actual mutex
  return mutex->create(&mutex->mutex_handle);
}

// Destroy a mutex
CK_RV cnk_mutex_destroy(CNK_PKCS11_MUTEX *mutex) {
  CNK_ENSURE_NONNULL(mutex, mutex->mutex_handle, mutex->lock);
  return mutex->destroy(mutex->mutex_handle);
}

// Lock a mutex
CK_RV cnk_mutex_lock(CNK_PKCS11_MUTEX *mutex) {
  CNK_LOG_FUNC(": mutex: %p", mutex);
  CNK_ENSURE_NONNULL(mutex, mutex->mutex_handle, mutex->lock);
  return mutex->lock(mutex->mutex_handle);
}

// Unlock a mutex
CK_RV cnk_mutex_unlock(CNK_PKCS11_MUTEX *mutex) {
  CNK_LOG_FUNC(": mutex: %p", mutex);
  CNK_ENSURE_NONNULL(mutex, mutex->mutex_handle, mutex->unlock);
  return mutex->unlock(mutex->mutex_handle);
}
