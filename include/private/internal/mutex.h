#ifndef CNK_INTERNAL_MUTEX_H
#define CNK_INTERNAL_MUTEX_H

#include "pkcs11.h"

#undef CreateMutex // avoid conflicts with Windows API

// Mutex abstraction structure
typedef struct CNK_PKCS11_MUTEX {
  // Mutex handle - opaque pointer to the actual mutex implementation
  void *mutex_handle;

  // Function pointers for mutex operations
  CK_RV (*create)(void **mutex);
  CK_RV (*destroy)(void *mutex);
  CK_RV (*lock)(void *mutex);
  CK_RV (*unlock)(void *mutex);
} CNK_PKCS11_MUTEX;

typedef struct {
  CNK_PKCS11_MUTEX *mutex;
  CK_BBOOL acquired;
} CNK_PKCS11_MUTEX_GUARD;

// Initialize the mutex system with the given mutex functions
// If mutex_funcs is NULL, use OS primitives
CK_RV cnk_mutex_system_init(CK_C_INITIALIZE_ARGS_PTR mutex_funcs);

// Clean up the mutex system
void cnk_mutex_system_cleanup(void);

// Create a new mutex
CK_RV cnk_mutex_create(CNK_PKCS11_MUTEX *mutex);

// Destroy a mutex
CK_RV cnk_mutex_destroy(CNK_PKCS11_MUTEX *mutex);

// Lock a mutex
CK_RV cnk_mutex_lock(CNK_PKCS11_MUTEX *mutex);

// Unlock a mutex
CK_RV cnk_mutex_unlock(CNK_PKCS11_MUTEX *mutex);

CK_RV cnk_mutex_lock_guard(CNK_PKCS11_MUTEX_GUARD *guard);
void cnk_mutex_unlock_guard(CNK_PKCS11_MUTEX_GUARD *guard);

#if defined(__clang__) || defined(__GNUC__)
#define CNK_MUTEX_GUARD __attribute__((cleanup(cnk_mutex_unlock_guard)))
#else
#error "CanoKey PKCS11 scoped mutex guards require compiler cleanup support"
#endif

#endif /* CNK_INTERNAL_MUTEX_H */
