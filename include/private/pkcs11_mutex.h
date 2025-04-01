#ifndef PKCS11_MUTEX_H
#define PKCS11_MUTEX_H

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

#endif /* PKCS11_MUTEX_H */
