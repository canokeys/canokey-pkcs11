#ifndef PKCS11_MANAGED_H
#define PKCS11_MANAGED_H

#include "pkcs11.h"

#if defined(__APPLE__) || defined(__MACH__)
#include <PCSC/PCSC.h>
#else
#include <winscard.h> // pcsc-lite also provides it
#endif

// Function pointer types for memory allocation
typedef void *(*CNK_MALLOC_FUNC)(size_t size);
typedef void (*CNK_FREE_FUNC)(void *ptr);

// Initialization arguments structure, for managed mode
typedef struct {
  CNK_MALLOC_FUNC malloc_func;
  CNK_FREE_FUNC free_func;
  SCARDCONTEXT hSCardCtx;
  SCARDHANDLE hScard;
} CNK_MANAGED_MODE_INIT_ARGS;

typedef CNK_MANAGED_MODE_INIT_ARGS *CNK_MANAGED_MODE_INIT_ARGS_PTR;

// Extension API to enable managed mode
CK_DEFINE_FUNCTION(CK_RV, C_CNK_EnableManagedMode)(CNK_MANAGED_MODE_INIT_ARGS_PTR pInitArgs);

#endif /* PKCS11_MANAGED_H */
