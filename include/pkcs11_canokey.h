#ifndef PKCS11_CANOKEY_H
#define PKCS11_CANOKEY_H

#include "pkcs11.h"

#include <stdio.h>

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

// Extension API to enable managed mode (must be called before `C_Initialize`)
// pInitArgs: non-NULL pointer to CNK_MANAGED_MODE_INIT_ARGS
CK_DEFINE_FUNCTION(CK_RV, C_CNK_EnableManagedMode)(CNK_MANAGED_MODE_INIT_ARGS_PTR pInitArgs);
// Extension API to configure logging
// level: must be CNK_LOG_LEVEL_*, -1 for unchanged (default: CNK_LOG_LEVEL_WARNING)
// file: a valid FILE pointer, NULL for unchaged (default: stderr)
CK_DEFINE_FUNCTION(CK_RV, C_CNK_ConfigLogging)(int level, FILE *file);

#endif /* PKCS11_CANOKEY_H */
