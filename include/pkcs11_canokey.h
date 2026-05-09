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
// level: must be CNK_LOG_LEVEL_*, -1 for unchanged (default: CNK_LOG_LEVEL_WARN)
// file: a valid FILE pointer, NULL for unchanged (default: stderr)
// unsafe_log_apdu: CK_TRUE enables raw APDU logging, including sensitive data
CK_DEFINE_FUNCTION(CK_RV, C_CNK_ConfigLogging)(int level, FILE *file, CK_BBOOL unsafe_log_apdu);

// Extension API to login and get remaining PIN tries
// pPinTries: pointer to an integer to receive the number of remaining PIN tries (NULL for not needed)
// See C_Login for other arguments
CK_DEFINE_FUNCTION(CK_RV, C_CNK_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin,
                                       CK_ULONG ulPinLen, CK_BYTE_PTR pPinTries);

// Extension API to convert object ID to PIV tag
// obj_id: must be a valid object ID
// piv_tag: non-NULL pointer to the PIV tag
CK_DEFINE_FUNCTION(CK_RV, C_CNK_ObjIdToPivTag)(CK_BYTE obj_id, CK_BYTE *piv_tag);

#endif /* PKCS11_CANOKEY_H */
