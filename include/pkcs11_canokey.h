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

// CanoKey vendor-defined attributes.
// Policy attributes use CK_BYTE values matching CanoKey PIV key metadata.
// CKA_CNK_VENDOR_BASE uses ASCII "CNK" (0x43 0x4E 0x4B) in the
// vendor-defined attribute range and reserves the low byte for attribute IDs.
#define CKA_CNK_VENDOR_BASE (CKA_VENDOR_DEFINED | 0x434E4B00UL)
#define CKA_CNK_PIV_PIN_POLICY (CKA_CNK_VENDOR_BASE + 0x0001UL)
#define CKA_CNK_PIV_TOUCH_POLICY (CKA_CNK_VENDOR_BASE + 0x0002UL)

#define CNK_PIV_PIN_POLICY_NEVER 0x01
#define CNK_PIV_PIN_POLICY_ONCE 0x02
#define CNK_PIV_PIN_POLICY_ALWAYS 0x03

#define CNK_PIV_TOUCH_POLICY_NEVER 0x01
#define CNK_PIV_TOUCH_POLICY_ALWAYS 0x02
#define CNK_PIV_TOUCH_POLICY_CACHED 0x03

// PIV secret reference values for C_CNK_SetPIN().
#define CNK_PIV_PIN_TYPE_PIN 0x80
#define CNK_PIV_PIN_TYPE_PUK 0x81

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

// Verify and cache a PIN-protected PIV management key while preserving the
// existing CKU_USER login. This extension is intended for managed callers that
// recovered the key from a PIN-protected PIV data object.
CK_DEFINE_FUNCTION(CK_RV, C_CNK_LoginProtectedManagementKey)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pKey,
                                                             CK_ULONG ulKeyLen);

// Read one PIV data object by its full BER-TLV tag. A NULL output buffer
// queries the required length. PIN-protected objects require a cached CKU_USER
// login and are read through that session.
CK_DEFINE_FUNCTION(CK_RV, C_CNK_GetPivData)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pTag, CK_ULONG ulTagLen,
                                            CK_BYTE_PTR pValue, CK_ULONG_PTR pulValueLen);

// Extension API to change the PIV PIN or PUK and get remaining tries.
// pinType: CNK_PIV_PIN_TYPE_PIN or CNK_PIV_PIN_TYPE_PUK
// pPinTries: pointer to receive remaining tries for the selected secret (NULL for not needed)
CK_DEFINE_FUNCTION(CK_RV, C_CNK_SetPIN)(CK_SESSION_HANDLE hSession, CK_BYTE pinType, CK_UTF8CHAR_PTR pOldPin,
                                        CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen,
                                        CK_BYTE_PTR pPinTries);

// Extension API to unblock the PIV PIN using the PUK and set a new PIN
// pPinTries: pointer to an integer to receive the number of remaining PUK tries (NULL for not needed)
CK_DEFINE_FUNCTION(CK_RV, C_CNK_UnblockPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPuk, CK_ULONG ulPukLen,
                                            CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewPinLen, CK_BYTE_PTR pPinTries);

// Extension API to convert object ID to PIV tag
// obj_id: must be a valid object ID
// piv_tag: non-NULL pointer to the PIV tag
CK_DEFINE_FUNCTION(CK_RV, C_CNK_ObjIdToPivTag)(CK_BYTE obj_id, CK_BYTE *piv_tag);

#endif /* PKCS11_CANOKEY_H */
