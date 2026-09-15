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

// PIV metadata-directory entries returned by the read-only extension below.
// Callers own the output array and the module retains no caller pointer after
// the call returns. Standalone mode may retain a bounded public copy internally;
// managed mode bypasses that copy.
#define CNK_PIV_METADATA_DIRECTORY_FLAG_KEY 0x01
#define CNK_PIV_METADATA_DIRECTORY_FLAG_CERT 0x02
#define CNK_PIV_METADATA_DIRECTORY_MAX_ENTRIES 24

typedef struct {
  CK_BYTE pivSlot;
  CK_BYTE flags;
  CK_BYTE algorithmType;
  CK_BYTE origin;
  CK_BYTE pinPolicy;
  CK_BYTE touchPolicy;
} CNK_PIV_METADATA_DIRECTORY_ENTRY;

// Vendor mechanisms have explicit SM2 semantics; they are not ECDSA/ECDH aliases.
#define CKM_CNK_SM2_RAW (CKM_VENDOR_DEFINED | 0x434E4B01UL)
#define CKM_CNK_SM2_SM3 (CKM_VENDOR_DEFINED | 0x434E4B02UL)
#define CKM_CNK_SM2_DERIVE (CKM_VENDOR_DEFINED | 0x434E4B03UL)
// Public 65-byte SEC1 ephemeral point attached to an SM2-derived session key.
#define CKA_CNK_SM2_EPHEMERAL_PUBLIC (CKA_VENDOR_DEFINED | 0x434E4B03UL)

#if defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)
#pragma pack(push, cnk_sm2, 1)
#endif
typedef struct CK_CNK_SM2_DERIVE_PARAMS {
  CK_ULONG role; // 1 initiator, 2 responder; peer material is pre-exchanged
  CK_BYTE_PTR pPeerStatic;
  CK_ULONG ulPeerStaticLen;
  CK_BYTE_PTR pPeerEphemeral;
  CK_ULONG ulPeerEphemeralLen;
  CK_BYTE_PTR pUserId; // NULL/0 selects the PIV default identity
  CK_ULONG ulUserIdLen;
  CK_BYTE_PTR pPeerId;
  CK_ULONG ulPeerIdLen;
} CK_CNK_SM2_DERIVE_PARAMS;
#if defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)
#pragma pack(pop, cnk_sm2)
#endif

// PIV secret reference values for C_CNK_SetPIN().
#define CNK_PIV_PIN_TYPE_PIN 0x80
#define CNK_PIV_PIN_TYPE_PUK 0x81

// Extension API to enable managed mode (must be called before `C_Initialize`)
// pInitArgs: non-NULL pointer to CNK_MANAGED_MODE_INIT_ARGS
CK_DEFINE_FUNCTION(CK_RV, C_CNK_EnableManagedMode)(CNK_MANAGED_MODE_INIT_ARGS_PTR pInitArgs);

// Roll back a managed-mode binding when C_Initialize fails before publishing
// the Cryptoki initialized state. Returns CKR_OPERATION_ACTIVE once initialized.
CK_DEFINE_FUNCTION(CK_RV, C_CNK_ResetManagedMode)(void);

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

// Authenticate the user PIN and, when ADMIN DATA marks the token as
// PIN-protected, recover and authenticate the management key without exposing
// it to the caller.
CK_DEFINE_FUNCTION(CK_RV, C_CNK_LoginPinManaged)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);

// Finish a preconfigured PIN-managed setup by authenticating USER and the
// protected management key, then permanently blocking the PIV PUK. This is a
// destructive provisioning operation; successful completion leaves zero PUK
// retries.
CK_DEFINE_FUNCTION(CK_RV, C_CNK_FinalizePinManaged)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin,
                                                    CK_ULONG ulPinLen);

// Read one PIV data object by its full BER-TLV tag. A NULL output buffer
// queries the required length. PIN-protected objects require a cached CKU_USER
// login and are read through that session.
CK_DEFINE_FUNCTION(CK_RV, C_CNK_GetPivData)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pTag, CK_ULONG ulTagLen,
                                            CK_BYTE_PTR pValue, CK_ULONG_PTR pulValueLen);

// Read the firmware metadata directory in one card transaction. Firmware
// versions before 5.7 return CKR_FUNCTION_NOT_SUPPORTED. A NULL entries
// pointer performs a count query; entryCount is updated before any buffer
// error, following PKCS#11 two-stage output semantics.
CK_DEFINE_FUNCTION(CK_RV, C_CNK_GetPivMetadataDirectory)(CK_SESSION_HANDLE hSession,
                                                         CNK_PIV_METADATA_DIRECTORY_ENTRY *entries,
                                                         CK_ULONG_PTR entryCount);

// Extension API to change the PIV PIN or PUK and get remaining tries.
// pinType: CNK_PIV_PIN_TYPE_PIN or CNK_PIV_PIN_TYPE_PUK
// pPinTries: pointer to receive remaining tries for the selected secret (NULL for not needed)
CK_DEFINE_FUNCTION(CK_RV, C_CNK_SetPIN)(CK_SESSION_HANDLE hSession, CK_BYTE pinType, CK_UTF8CHAR_PTR pOldPin,
                                        CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen,
                                        CK_BYTE_PTR pPinTries);

// Extension API to unblock the PIV PIN using the PUK and set a new PIN
// pPinTries: pointer to an integer to receive the number of remaining PUK tries (NULL for not needed)
// Returns CKR_ACTION_PROHIBITED when PIN-managed management-key recovery is configured.
CK_DEFINE_FUNCTION(CK_RV, C_CNK_UnblockPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPuk, CK_ULONG ulPukLen,
                                            CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewPinLen, CK_BYTE_PTR pPinTries);

// Extension API to convert object ID to PIV tag
// obj_id: must be a valid object ID
// piv_tag: non-NULL pointer to the PIV tag
CK_DEFINE_FUNCTION(CK_RV, C_CNK_ObjIdToPivTag)(CK_BYTE obj_id, CK_BYTE *piv_tag);

// F5 vendor extension. Names are raw UTF-16LE bytes, not CK_UTF8CHAR strings.
// PIV references: 9A/9C/9D/9E, 82..95, F9 (not PKCS#11 object IDs).
// Get uses a fresh, unauthenticated read even for a NULL-buffer size query.
// Empty success means unnamed; CKR_KEY_HANDLE_INVALID means absent key.
// PIV < 6.0.0 returns FUNCTION_NOT_SUPPORTED without sending F5, using the
// same version gate as RNG. F5 errors on PIV >= 6.0.0 are not legacy fallback.
#define CNK_PIV_CONTAINER_NAME_MAX_BYTES 78
CK_DEFINE_FUNCTION(CK_RV, C_CNK_GetContainerName)(CK_SESSION_HANDLE hSession, CK_BYTE pivSlot, CK_BYTE_PTR name,
                                                  CK_ULONG_PTR nameLen);
// RW session and SO/protected-management authorization required. Zero length clears.
// A failed transport can follow a committed write: read back, never regenerate a key.
CK_DEFINE_FUNCTION(CK_RV, C_CNK_SetContainerName)(CK_SESSION_HANDLE hSession, CK_BYTE pivSlot, CK_BYTE_PTR name,
                                                  CK_ULONG nameLen);

// Physical key lifecycle uses PIV references, not PKCS#11 object handles.
// Move requires an empty destination; target 0xFF deletes the source key/name.
// Both public/private views move or disappear; certificates remain in their slots.
// Requires RW + SO/protected management. Attempted writes revoke pending
// find/sign/decrypt operations. No automatic retry after uncertain I/O.
CK_DEFINE_FUNCTION(CK_RV, C_CNK_MoveKey)(CK_SESSION_HANDLE hSession, CK_BYTE source, CK_BYTE target);

// Read a fresh attestation DER for a generated key. No trust decision is made.
// NULL output queries length; short output is untouched and reports required length.
// Each call performs a new card request, including a query or buffer retry.
CK_DEFINE_FUNCTION(CK_RV, C_CNK_Attest)(CK_SESSION_HANDLE hSession, CK_BYTE pivSlot, CK_BYTE_PTR certificate,
                                        CK_ULONG_PTR certificateLen);

// Rotate the 24-byte management key with its current algorithm (1 TDES, 2 AES192).
// touch is 0 never or 1 always (AES192 only). Requires RW + management auth.
// In PIN-managed mode also requires USER login; updates PRINTED after key rotation.
// Writes are not atomic: after uncertain failure recover using the supplied new
// key and repair PRINTED. Any attempt clears local credentials/private operations.
CK_DEFINE_FUNCTION(CK_RV, C_CNK_SetManagementKey)(CK_SESSION_HANDLE hSession, CK_ULONG algorithm, CK_BYTE_PTR key,
                                                  CK_ULONG keyLen, CK_BBOOL touch);

// Set retry limits (1..15) AND reset PIN/PUK to firmware defaults. Requires RW,
// management authorization and the explicitly supplied current PIN. Protected
// mode prohibits this operation because it would re-enable PUK recovery.
// Any attempted reset clears all cached credentials and private operations.
CK_DEFINE_FUNCTION(CK_RV, C_CNK_SetPinRetries)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pin, CK_ULONG pinLen,
                                               CK_BYTE pinRetries, CK_BYTE pukRetries);

#endif /* PKCS11_CANOKEY_H */
