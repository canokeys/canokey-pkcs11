#ifndef CNK_API_SESSION_H
#define CNK_API_SESSION_H

#include "pkcs11.h"

#include "internal/mutex.h"
#include <mbedtls/md.h>
#include <stdatomic.h>

// Session states as defined in PKCS#11 standard
typedef enum {
  SESSION_STATE_RO_PUBLIC = 0,
  SESSION_STATE_RO_USER,
  SESSION_STATE_RW_PUBLIC,
  SESSION_STATE_RW_USER,
  SESSION_STATE_RW_SO
} SessionState;

typedef enum {
  TOKEN_LOGIN_PUBLIC = 0,
  TOKEN_LOGIN_PENDING_USER,
  TOKEN_LOGIN_PENDING_SO,
  TOKEN_LOGIN_USER,
  TOKEN_LOGIN_SO,
} CNK_TOKEN_LOGIN_STATE;

// Login credentials are shared by every session for one slot, as required by
// PKCS#11. The lock protects state and both sensitive caches.
typedef struct CNK_PKCS11_TOKEN_STATE {
  CK_SLOT_ID slotId;
  _Atomic CNK_TOKEN_LOGIN_STATE loginState;
  CK_BYTE pin[8];
  CK_ULONG cbPin;
  CK_BYTE managementKey[24];
  CK_ULONG cbManagementKey;
  _Atomic CK_BBOOL managementLoginPending;
  _Atomic CK_BBOOL managementOperationPending;
  _Atomic CK_SESSION_HANDLE managementOperationOwner;
  _Atomic CK_BBOOL logoutRecoveryPending;
  _Atomic CK_BBOOL logoutPending;
  CK_ULONG openSessions;
  CK_ULONG readOnlySessions;
  CNK_PKCS11_MUTEX lock;
  struct CNK_PKCS11_TOKEN_STATE *next;
} CNK_PKCS11_TOKEN_STATE;

// Maximum number of session-only secret keys produced by generation,
// derivation, ML-KEM, or object copying.
#define MAX_SESSION_SECRET_KEYS 8

// Maximum number of objects that can be found (24 PIV slots x cert/public/private, 16 PIV data objects,
// plus session secrets)
#define MAX_PIV_DATA_OBJECTS 16
#define MAX_FIND_OBJECTS (72 + MAX_PIV_DATA_OBJECTS + MAX_SESSION_SECRET_KEYS)

// Session secret object IDs are kept outside the PIV object ID range.
#define CNK_SESSION_SECRET_KEY_FIRST_ID 0x80

typedef struct {
  CK_BBOOL active;
  CK_BYTE id;
  CK_KEY_TYPE keyType;
  CK_BYTE value[128];
  CK_ULONG valueLen;
  CK_BBOOL extractable;
  CK_BBOOL sensitive;
  CK_BBOOL token;
  CK_BBOOL private;
  CK_BBOOL encrypt;
  CK_BBOOL decrypt;
  CK_BBOOL sign;
  CK_BBOOL verify;
  CK_BBOOL wrap;
  CK_BBOOL unwrap;
  CK_BBOOL derive;
  CK_BBOOL local;
  CK_BBOOL modifiable;
  CK_BBOOL copyable;
  CK_BBOOL destroyable;
  CK_MECHANISM_TYPE keyGenMechanism;
  CK_BYTE label[64];
  CK_ULONG labelLen;
} CNK_PKCS11_SECRET_KEY_OBJECT;

typedef struct {
  CK_MECHANISM_TYPE mechanismType;
  mbedtls_md_type_t type;
  mbedtls_md_context_t context;
} CNK_PKCS11_DIGESTING_CONTEXT;

typedef struct {
  CK_OBJECT_HANDLE hKey;
  CK_MECHANISM mechanism;
  CK_BYTE pivSlot;
  CK_BYTE algorithmType;
  CK_BYTE pinPolicy;
  mbedtls_md_type_t mdType;
  CK_BYTE abModulus[512];
  CK_ULONG cbSignature;
  CK_BYTE_PTR message;
  CK_ULONG messageLen;
  CK_ULONG messageCapacity;
  CNK_PKCS11_DIGESTING_CONTEXT digestingContext;
  CK_BBOOL contextAuthenticated;
  CK_BYTE contextPin[8];
  CK_ULONG contextPinLen;
} CNK_PKCS11_SIGNING_CONTEXT;

typedef struct {
  CK_OBJECT_HANDLE hKey;
  CK_MECHANISM mechanism;
  CK_BYTE pivSlot;
  CK_BYTE algorithmType;
  CK_BYTE pinPolicy;
  CK_ULONG cbModulus;
  CK_BBOOL contextAuthenticated;
  CK_BYTE contextPin[8];
  CK_ULONG contextPinLen;
} CNK_PKCS11_DECRYPTING_CONTEXT;

// Verify may own the shared digest context for combined-hash mechanisms, or a
// buffered raw message for raw RSA/ECDSA and ML-DSA.
typedef struct {
  CK_OBJECT_HANDLE hKey;
  CK_MECHANISM mechanism;
  CK_BYTE algorithmType;
  mbedtls_md_type_t mdType;
  CNK_PKCS11_DIGESTING_CONTEXT digestingContext;
  CK_BYTE publicKey[2048];
  CK_ULONG publicKeyLen;
  CK_BYTE_PTR message;
  CK_ULONG messageLen;
  CK_ULONG messageCapacity;
} CNK_PKCS11_VERIFYING_CONTEXT;

typedef struct {
  CK_OBJECT_HANDLE hKey;
  CK_MECHANISM mechanism;
  CK_BYTE publicKey[2048];
  CK_ULONG publicKeyLen;
  CK_ULONG modulusLen;
} CNK_PKCS11_ENCRYPTING_CONTEXT;

// Session structure
typedef struct CNK_PKCS11_SESSION {
  CK_SESSION_HANDLE handle; // Session handle
  CK_SLOT_ID slotId;        // Slot ID associated with this session
  CK_FLAGS flags;           // Session flags
  CK_VOID_PTR application;  // Application pointer
  CK_NOTIFY notify;         // Notification callback
  CK_BBOOL isOpen;          // Flag indicating if the session is open
  _Atomic CK_BBOOL closing; // Close has started; reject new session references
  CNK_PKCS11_TOKEN_STATE *token;
  CK_BYTE mldsa65Algorithm;  // Runtime PIV algorithm-extension ID
  CK_BYTE mlkem768Algorithm; // Runtime PIV algorithm-extension ID
  CK_BYTE ed25519Algorithm;  // Runtime PIV algorithm-extension ID
  CK_BYTE x25519Algorithm;   // Runtime PIV algorithm-extension ID
  CK_BYTE rsa3072Algorithm;  // Runtime PIV algorithm-extension ID
  CK_BYTE rsa4096Algorithm;  // Runtime PIV algorithm-extension ID
  CK_BYTE secp256k1Algorithm;
  CK_BYTE secp521r1Algorithm;
  CK_BYTE sm2Algorithm;
  CNK_PKCS11_MUTEX lock; // Session lock using abstract mutex

  // Object finding fields
  CK_BBOOL findActive;                            // Whether a find operation is active
  CK_OBJECT_HANDLE findObjects[MAX_FIND_OBJECTS]; // Array of found object handles
  CK_ULONG findObjectsCount;                      // Number of objects found
  CK_ULONG findObjectsPosition;                   // Current position in the find_objects array
  CK_OBJECT_CLASS findObjectClass;                // Object class to find
  CK_BYTE findObjectId;                           // Object ID to find
  CK_BBOOL findIdSpecified;                       // Whether ID was specified in the search template
  CK_BBOOL findClassSpecified;                    // Whether class was specified in the search template

  // Cryptographic operation fields
  CNK_PKCS11_SIGNING_CONTEXT signingContext;
  CNK_PKCS11_VERIFYING_CONTEXT verifyingContext;
  CNK_PKCS11_ENCRYPTING_CONTEXT encryptingContext;
  CNK_PKCS11_DECRYPTING_CONTEXT decryptingContext;
  CNK_PKCS11_DIGESTING_CONTEXT digestingContext;
  CNK_PKCS11_SECRET_KEY_OBJECT secretKeys[MAX_SESSION_SECRET_KEYS];
  CK_BYTE nextSecretKeyId;
  // Protected by the global session-table mutex. Close removes the session
  // only after every API call that acquired this pointer has released it.
  _Atomic CK_ULONG activeCalls;
  struct CNK_PKCS11_SESSION *retiredNext;
} CNK_PKCS11_SESSION;

void cnk_session_release_ref(CNK_PKCS11_SESSION **session);

#if defined(__clang__) || defined(__GNUC__)
#define CNK_SESSION_REF __attribute__((cleanup(cnk_session_release_ref)))
#else
#error "CanoKey PKCS11 session lifetime guards require compiler cleanup support"
#endif

// Initialize the session manager
CK_RV cnk_session_manager_init(void);

// Clean up the session manager
CK_RV cnk_session_manager_cleanup(void);

// Wait until API calls that already hold session references have released
// them. Finalization calls this before tearing down backend resources.
CK_RV cnk_session_wait_for_active_calls(void);

// Find a session by handle
CK_RV cnk_session_find(CK_SESSION_HANDLE hSession, CNK_PKCS11_SESSION **session);

CK_RV cnk_session_cancel_operations(CNK_PKCS11_SESSION *session, CK_FLAGS flags);

CK_RV cnk_token_pin_is_cached(CNK_PKCS11_SESSION *session, CK_BBOOL *cached);
CK_RV cnk_token_copy_pin(CNK_PKCS11_SESSION *session, CK_BYTE pin[8], CK_ULONG_PTR pinLen);
CK_RV cnk_token_cache_pin(CNK_PKCS11_SESSION *session, CK_UTF8CHAR_PTR pin, CK_ULONG pinLen);
CK_RV cnk_token_update_cached_pin(CNK_PKCS11_SESSION *session, CK_UTF8CHAR_PTR oldPin, CK_ULONG oldPinLen,
                                  CK_UTF8CHAR_PTR newPin, CK_ULONG newPinLen);
CK_RV cnk_token_management_key_is_cached(CNK_PKCS11_SESSION *session, CK_BBOOL *cached);
CK_RV cnk_token_copy_management_key(CNK_PKCS11_SESSION *session, CK_BYTE key[24]);
CK_RV cnk_token_begin_protected_management_login(CNK_PKCS11_SESSION *session);
CK_RV cnk_token_complete_protected_management_login(CNK_PKCS11_SESSION *session, CK_BYTE_PTR key, CK_ULONG keyLen,
                                                    CK_RV verificationRv);
CK_RV cnk_token_begin_management_operation(CNK_PKCS11_SESSION *session);
CK_RV cnk_token_begin_user_operation(CNK_PKCS11_SESSION *session);
CK_RV cnk_token_begin_card_operation(CNK_PKCS11_SESSION *session);
void cnk_token_end_management_operation(CNK_PKCS11_SESSION *session);
CK_RV cnk_token_get_session_counts(CK_SLOT_ID slotId, CK_ULONG_PTR openSessions, CK_ULONG_PTR readOnlySessions);
CK_RV cnk_token_revoke_private_operations(CNK_PKCS11_TOKEN_STATE *token);

#endif /* CNK_API_SESSION_H */
