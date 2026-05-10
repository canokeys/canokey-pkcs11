#ifndef CNK_API_SESSION_H
#define CNK_API_SESSION_H

#include "pkcs11.h"

#include "internal/mutex.h"
#include <mbedtls/md.h>

// Session states as defined in PKCS#11 standard
typedef enum {
  SESSION_STATE_RO_PUBLIC = 0,
  SESSION_STATE_RO_USER,
  SESSION_STATE_RW_PUBLIC,
  SESSION_STATE_RW_USER,
  SESSION_STATE_RW_SO
} SessionState;

// Maximum number of session-only secret keys, currently produced by C_DeriveKey.
#define MAX_SESSION_SECRET_KEYS 8

// Maximum number of objects that can be found (6 PIV slots x cert/public/private, 16 PIV data objects,
// plus session secrets)
#define MAX_PIV_DATA_OBJECTS 16
#define MAX_FIND_OBJECTS (18 + MAX_PIV_DATA_OBJECTS + MAX_SESSION_SECRET_KEYS)

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
  CK_BYTE label[64];
  CK_ULONG labelLen;
} CNK_PKCS11_SECRET_KEY_OBJECT;

typedef struct {
  CK_OBJECT_HANDLE hKey;
  CK_MECHANISM mechanism;
  CK_BYTE pivSlot;
  CK_BYTE algorithmType;
  CK_BYTE pinPolicy;
  CK_BYTE abModulus[512];
  CK_ULONG cbSignature;
} CNK_PKCS11_SIGNING_CONTEXT;

typedef struct {
  CK_OBJECT_HANDLE hKey;
  CK_MECHANISM mechanism;
  CK_BYTE pivSlot;
  CK_BYTE algorithmType;
  CK_BYTE pinPolicy;
  CK_ULONG cbModulus;
} CNK_PKCS11_DECRYPTING_CONTEXT;

typedef struct {
  CK_MECHANISM_TYPE mechanismType;
  mbedtls_md_type_t type;
  mbedtls_md_context_t context;
} CNK_PKCS11_DIGESTING_CONTEXT;

// Session structure
typedef struct CNK_PKCS11_SESSION {
  CK_SESSION_HANDLE handle;  // Session handle
  CK_SLOT_ID slotId;         // Slot ID associated with this session
  CK_FLAGS flags;            // Session flags
  CK_VOID_PTR application;   // Application pointer
  CK_NOTIFY notify;          // Notification callback
  SessionState state;        // Current session state
  CK_BBOOL isOpen;           // Flag indicating if the session is open
  CK_BYTE pin[8];            // Cached PIV PIN (padded with 0xFF)
  CK_ULONG cbPin;            // Length of the cached PIV PIN
  CK_BYTE managementKey[24]; // Cached PIV management key after CKU_SO login
  CK_ULONG cbManagementKey;  // Length of the cached PIV management key
  CNK_PKCS11_MUTEX lock;     // Session lock using abstract mutex

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
  CNK_PKCS11_DECRYPTING_CONTEXT decryptingContext;
  CNK_PKCS11_DIGESTING_CONTEXT digestingContext;
  CNK_PKCS11_SECRET_KEY_OBJECT secretKeys[MAX_SESSION_SECRET_KEYS];
  CK_BYTE nextSecretKeyId;
} CNK_PKCS11_SESSION;

// Initialize the session manager
CK_RV cnk_session_manager_init(void);

// Clean up the session manager
void cnk_session_manager_cleanup(void);

// Find a session by handle
CK_RV cnk_session_find(CK_SESSION_HANDLE hSession, CNK_PKCS11_SESSION **session);

#endif /* CNK_API_SESSION_H */
