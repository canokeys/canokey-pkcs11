#ifndef PKCS11_SESSION_H
#define PKCS11_SESSION_H

#include "pkcs11.h"

#include "pkcs11_mutex.h"
#include <mbedtls/md.h>

// Session states as defined in PKCS#11 standard
typedef enum {
  SESSION_STATE_RO_PUBLIC = 0,
  SESSION_STATE_RO_USER,
  SESSION_STATE_RW_PUBLIC,
  SESSION_STATE_RW_USER,
  SESSION_STATE_RW_SO
} SessionState;

// Maximum number of objects that can be found
#define MAX_FIND_OBJECTS 6

// Session structure
typedef struct CNK_PKCS11_SESSION {
  CK_SESSION_HANDLE handle; // Session handle
  CK_SLOT_ID slot_id;       // Slot ID associated with this session
  CK_FLAGS flags;           // Session flags
  CK_VOID_PTR application;  // Application pointer
  CK_NOTIFY notify;         // Notification callback
  SessionState state;       // Current session state
  CK_BBOOL is_open;         // Flag indicating if the session is open
  CK_BYTE piv_pin[8];       // Cached PIV PIN (padded with 0xFF)
  CK_ULONG piv_pin_len;     // Length of the cached PIV PIN
  CNK_PKCS11_MUTEX lock;    // Session lock using abstract mutex

  // Object finding fields
  CK_BBOOL find_active;                            // Whether a find operation is active
  CK_OBJECT_HANDLE find_objects[MAX_FIND_OBJECTS]; // Array of found object handles
  CK_ULONG find_objects_count;                     // Number of objects found
  CK_ULONG find_objects_position;                  // Current position in the find_objects array
  CK_OBJECT_CLASS find_object_class;               // Object class to find
  CK_BYTE find_object_id;                          // Object ID to find
  CK_BBOOL find_id_specified;                      // Whether ID was specified in the search template
  CK_BBOOL find_class_specified;                   // Whether class was specified in the search template

  // Cryptographic operation fields
  CK_OBJECT_HANDLE active_key;           // Active key for crypto operations
  CK_MECHANISM_PTR active_mechanism_ptr; // Pointer to active mechanism structure
  CK_BYTE active_key_piv_tag;            // PIV tag of the active key
  CK_BYTE active_key_algorithm_type;     // Algorithm type of the active key
  CK_BYTE active_key_modulus[512];       // Cached modulus for RSA operations (max 4096 bits)
  CK_ULONG active_key_modulus_len;       // Length of the cached modulus
  mbedtls_md_context_t digest_ctx;      // context for digest operations
  CK_MECHANISM_TYPE digest_mech;        // active digest mechanism
  CK_BBOOL digest_active;               // whether a digest operation is active
} CNK_PKCS11_SESSION;

// Initialize the session manager
CK_RV cnk_session_manager_init(void);

// Clean up the session manager
void cnk_session_manager_cleanup(void);

// Find a session by handle
CK_RV cnk_session_find(CK_SESSION_HANDLE hSession, CNK_PKCS11_SESSION **session);

#endif /* PKCS11_SESSION_H */
