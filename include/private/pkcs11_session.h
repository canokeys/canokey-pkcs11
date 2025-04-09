#ifndef PKCS11_SESSION_H
#define PKCS11_SESSION_H

#include "pkcs11.h"

#include "pkcs11_mutex.h"

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
  CK_OBJECT_HANDLE active_key;                     // Active key for crypto operations
  CK_MECHANISM_TYPE active_mechanism;              // Active mechanism for crypto operations
  CK_BYTE active_key_piv_tag;                     // PIV tag of the active key
  CK_BYTE active_key_algorithm_type;              // Algorithm type of the active key
} CNK_PKCS11_SESSION;

// Initialize the session manager
CK_RV cnk_session_manager_init(void);

// Clean up the session manager
void cnk_session_manager_cleanup(void);

// Open a new session
CK_RV cnk_session_open(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify,
                       CK_SESSION_HANDLE_PTR phSession);

// Close a session
CK_RV cnk_session_close(CK_SESSION_HANDLE hSession);

// Close all sessions for a slot
CK_RV cnk_session_close_all(CK_SLOT_ID slotID);

// Get session info
CK_RV cnk_session_get_info(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);

// Find a session by handle
CK_RV cnk_session_find(CK_SESSION_HANDLE hSession, CNK_PKCS11_SESSION **session);

#endif /* PKCS11_SESSION_H */
