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
  CNK_PKCS11_MUTEX lock;        // Session lock using abstract mutex
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
