#ifndef CANOKEY_H
#define CANOKEY_H

#include "pkcs11.h"

#if defined(__APPLE__) || defined(__MACH__)
#include <PCSC/PCSC.h>
#else
#include <pcsclite.h>
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

// Define a struct to store reader information
typedef struct {
  char *name;         // Reader name
  CK_SLOT_ID slot_id; // Assigned slot ID
} ReaderInfo;

// Global variables for reader management (declared as extern)
extern ReaderInfo *g_readers;
extern CK_ULONG g_num_readers;
extern CK_BBOOL g_is_initialized;
extern CK_BBOOL g_is_managed_mode; // True for managed mode, False for standalone mode
extern SCARDCONTEXT g_pcsc_context;
extern SCARDHANDLE g_scard;

// Memory management functions
extern CNK_MALLOC_FUNC g_malloc_func;
extern CNK_FREE_FUNC g_free_func;

// Helper functions for memory allocation
static inline void *ck_malloc(size_t size) { return g_malloc_func(size); }

static inline void ck_free(void *ptr) { g_free_func(ptr); }

// Enable managed mode
CK_RV C_CNK_EnableManagedMode(CNK_MANAGED_MODE_INIT_ARGS_PTR pInitArgs);

// Initialize PC/SC context only
CK_RV initialize_pcsc(void);

// List readers and populate g_readers
CK_RV list_readers(void);

// Clean up PC/SC resources
void cleanup_pcsc(void);

// PIV application functions
CK_RV select_piv_application(SCARDHANDLE hCard);
CK_RV verify_piv_pin(SCARDHANDLE hCard, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
CK_RV logout_piv_pin(SCARDHANDLE hCard);

// Forward declaration for session struct
typedef struct PKCS11_SESSION PKCS11_SESSION;

// Function to verify PIN with session
CK_RV verify_piv_pin_with_session(CK_SLOT_ID slotID, PKCS11_SESSION *session, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
// Function to logout PIV PIN with session
CK_RV logout_piv_pin_with_session(CK_SLOT_ID slotID);

// Get the number of readers
CK_ULONG get_num_readers(void);

// Get the slot ID for a reader at the given index
CK_SLOT_ID get_reader_slot_id(CK_ULONG index);

// Connect to a card, select the CanoKey AID, and begin a transaction
CK_RV connect_and_select_canokey(CK_SLOT_ID slotID, SCARDHANDLE *phCard);

// Disconnect from a card and end any active transaction
void disconnect_card(SCARDHANDLE hCard);

// Get firmware or hardware version
CK_RV get_version(CK_SLOT_ID slotID, CK_BYTE version_type, CK_BYTE *major, CK_BYTE *minor);

#endif /* CANOKEY_H */
