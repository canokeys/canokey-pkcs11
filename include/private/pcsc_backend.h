#ifndef PCSC_BACKEND_H
#define PCSC_BACKEND_H

#include "pkcs11.h"
#include "pkcs11_canokey.h"

#if defined(__APPLE__) || defined(__MACH__)
#include <PCSC/PCSC.h>
#else
#include <winscard.h> // pcsc-lite also provides it
#endif

// Define a struct to store reader information
typedef struct {
  char *name;         // Reader name
  CK_SLOT_ID slot_id; // Assigned slot ID
} ReaderInfo;

// Global variables for reader management (declared as extern)
extern ReaderInfo *g_cnk_readers;
extern CK_ULONG g_cnk_num_readers;
extern CK_BBOOL g_cnk_is_initialized;
extern CK_BBOOL g_cnk_is_managed_mode; // true for managed mode, false for standalone mode
extern SCARDCONTEXT g_cnk_pcsc_context;
extern SCARDHANDLE g_cnk_scard;

// Memory management functions
extern CNK_MALLOC_FUNC g_cnk_malloc_func;
extern CNK_FREE_FUNC g_cnk_free_func;

// PIV slots mapping to CKA_ID values
#define PIV_SLOT_9A 1
#define PIV_SLOT_9C 2
#define PIV_SLOT_9D 3
#define PIV_SLOT_9E 4
#define PIV_SLOT_82 5
#define PIV_SLOT_83 6

// Helper functions for memory allocation
static inline void *ck_malloc(size_t size) { return g_cnk_malloc_func(size); }
static inline void ck_free(void *ptr) { g_cnk_free_func(ptr); }

// Initialize PC/SC context only
CK_RV cnk_initialize_pcsc(void);

// List readers and populate g_readers
CK_RV cnk_list_readers(void);

// Clean up PC/SC resources
void cnk_cleanup_pcsc(void);

// PIV application functions
CK_RV cnk_select_piv_application(SCARDHANDLE hCard);
CK_RV cnk_verify_piv_pin(SCARDHANDLE hCard, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
CK_RV cnk_logout_piv_pin(SCARDHANDLE hCard);

// Forward declaration for session struct
typedef struct CNK_PKCS11_SESSION CNK_PKCS11_SESSION;

// Function to verify PIN with session
CK_RV cnk_verify_piv_pin_with_session(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_UTF8CHAR_PTR pPin,
                                      CK_ULONG ulPinLen);

// Extended version of verify PIN with option to control card disconnection
CK_RV cnk_verify_piv_pin_with_session_ex(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_UTF8CHAR_PTR pPin,
                                        CK_ULONG ulPinLen, CK_BBOOL disconnect_card, SCARDHANDLE *out_card);

// Function to logout PIV PIN with session
CK_RV cnk_logout_piv_pin_with_session(CK_SLOT_ID slotID);

// Get the number of readers
CK_ULONG cnk_get_num_readers(void);

// Get the slot ID for a reader at the given index
CK_SLOT_ID cnk_get_reader_slot_id(CK_ULONG index);

// Connect to a card, select the CanoKey AID, and begin a transaction
CK_RV cnk_connect_and_select_canokey(CK_SLOT_ID slotID, SCARDHANDLE *phCard);

// Disconnect from a card and end any active transaction
void cnk_disconnect_card(SCARDHANDLE hCard);

// Get firmware or hardware version
CK_RV cnk_get_version(CK_SLOT_ID slotID, CK_BYTE version_type, CK_BYTE *major, CK_BYTE *minor);

// Get PIV data from the CanoKey device
// If fetch_data is CK_FALSE, only checks for existence and sets data_len to 1 if found, 0 if not
CK_RV cnk_get_piv_data(CK_SLOT_ID slotID, CK_BYTE tag, CK_BYTE_PTR *data, CK_ULONG_PTR data_len, CK_BBOOL fetch_data);

// Get metadata for a PIV key or object
// This function retrieves metadata from a PIV key or object using the PIV metadata APDU command
CK_RV cnk_get_metadata(CK_SLOT_ID slotID, CK_BYTE piv_tag, CK_MECHANISM_TYPE_PTR algorithm_type, CK_KEY_TYPE *key_type);

// Sign data using PIV key
// This function signs data using the PIV GENERAL AUTHENTICATE command
// Currently only supports RSA 2048 with PKCS#1 v1.5 padding
CK_RV cnk_piv_sign(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_BYTE piv_tag, CK_BYTE_PTR pData,
                   CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);

#endif /* PCSC_BACKEND_H */
