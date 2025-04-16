#ifndef PCSC_BACKEND_H
#define PCSC_BACKEND_H

#include "pkcs11.h"
#include "pkcs11_canokey.h"

#include <winscard.h> // pcsc-lite also provides it

// Define a struct to store reader information
typedef struct {
  char *name;         // Reader name
  CK_SLOT_ID slot_id; // Assigned slot ID
} ReaderInfo;

// Global variables for reader management (declared as extern)
extern ReaderInfo *g_cnk_readers;
extern CK_LONG g_cnk_num_readers;
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

// Algorithm types for PIV
#define PIV_ALG_RSA_2048 0x07
#define PIV_ALG_ECC_256 0x11
#define PIV_ALG_ECC_384 0x14
#define PIV_ALG_ED25519 0xE0
#define PIV_ALG_RSA_3072 0x05
#define PIV_ALG_RSA_4096 0x16
#define PIV_ALG_X25519 0xE1
#define PIV_ALG_SECP256K1 0x53
#define PIV_ALG_SM2 0x54

// Helper functions for memory allocation
static inline void *ck_malloc(size_t size) { return g_cnk_malloc_func(size); }
static inline void *ck_calloc(size_t num, size_t size) { return g_cnk_malloc_func(num * size); }
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
                                         CK_ULONG ulPinLen, SCARDHANDLE *out_card);

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

// Get firmware version and hardware name
CK_RV cnk_get_version(CK_SLOT_ID slotID, CK_BYTE *fw_major, CK_BYTE *fw_minor, char *hw_name, size_t hw_name_len);

// Get serial number (4-byte big endian number)
CK_RV cnk_get_serial_number(CK_SLOT_ID slotID, CK_ULONG *serial_number);

// Check if the library is initialized
CK_BBOOL cnk_is_initialized(void);

// Get the number of available slots
CK_ULONG cnk_get_slot_count(void);

// Get PIV data from the CanoKey device
// If fetch_data is CK_FALSE, only checks for existence and sets data_len to 1 if found, 0 if not
CK_RV cnk_get_piv_data(CK_SLOT_ID slotID, CK_BYTE tag, CK_BYTE_PTR *data, CK_ULONG_PTR data_len, CK_BBOOL fetch_data);

// Get metadata for a PIV key or object
// This function retrieves metadata from a PIV key or object using the PIV metadata APDU command
CK_RV cnk_get_metadata(CK_SLOT_ID slotID, CK_BYTE piv_tag, CK_BYTE_PTR algorithm_type, CK_BYTE_PTR modulus_ptr,
                       CK_ULONG_PTR modulus_len_ptr);

// Sign data using PIV key
// This function signs data using the PIV GENERAL AUTHENTICATE command
// Currently only supports RSA 2048 with PKCS#1 v1.5 padding
CK_RV cnk_piv_sign(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_BYTE piv_tag, CK_BYTE_PTR pData,
                   CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);

#endif /* PCSC_BACKEND_H */
