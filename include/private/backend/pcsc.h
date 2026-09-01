#ifndef CNK_BACKEND_PCSC_H
#define CNK_BACKEND_PCSC_H

#include "pkcs11.h"
#include "pkcs11_canokey.h"

#if defined(__APPLE__) || defined(__MACH__)
#include <PCSC/PCSC.h>
#else
#include <winscard.h> // pcsc-lite also provides it
#endif
#undef CreateMutex // avoid conflicts between Windows API and PKCS#11 fields

#include "internal/mutex.h"

#include <string.h>

// Forward declaration for session struct
typedef struct CNK_PKCS11_SESSION CNK_PKCS11_SESSION;

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
extern CNK_PKCS11_MUTEX g_cnk_readers_mutex;

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
#define PIV_SLOT_COUNT 24

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
#define PIV_ALG_MLDSA65 0xE2
#define PIV_ALG_MLKEM768 0xE3

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

typedef struct {
  CK_BYTE enabled;
  CK_BYTE ed25519;
  CK_BYTE rsa3072;
  CK_BYTE rsa4096;
  CK_BYTE x25519;
  CK_BYTE secp256k1;
  CK_BYTE secp521r1;
  CK_BYTE sm2;
  CK_BYTE mldsa65;
  CK_BYTE mlkem768;
} CNK_PIV_ALGORITHM_EXTENSION_CONFIG;

// PIV object tags mapped by GET DATA / PUT DATA.
#define PIV_OBJECT_TAG_CERT_9A 0x05
#define PIV_OBJECT_TAG_CERT_9C 0x0A
#define PIV_OBJECT_TAG_CERT_9D 0x0B
#define PIV_OBJECT_TAG_CERT_9E 0x01
#define PIV_OBJECT_TAG_CERT_82 0x0D
#define PIV_OBJECT_TAG_CERT_83 0x0E

// Helper functions for memory allocation
static __attribute__((unused)) void *ck_malloc(size_t size) { return g_cnk_malloc_func(size); }
static __attribute__((unused)) void *ck_calloc(size_t num, size_t size) {
  if (size != 0 && num > (size_t)-1 / size)
    return NULL;
  size_t total = num * size;
  void *ptr = g_cnk_malloc_func(total);
  if (ptr != NULL)
    memset(ptr, 0, total);
  return ptr;
}
static __attribute__((unused)) void ck_free(void *ptr) { g_cnk_free_func(ptr); }

// Initialize PC/SC backend
CK_RV cnk_initialize_backend(void);

// Initialize PC/SC context only
CK_RV cnk_initialize_pcsc(void);

// List readers and populate g_readers
CK_RV cnk_list_readers(void);

// Clean up PC/SC resources
void cnk_cleanup_pcsc(void);

// PIV application functions
CK_RV cnk_select_piv_application(SCARDHANDLE hCard);
CK_RV cnk_verify_piv_pin(SCARDHANDLE hCard, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_BYTE_PTR pPinTries);
CK_RV cnk_logout_piv_pin(SCARDHANDLE hCard);
CK_RV cnkVerifyManagementKey(CNK_PKCS11_SESSION *session, CK_BYTE_PTR pKey);
CK_RV cnk_change_piv_secret_with_session(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_BYTE pinReference,
                                         CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldPinLen, CK_UTF8CHAR_PTR pNewPin,
                                         CK_ULONG ulNewPinLen, CK_BYTE_PTR pPinTries);
CK_RV cnk_unblock_piv_pin_with_session(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_UTF8CHAR_PTR pPuk,
                                       CK_ULONG ulPukLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewPinLen,
                                       CK_BYTE_PTR pPinTries);

// Function to verify PIN with session
CK_RV cnk_verify_piv_pin_with_session(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_UTF8CHAR_PTR pPin,
                                      CK_ULONG ulPinLen, CK_BYTE_PTR pPinTries);

CK_RV cnk_verify_piv_pin_for_context(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_BYTE_PTR pPinTries);

// Extended version of verify PIN with option to control card disconnection
CK_RV cnk_verify_piv_pin_with_session_ex(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_UTF8CHAR_PTR pPin,
                                         CK_ULONG ulPinLen, CK_BYTE_PTR pPinTries, SCARDHANDLE *out_card);

// Function to logout PIV PIN with session
CK_RV cnk_logout_piv_pin_with_session(CK_SLOT_ID slotID);

// Get the number of readers
CK_ULONG cnk_get_num_readers(void);

// Get the slot ID for a reader at the given index
CK_SLOT_ID cnk_get_reader_slot_id(CK_ULONG index);

CK_RV cnk_wait_for_slot_event(CK_FLAGS flags, CK_SLOT_ID_PTR slot);

// Connect to a card, select the CanoKey AID, and begin a transaction
CK_RV cnk_connect_and_select_canokey(CK_SLOT_ID slotID, SCARDHANDLE *phCard);

// Disconnect from a card and end any active transaction
void cnk_disconnect_card(SCARDHANDLE hCard);

// Get firmware version and hardware name
CK_RV cnk_get_version(CK_SLOT_ID slotID, CK_BYTE *fw_major, CK_BYTE *fw_minor, char *hw_name, size_t hw_name_len);

// Get serial number (4-byte big endian number)
CK_RV cnk_get_serial_number(CK_SLOT_ID slotID, CK_ULONG *serial_number);

// Get PIV data from the CanoKey device. If fetch_data is CK_FALSE, only checks
// existence and reports it through the return value.
CK_RV cnk_get_piv_data(CK_SLOT_ID slotID, CK_BYTE tag, CK_BYTE_PTR data, CK_ULONG_PTR data_len, CK_BBOOL fetch_data);

// Get a PIV data object by its full BER-TLV tag, for example 5F C1 02 or 7E.
CK_RV cnk_get_piv_data_by_tag(CK_SLOT_ID slotID, const CK_BYTE *tag, CK_ULONG tag_len, CK_BYTE_PTR data,
                              CK_ULONG_PTR data_len, CK_BBOOL fetch_data);

// Get a PIV data object by its full BER-TLV tag, verifying the cached user PIN first when available.
CK_RV cnk_get_piv_data_by_tag_with_session(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, const CK_BYTE *tag,
                                           CK_ULONG tag_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len,
                                           CK_BBOOL fetch_data);

// Write a PIV data object. The tag is the one-byte 0x5FC1xx object tag.
CK_RV cnk_put_piv_data(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_BYTE tag, CK_BYTE_PTR data,
                       CK_ULONG data_len);

// Write a PIV data object by its full BER-TLV tag.
CK_RV cnk_put_piv_data_by_tag(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, const CK_BYTE *tag, CK_ULONG tag_len,
                              CK_BYTE_PTR data, CK_ULONG data_len);

// Get metadata for a PIV key or object
// This function retrieves metadata from a PIV key or object using the PIV metadata APDU command
CK_RV cnk_get_metadata(CK_SLOT_ID slotID, CK_BYTE pivTag, CK_BYTE_PTR pbAlgorithmType, CK_BYTE_PTR pbPublicKey,
                       CK_ULONG_PTR pulPublicKeyLen, CK_BYTE_PTR pbPinPolicy, CK_BYTE_PTR pbTouchPolicy);

// Read the firmware 5.7+ PIV metadata directory. Older firmware returns
// CKR_FUNCTION_NOT_SUPPORTED so callers can fall back to per-slot probes.
CK_RV cnk_get_piv_metadata_directory(CK_SLOT_ID slotID, CNK_PIV_METADATA_DIRECTORY_ENTRY *entries,
                                     CK_ULONG_PTR entryCount);

CK_RV cnk_get_piv_algorithm_extension(CK_SLOT_ID slotID, CNK_PIV_ALGORITHM_EXTENSION_CONFIG *config);

// Firmware 6.0+ exposes an unauthenticated PIV GET CHALLENGE command backed by
// the token RNG. Older firmware reports supported = CK_FALSE.
CK_RV cnk_piv_random_supported(CK_SLOT_ID slotID, CK_BBOOL *supported);
CK_RV cnk_piv_generate_random(CK_SLOT_ID slotID, CK_BYTE_PTR output, CK_ULONG outputLen);

// Generate a PIV asymmetric key pair.
CK_RV cnk_piv_generate_keypair(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_BYTE algorithmType, CK_BYTE pivSlot,
                               CK_BYTE pinPolicy, CK_BYTE touchPolicy, CK_BYTE_PTR pbPublicKey,
                               CK_ULONG_PTR pcbPublicKey);

// Import a PIV asymmetric private key.
CK_RV cnk_piv_import_key(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_BYTE algorithmType, CK_BYTE pivSlot,
                         CK_BYTE_PTR keyData, CK_ULONG keyDataLen);

// Sign data using PIV key
// This function signs data using the PIV GENERAL AUTHENTICATE command
CK_RV cnk_piv_sign(CK_SLOT_ID slotId, CNK_PKCS11_SESSION *pSession, CK_BYTE_PTR pData, CK_ULONG cbDataLen,
                   CK_BYTE_PTR pSignature, CK_ULONG_PTR pcbSignature);

// Decrypt data using a PIV RSA key
// This function returns the raw RSA private operation result from GENERAL AUTHENTICATE
CK_RV cnk_piv_decrypt(CK_SLOT_ID slotId, CNK_PKCS11_SESSION *pSession, CK_BYTE_PTR pEncryptedData,
                      CK_ULONG cbEncryptedData, CK_BYTE_PTR pRawData, CK_ULONG_PTR pcbRawData);

// Perform ECDH key agreement using a PIV EC key
// This function returns the raw shared secret from GENERAL AUTHENTICATE
CK_RV cnk_piv_ecdh(CK_SLOT_ID slotId, CNK_PKCS11_SESSION *pSession, CK_BYTE algorithmType, CK_BYTE pivSlot,
                   CK_BYTE pinPolicy, CK_BYTE_PTR pPublicData, CK_ULONG cbPublicData, CK_BYTE_PTR pSharedSecret,
                   CK_ULONG_PTR pcbSharedSecret);

CK_RV cnk_piv_mlkem_decapsulate(CK_SLOT_ID slotId, CNK_PKCS11_SESSION *pSession, CK_BYTE algorithmType, CK_BYTE pivSlot,
                                CK_BYTE pinPolicy, CK_BYTE_PTR pCiphertext, CK_ULONG cbCiphertext,
                                CK_BYTE_PTR pSharedSecret, CK_ULONG_PTR pcbSharedSecret);

#endif /* CNK_BACKEND_PCSC_H */
