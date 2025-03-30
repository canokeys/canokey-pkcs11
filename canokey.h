#ifndef CANOKEY_H
#define CANOKEY_H

#include "pkcs11.h"
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>

// Function pointer types for memory allocation
typedef void *(*CK_MALLOC_FUNC)(size_t size);
typedef void (*CK_FREE_FUNC)(void *ptr);

// Initialization arguments structure
typedef struct {
  CK_MALLOC_FUNC malloc_func;
  CK_FREE_FUNC free_func;
  SCARDCONTEXT hSCardCtx;
  SCARDHANDLE hScard;
} CK_INIT_ARGS;

// Define a struct to store reader information
typedef struct {
  char *name;         // Reader name
  CK_SLOT_ID slot_id; // Assigned slot ID
} ReaderInfo;

// Global variables for reader management (declared as extern)
extern ReaderInfo *g_readers;
extern CK_ULONG g_num_readers;
extern CK_BBOOL g_is_initialized;
extern CK_BBOOL g_is_minidriver_mode;
extern SCARDCONTEXT g_pcsc_context;
extern SCARDHANDLE g_scard;

// Minidriver mode functions
extern CK_MALLOC_FUNC g_malloc_func;
extern CK_FREE_FUNC g_free_func;

// Helper functions for memory allocation
static inline void *ck_malloc(size_t size) { return g_malloc_func(size); }

static inline void ck_free(void *ptr) { g_free_func(ptr); }

// Initialize PC/SC context only
CK_RV initialize_pcsc(void);

// List readers and populate g_readers
CK_RV list_readers(void);

// Clean up PC/SC resources
void cleanup_pcsc(void);

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
