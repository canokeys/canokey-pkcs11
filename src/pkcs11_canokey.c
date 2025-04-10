#define CRYPTOKI_EXPORTS

#include "pkcs11_canokey.h"
#include "logging.h"
#include "pcsc_backend.h"
#include "pkcs11.h"

#include <stdlib.h>
#include <mbedtls/platform.h>

// Function pointers for memory allocation (global)
CNK_MALLOC_FUNC g_cnk_malloc_func = malloc;
CNK_FREE_FUNC g_cnk_free_func = free;

CK_BBOOL g_cnk_is_managed_mode = CK_FALSE; // False for standalone mode, True for managed mode
SCARDCONTEXT g_cnk_pcsc_context = 0L;
SCARDHANDLE g_cnk_scard = 0L;

// Forward declaration of the function list
static CK_FUNCTION_LIST ck_function_list;

CK_RV C_CNK_EnableManagedMode(CNK_MANAGED_MODE_INIT_ARGS_PTR pInitArgs) {
  // Check if the library is already initialized
  if (g_cnk_is_initialized)
    return CKR_CRYPTOKI_ALREADY_INITIALIZED;

  // Check if initialization arguments are provided
  if (pInitArgs != NULL_PTR) {
    if (pInitArgs->malloc_func == NULL || pInitArgs->free_func == NULL || pInitArgs->hSCardCtx == 0 ||
        pInitArgs->hScard == 0) {
      return CKR_ARGUMENTS_BAD;
    }

    g_cnk_is_managed_mode = CK_TRUE;
    g_cnk_malloc_func = pInitArgs->malloc_func;
    g_cnk_free_func = pInitArgs->free_func;
    // call mbedtls hook to use the same malloc/free functions
    mbedtls_platform_set_calloc_free(ck_calloc, ck_free);
    g_cnk_pcsc_context = pInitArgs->hSCardCtx;
    g_cnk_scard = pInitArgs->hScard;
    return CKR_OK;
  }

  return CKR_ARGUMENTS_BAD;
}

CK_RV C_CNK_ConfigLogging(int level, FILE *file) {
  if (level >= 0 && level < CNK_LOG_LEVEL_SIZE) {
    g_cnk_log_level = level;
  } else if (level != -1) {
    return CKR_ARGUMENTS_BAD;
  }

  if (file != NULL) {
    g_cnk_log_file = file;
  }

  return CKR_OK;
}
