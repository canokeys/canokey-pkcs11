#ifndef PKCS11_MACROS_H
#define PKCS11_MACROS_H

#include "pkcs11.h"

/**
 * Macro to check if the PKCS#11 library is initialized
 * Returns CKR_CRYPTOKI_NOT_INITIALIZED if not initialized
 */
#define CHECK_INITIALIZED()                                                                                            \
  do {                                                                                                                 \
    if (!g_cnk_is_initialized) {                                                                                       \
      return CKR_CRYPTOKI_NOT_INITIALIZED;                                                                             \
    }                                                                                                                  \
  } while (0)

/**
 * Macro to check if a required pointer argument is not NULL
 * Returns CKR_ARGUMENTS_BAD if the pointer is NULL
 *
 * @param ptr The pointer to check
 */
#define CHECK_ARGUMENT_NOT_NULL(ptr)                                                                                   \
  do {                                                                                                                 \
    if ((ptr) == NULL) {                                                                                               \
      return CKR_ARGUMENTS_BAD;                                                                                        \
    }                                                                                                                  \
  } while (0)

/**
 * Macro to check if a slot ID is valid
 * Returns CKR_SLOT_ID_INVALID if the slot ID is invalid
 *
 * @param id The slot ID to check
 */
#define CHECK_SLOT_ID_VALID(id)                                                                                        \
  do {                                                                                                                 \
    if ((id) >= g_cnk_num_readers) {                                                                                   \
      return CKR_SLOT_ID_INVALID;                                                                                      \
    }                                                                                                                  \
  } while (0)

/**
 * Combined macro to perform common PKCS#11 function validations:
 * 1. Check if the library is initialized
 * 2. Check if a required pointer argument is not NULL
 * 3. Check if a slot ID is valid
 *
 * @param ptr The pointer to check
 * @param id The slot ID to check
 */
#define PKCS11_VALIDATE(ptr, id)                                                                                       \
  do {                                                                                                                 \
    CHECK_INITIALIZED();                                                                                               \
    CHECK_ARGUMENT_NOT_NULL(ptr);                                                                                      \
    CHECK_SLOT_ID_VALID(id);                                                                                           \
  } while (0)

/**
 * Macro to validate initialization and a required pointer argument
 *
 * @param ptr The pointer to check
 */
#define PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(ptr)                                                                  \
  do {                                                                                                                 \
    CHECK_INITIALIZED();                                                                                               \
    CHECK_ARGUMENT_NOT_NULL(ptr);                                                                                      \
  } while (0)

#endif /* PKCS11_MACROS_H */
