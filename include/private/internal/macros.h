#ifndef CNK_INTERNAL_MACROS_H
#define CNK_INTERNAL_MACROS_H

#include "backend/pcsc.h"
#include "internal/lifecycle.h"
#include "internal/logging.h"
#include "internal/util.h"
#include "pkcs11.h"

/**
 * Macro to check if the PKCS#11 library is initialized
 * Returns CKR_CRYPTOKI_NOT_INITIALIZED if not initialized
 */
#if defined(__clang__) || defined(__GNUC__)
#define CNK_API_ADMISSION_CLEANUP __attribute__((cleanup(cnk_api_admission_end)))
#else
#error "CanoKey API admission guards require compiler cleanup support"
#endif

#define CNK_ENSURE_INITIALIZED()                                                                                       \
  CNK_API_ADMISSION_GUARD _cnk_api_admission_guard CNK_API_ADMISSION_CLEANUP = {.active = CK_FALSE};                   \
  do {                                                                                                                 \
    CK_RV _cnk_api_admission_rv = cnk_api_admission_begin(&_cnk_api_admission_guard);                                  \
    if (_cnk_api_admission_rv != CKR_OK)                                                                               \
      return _cnk_api_admission_rv;                                                                                    \
  } while (0)

/**
 * Macro to check if a slot ID is valid
 * Returns CKR_SLOT_ID_INVALID if the slot ID is invalid
 *
 * @param id The slot ID to check
 */
#define PKCS11_CHECK_SLOT_ID_VALID(id)                                                                                 \
  do {                                                                                                                 \
    CK_BBOOL _slot_exists = CK_FALSE;                                                                                  \
    CNK_ENSURE_OK(cnk_slot_exists((id), &_slot_exists));                                                               \
    if (!_slot_exists) {                                                                                               \
      CNK_RETURN(CKR_SLOT_ID_INVALID, "Invalid slot ID");                                                              \
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
    CNK_ENSURE_INITIALIZED();                                                                                          \
    CNK_ENSURE_NONNULL(ptr);                                                                                           \
    PKCS11_CHECK_SLOT_ID_VALID(id);                                                                                    \
  } while (0)

/**
 * Macro to validate initialization and a required pointer argument
 *
 * @param ptr The pointer to check
 */
#define PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(ptr)                                                                  \
  do {                                                                                                                 \
    CNK_ENSURE_INITIALIZED();                                                                                          \
    CNK_ENSURE_NONNULL(ptr);                                                                                           \
  } while (0)

#endif /* CNK_INTERNAL_MACROS_H */
