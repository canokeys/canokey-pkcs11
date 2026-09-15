#ifndef CNK_BACKEND_PIV_OPERATION_H
#define CNK_BACKEND_PIV_OPERATION_H

#include "backend/libcanokey.h"
#include "backend/pcsc.h"
#include "internal/logging.h"

/* Absent objects have different PKCS#11 meanings for metadata, keys and data. */
CK_RV cnk_piv_operation_status(uint32_t status, const cnk_error_v1 *error, CK_RV absent);

/* Borrow the profile under its lock only while a factory copies its inputs.
 * End releases the lock and discards provisional operations on every failure;
 * card I/O starts afterward, without holding this lock or reselecting PIV. */
CK_RV cnk_piv_profile_begin(CNK_PKCS11_SESSION *session, const cnk_profile_t **profile);
CK_RV cnk_piv_profile_end(CNK_PKCS11_SESSION *session, cnk_operation_t **operation, uint32_t status,
                          const cnk_error_v1 *error);
extern const cnk_operation_options_v1 cnk_piv_existing_options;
#define CNK_PIV_CREATE(SESSION, FUNCTION, OUT, ERROR, ...)                                                             \
  ({                                                                                                                   \
    const cnk_profile_t *_cnk_profile = NULL;                                                                          \
    CK_RV _cnk_rv = cnk_piv_profile_begin((SESSION), &_cnk_profile);                                                   \
    if (_cnk_rv == CKR_OK) {                                                                                           \
      uint32_t _cnk_status =                                                                                           \
          CNK_EXTERNAL_CALL(FUNCTION, _cnk_profile, __VA_ARGS__, &cnk_piv_existing_options, OUT, ERROR);               \
      _cnk_rv = cnk_piv_profile_end((SESSION), OUT, _cnk_status, ERROR);                                               \
    }                                                                                                                  \
    _cnk_rv;                                                                                                           \
  })

/* Require observed algorithm support before authentication. This local query
 * does not select or authorize; operation factories revalidate their policy. */
CK_RV cnk_piv_require_algorithm(CNK_PKCS11_SESSION *session, uint32_t algorithm);

/* Run an explicit credential action within the caller's selected transaction. */
CK_RV cnk_piv_credential_on_card(CNK_PKCS11_SESSION *session, SCARDHANDLE card, uint32_t action, const CK_BYTE *old,
                                 CK_ULONG oldLen, const CK_BYTE *replacement, CK_ULONG newLen, CK_BYTE *tries);

/* Read scalar metadata in the caller's selected transaction; never SELECT. */
CK_RV cnk_piv_read_metadata_fields(CNK_PKCS11_SESSION *session, SCARDHANDLE card, CK_BYTE reference,
                                   cnk_metadata_v1 *metadata, CK_RV absent);

/* Borrows an unstarted operation and an active card transaction.
 * The factory owns selection/authentication; USE_EXISTING omits implicit selection/authentication.
 * Only libcanokey drives continuation/chaining. attempted is set before raw
 * transport so callers invalidate write caches even after uncertain failures.
 * The caller retains operation, transaction and result ownership on every exit. */
CK_RV cnk_run_piv_operation(SCARDHANDLE card, cnk_operation_t *operation, CK_RV absent, CK_BBOOL *attempted);

CK_RV cnk_copy_piv_public_key(const cnk_operation_t *operation, CNK_PIV_PUBLIC_KEY *output);

#endif
