#ifndef CNK_BACKEND_PIV_OPERATION_H
#define CNK_BACKEND_PIV_OPERATION_H

#include "backend/libcanokey.h"
#include "backend/pcsc.h"

/* Absent objects have different PKCS#11 meanings for metadata, keys and data. */
CK_RV cnk_piv_operation_status(uint32_t status, const CNK_LIBCANO_ERROR *error, CK_RV absent);

/* Clone the immutable profile under its lock. Never probe or select an applet
 * while the caller holds an authenticated transaction. */
CK_RV cnk_piv_context_for_session(CNK_PKCS11_SESSION *session, uint32_t state, CNK_LIBCANO_CONTEXT **context);

/* Resolve from the immutable profile before authentication, without guessing
 * extension IDs. The operation factory still owns capability authorization. */
CK_RV cnk_piv_resolve_algorithm(CNK_PKCS11_SESSION *session, CK_BYTE wire, uint32_t *algorithm);

/* Run an explicit credential action within the caller's selected transaction. */
CK_RV cnk_piv_credential_on_card(CNK_PKCS11_SESSION *session, SCARDHANDLE card, uint32_t action, const CK_BYTE *old,
                                 CK_ULONG oldLen, const CK_BYTE *replacement, CK_ULONG newLen, CK_BYTE *tries);

/* Read scalar metadata in the caller's selected transaction; never SELECT. */
CK_RV cnk_piv_read_metadata_fields(CNK_PKCS11_SESSION *session, SCARDHANDLE card, CK_BYTE reference,
                                   CNK_LIBCANO_METADATA *metadata, CK_RV absent);

/* Borrows an unstarted operation and an active card transaction.
 * The factory owns selection/authentication; context factories do neither.
 * Only libcanokey drives continuation/chaining. attempted is set before raw
 * transport so callers invalidate write caches even after uncertain failures.
 * The caller retains operation, transaction and result ownership on every exit. */
CK_RV cnk_run_piv_operation(SCARDHANDLE card, CNK_LIBCANO_OPERATION *operation, CK_RV absent, CK_BBOOL *attempted);

CK_RV cnk_copy_piv_public_key(const CNK_LIBCANO_OPERATION *operation, CNK_PIV_PUBLIC_KEY *output);

#endif
