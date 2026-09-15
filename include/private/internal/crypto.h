#ifndef CNK_INTERNAL_CRYPTO_H
#define CNK_INTERNAL_CRYPTO_H

#include "pkcs11.h"

#include <mbedtls/md.h>

CK_RV cnk_hash_mech_to_md(CK_MECHANISM_TYPE mechanism, mbedtls_md_type_t *mdType);
// Pure lookup: raw or unsupported signing mechanisms return MBEDTLS_MD_NONE.
mbedtls_md_type_t cnk_sign_mech_to_md(CK_MECHANISM_TYPE mechanism);
CK_RV cnk_mgf_to_md(CK_RSA_PKCS_MGF_TYPE mgf, mbedtls_md_type_t *mdType);
CK_RV cnk_ec_kdf_to_md(CK_ULONG kdf, mbedtls_md_type_t *mdType);

#endif // CNK_INTERNAL_CRYPTO_H
