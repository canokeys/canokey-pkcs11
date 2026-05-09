#ifndef CNK_INTERNAL_CRYPTO_H
#define CNK_INTERNAL_CRYPTO_H

#include "pkcs11.h"

#include <mbedtls/md.h>

CK_RV cnk_hash_mech_to_md(CK_MECHANISM_TYPE mechanism, mbedtls_md_type_t *mdType);
CK_RV cnk_sign_mech_to_md(CK_MECHANISM_TYPE mechanism, mbedtls_md_type_t *mdType);
CK_RV cnk_mgf_to_md(CK_RSA_PKCS_MGF_TYPE mgf, mbedtls_md_type_t *mdType);
CK_RV cnk_ec_kdf_to_md(CK_ULONG kdf, mbedtls_md_type_t *mdType);
CK_RV cnk_rsa_pkcs_pss_mech_to_hash_mgf(CK_MECHANISM_TYPE mechanism, CK_MECHANISM_TYPE *hashAlg,
                                        CK_RSA_PKCS_MGF_TYPE *mgf);

#endif // CNK_INTERNAL_CRYPTO_H
