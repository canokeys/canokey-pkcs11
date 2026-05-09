#include "internal/crypto.h"
#include "internal/logging.h"
#include "internal/util.h"

CK_RV cnk_hash_mech_to_md(CK_MECHANISM_TYPE mechanism, mbedtls_md_type_t *mdType) {
  CNK_ENSURE_NONNULL(mdType);

  switch (mechanism) {
  case CKM_SHA_1:
    *mdType = MBEDTLS_MD_SHA1;
    break;
  case CKM_SHA224:
    *mdType = MBEDTLS_MD_SHA224;
    break;
  case CKM_SHA256:
    *mdType = MBEDTLS_MD_SHA256;
    break;
  case CKM_SHA384:
    *mdType = MBEDTLS_MD_SHA384;
    break;
  case CKM_SHA512:
    *mdType = MBEDTLS_MD_SHA512;
    break;
  case CKM_SHA3_224:
    *mdType = MBEDTLS_MD_SHA3_224;
    break;
  case CKM_SHA3_256:
    *mdType = MBEDTLS_MD_SHA3_256;
    break;
  case CKM_SHA3_384:
    *mdType = MBEDTLS_MD_SHA3_384;
    break;
  case CKM_SHA3_512:
    *mdType = MBEDTLS_MD_SHA3_512;
    break;
  default:
    CNK_RETURN(CKR_MECHANISM_INVALID, "unsupported hash mechanism");
  }

  CNK_RET_OK;
}

CK_RV cnk_sign_mech_to_md(CK_MECHANISM_TYPE mechanism, mbedtls_md_type_t *mdType) {
  CNK_ENSURE_NONNULL(mdType);

  switch (mechanism) {
  case CKM_SHA1_RSA_PKCS:
  case CKM_SHA1_RSA_PKCS_PSS:
  case CKM_ECDSA_SHA1:
    *mdType = MBEDTLS_MD_SHA1;
    break;
  case CKM_SHA224_RSA_PKCS:
  case CKM_SHA224_RSA_PKCS_PSS:
  case CKM_ECDSA_SHA224:
    *mdType = MBEDTLS_MD_SHA224;
    break;
  case CKM_SHA256_RSA_PKCS:
  case CKM_SHA256_RSA_PKCS_PSS:
  case CKM_ECDSA_SHA256:
    *mdType = MBEDTLS_MD_SHA256;
    break;
  case CKM_SHA384_RSA_PKCS:
  case CKM_SHA384_RSA_PKCS_PSS:
  case CKM_ECDSA_SHA384:
    *mdType = MBEDTLS_MD_SHA384;
    break;
  case CKM_SHA512_RSA_PKCS:
  case CKM_SHA512_RSA_PKCS_PSS:
  case CKM_ECDSA_SHA512:
    *mdType = MBEDTLS_MD_SHA512;
    break;
  case CKM_SHA3_224_RSA_PKCS:
  case CKM_SHA3_224_RSA_PKCS_PSS:
  case CKM_ECDSA_SHA3_224:
    *mdType = MBEDTLS_MD_SHA3_224;
    break;
  case CKM_SHA3_256_RSA_PKCS:
  case CKM_SHA3_256_RSA_PKCS_PSS:
  case CKM_ECDSA_SHA3_256:
    *mdType = MBEDTLS_MD_SHA3_256;
    break;
  case CKM_SHA3_384_RSA_PKCS:
  case CKM_SHA3_384_RSA_PKCS_PSS:
  case CKM_ECDSA_SHA3_384:
    *mdType = MBEDTLS_MD_SHA3_384;
    break;
  case CKM_SHA3_512_RSA_PKCS:
  case CKM_SHA3_512_RSA_PKCS_PSS:
  case CKM_ECDSA_SHA3_512:
    *mdType = MBEDTLS_MD_SHA3_512;
    break;
  default:
    CNK_RETURN(CKR_MECHANISM_INVALID, "unsupported signing hash mechanism");
  }

  CNK_RET_OK;
}

CK_RV cnk_mgf_to_md(CK_RSA_PKCS_MGF_TYPE mgf, mbedtls_md_type_t *mdType) {
  CNK_ENSURE_NONNULL(mdType);

  switch (mgf) {
  case CKG_MGF1_SHA1:
    *mdType = MBEDTLS_MD_SHA1;
    break;
  case CKG_MGF1_SHA224:
    *mdType = MBEDTLS_MD_SHA224;
    break;
  case CKG_MGF1_SHA256:
    *mdType = MBEDTLS_MD_SHA256;
    break;
  case CKG_MGF1_SHA384:
    *mdType = MBEDTLS_MD_SHA384;
    break;
  case CKG_MGF1_SHA512:
    *mdType = MBEDTLS_MD_SHA512;
    break;
  case CKG_MGF1_SHA3_224:
    *mdType = MBEDTLS_MD_SHA3_224;
    break;
  case CKG_MGF1_SHA3_256:
    *mdType = MBEDTLS_MD_SHA3_256;
    break;
  case CKG_MGF1_SHA3_384:
    *mdType = MBEDTLS_MD_SHA3_384;
    break;
  case CKG_MGF1_SHA3_512:
    *mdType = MBEDTLS_MD_SHA3_512;
    break;
  default:
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "unsupported MGF");
  }

  CNK_RET_OK;
}

CK_RV cnk_rsa_pkcs_pss_mech_to_hash_mgf(CK_MECHANISM_TYPE mechanism, CK_MECHANISM_TYPE *hashAlg,
                                        CK_RSA_PKCS_MGF_TYPE *mgf) {
  CNK_ENSURE_NONNULL(hashAlg, mgf);

  switch (mechanism) {
  case CKM_SHA1_RSA_PKCS_PSS:
    *hashAlg = CKM_SHA_1;
    *mgf = CKG_MGF1_SHA1;
    break;
  case CKM_SHA224_RSA_PKCS_PSS:
    *hashAlg = CKM_SHA224;
    *mgf = CKG_MGF1_SHA224;
    break;
  case CKM_SHA256_RSA_PKCS_PSS:
    *hashAlg = CKM_SHA256;
    *mgf = CKG_MGF1_SHA256;
    break;
  case CKM_SHA384_RSA_PKCS_PSS:
    *hashAlg = CKM_SHA384;
    *mgf = CKG_MGF1_SHA384;
    break;
  case CKM_SHA512_RSA_PKCS_PSS:
    *hashAlg = CKM_SHA512;
    *mgf = CKG_MGF1_SHA512;
    break;
  case CKM_SHA3_224_RSA_PKCS_PSS:
    *hashAlg = CKM_SHA3_224;
    *mgf = CKG_MGF1_SHA3_224;
    break;
  case CKM_SHA3_256_RSA_PKCS_PSS:
    *hashAlg = CKM_SHA3_256;
    *mgf = CKG_MGF1_SHA3_256;
    break;
  case CKM_SHA3_384_RSA_PKCS_PSS:
    *hashAlg = CKM_SHA3_384;
    *mgf = CKG_MGF1_SHA3_384;
    break;
  case CKM_SHA3_512_RSA_PKCS_PSS:
    *hashAlg = CKM_SHA3_512;
    *mgf = CKG_MGF1_SHA3_512;
    break;
  default:
    CNK_RETURN(CKR_MECHANISM_INVALID, "mechanism has no fixed PSS hash/MGF");
  }

  CNK_RET_OK;
}
