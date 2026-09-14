#include "internal/crypto.h"
#include "internal/logging.h"
#include "internal/util.h"

#include <psa/crypto.h>

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

CK_RV cnk_ec_kdf_to_md(CK_ULONG kdf, mbedtls_md_type_t *mdType) {
  CNK_ENSURE_NONNULL(mdType);

  switch (kdf) {
  case CKD_SHA1_KDF:
    *mdType = MBEDTLS_MD_SHA1;
    break;
  case CKD_SHA224_KDF:
    *mdType = MBEDTLS_MD_SHA224;
    break;
  case CKD_SHA256_KDF:
    *mdType = MBEDTLS_MD_SHA256;
    break;
  case CKD_SHA384_KDF:
    *mdType = MBEDTLS_MD_SHA384;
    break;
  case CKD_SHA512_KDF:
    *mdType = MBEDTLS_MD_SHA512;
    break;
  default:
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "unsupported EC KDF");
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

CK_RV cnk_aes192_encrypt_block(const CK_BYTE key[24], const CK_BYTE input[16], CK_BYTE output[16]) {
  CNK_ENSURE_NONNULL(key, input, output);

  psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  mbedtls_svc_key_id_t keyId = MBEDTLS_SVC_KEY_ID_INIT;
  size_t outputLen = 0;

  psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attributes, 192);
  psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
  psa_set_key_algorithm(&attributes, PSA_ALG_ECB_NO_PADDING);

  psa_status_t status = psa_import_key(&attributes, key, 24, &keyId);
  psa_reset_key_attributes(&attributes);
  if (status != PSA_SUCCESS) {
    CNK_ERROR("psa_import_key failed for AES-192 management authentication: %d", status);
    CNK_RETURN(CKR_FUNCTION_FAILED, "Failed to import AES-192 management key");
  }

  status = psa_cipher_encrypt(keyId, PSA_ALG_ECB_NO_PADDING, input, 16, output, 16, &outputLen);
  psa_status_t destroyStatus = psa_destroy_key(keyId);
  if (status != PSA_SUCCESS || destroyStatus != PSA_SUCCESS || outputLen != 16) {
    CNK_ERROR("AES-192 management authentication failed: cipher status %d, destroy status %d, output length %zu",
              status, destroyStatus, outputLen);
    CNK_RETURN(CKR_FUNCTION_FAILED, "Failed to encrypt AES-192 management challenge");
  }

  CNK_RET_OK;
}
