#include "rsa_utils.h"
#include "logging.h" // For logging macros
#include "mbedtls/bignum.h"
#include "pcsc_backend.h" // For ck_malloc and ck_free
#include "pkcs11.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <string.h>

// PKCS#1 v1.5 padding for signature
static CK_RV pkcs1_v1_5_pad(CK_BYTE_PTR input, CK_ULONG input_len, CK_BYTE_PTR output, CK_ULONG output_len,
                            CK_MECHANISM_TYPE digest_mech) {
  // Check if output buffer is large enough
  if (output_len < input_len + 11)
    return CKR_BUFFER_TOO_SMALL;

  // PKCS#1 v1.5 padding structure:
  // 0x00 | 0x01 | PS | 0x00 | T
  // where PS is a string of 0xFF bytes and T is the data
  // The minimum length of PS is 8 bytes

  // DER encoding for hash algorithms
  static const unsigned char md_sha1_der[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
                                              0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
  static const unsigned char md_sha256_der[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                                0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
  static const unsigned char md_sha384_der[] = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                                0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
  static const unsigned char md_sha512_der[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                                0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};

  const unsigned char *der = NULL;
  size_t der_len = 0;

  // Select DER encoding based on digest algorithm
  // Only apply DER prefix for hash algorithms
  if (digest_mech != CKM_RSA_PKCS) {
    switch (digest_mech) {
    case CKM_SHA_1:
    case CKM_SHA1_RSA_PKCS:
      der = md_sha1_der;
      der_len = sizeof(md_sha1_der);
      break;
    case CKM_SHA256:
    case CKM_SHA256_RSA_PKCS:
      der = md_sha256_der;
      der_len = sizeof(md_sha256_der);
      break;
    case CKM_SHA384:
    case CKM_SHA384_RSA_PKCS:
      der = md_sha384_der;
      der_len = sizeof(md_sha384_der);
      break;
    case CKM_SHA512:
    case CKM_SHA512_RSA_PKCS:
      der = md_sha512_der;
      der_len = sizeof(md_sha512_der);
      break;
    default:
      // For unknown digest, use raw data with no DER prefix
      der = NULL;
      der_len = 0;
      break;
    }
  }

  // Calculate total data length with DER encoding
  size_t tlen = der_len + input_len;

  // Check if output is large enough for padded data
  if (output_len < tlen + 11)
    return CKR_BUFFER_TOO_SMALL;

  // Calculate padding length
  size_t pad_len = output_len - tlen - 3;

  // First byte must be 0
  *output++ = 0;
  // Block type for signature is 0x01
  *output++ = 0x01;

  // Fill padding with 0xFF
  memset(output, 0xFF, pad_len);
  output += pad_len;

  // Add separator 0x00
  *output++ = 0x00;

  // Add DER encoding if present
  if (der_len > 0) {
    memcpy(output, der, der_len);
    output += der_len;
  }

  // Finally add the input data
  memcpy(output, input, input_len);

  return CKR_OK;
}

/**
 * pss_encode - Implements EMSA-PSS encoding as defined in PKCS#1 v2.1.
 *
 * This function always hashes the input data (it does not support pre‐hashed inputs).
 * It assumes that the message digest algorithm used for both hashing and the mask generation
 * function is the same (i.e. md_type == mgf_md_type).
 *
 * The encoding is performed as follows:
 *   1. Compute mHash = Hash(mInput). Done outside this function.
 *   2. Generate a random salt of length sLen.
 *   3. Construct M' = 0x00 00 00 00 00 00 00 00 || mHash || salt.
 *   4. Compute H = Hash(M').
 *   5. Construct DB = PS || 0x01 || salt, where PS is a string of zero bytes
 *      of length (emLen - expectedHashLen - sLen - 1) and emLen = (modBits+7)/8.
 *   6. Generate a mask dbMask = MGF1(H, dbLen) using md_type.
 *   7. Compute maskedDB = DB XOR dbMask and clear leftmost bits to ensure that
 *      the encoded value is less than the modulus.
 *   8. Output EM = maskedDB || H || 0xbc.
 *
 * @param mHash        Pointer to the digest of the raw message.
 * @param mHashLen     Length of the message digest.
 * @param pModulus     RSA modulus.
 * @param ulModulusLen Length of the modulus.
 * @param sLen         Length of the salt in bytes.
 * @param mdType       Message digest type (for both hashing and MGF1).
 * @param ctrDrbg      Pointer to an initialized CTR_DRBG context.
 * @param out          Pointer to the buffer that will receive the encoded message (EM).
 * @param outLen       On input, the size of the output buffer; on output, the size of EM.
 *
 * @return            CKR_OK on success; otherwise an error code.
 */
static CK_RV pss_encode(CK_BYTE_PTR mHash, CK_ULONG mHashLen, CK_BYTE_PTR pModulus, CK_ULONG ulModulusLen,
                        CK_ULONG sLen, mbedtls_md_type_t mdType, mbedtls_ctr_drbg_context *ctrDrbg, CK_BYTE_PTR out,
                        CK_ULONG *outLen) {
  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(mdType);
  if (md_info == NULL)
    return CKR_MECHANISM_PARAM_INVALID;

  const size_t hLen = mbedtls_md_get_size(md_info);
  if (mHashLen != hLen)
    return CKR_DATA_LEN_RANGE;
  if (sLen > hLen)
    return CKR_MECHANISM_PARAM_INVALID; /* FIPS 186‑4 */

  /* emBits = modBits - 1  ——  RFC 8017 §9.1.1 */
  mbedtls_mpi modulus_mpi;
  mbedtls_mpi_init(&modulus_mpi);
  mbedtls_mpi_read_binary(&modulus_mpi, pModulus, ulModulusLen);
  const CK_ULONG modBits = mbedtls_mpi_bitlen(&modulus_mpi);
  const CK_ULONG emBits = modBits - 1;
  const CK_ULONG emLen = (emBits + 7) / 8;

  if (*outLen < emLen)
    return CKR_BUFFER_TOO_SMALL;
  if (emLen < hLen + sLen + 2)
    return CKR_MECHANISM_PARAM_INVALID;

  /* -------- Generate salt -------- */
  unsigned char *salt = ck_malloc(sLen);
  if (!salt)
    return CKR_HOST_MEMORY;
  if (mbedtls_ctr_drbg_random(ctrDrbg, salt, sLen) != 0) {
    ck_free(salt);
    return CKR_FUNCTION_FAILED;
  }

  /* -------- H = Hash( 0x00×8 || mHash || salt ) -------- */
  unsigned char M_prime[8 + 64 + 64]; /* 最大 8+64+64 = 136B */
  memset(M_prime, 0, 8);
  memcpy(M_prime + 8, mHash, hLen);
  memcpy(M_prime + 8 + hLen, salt, sLen);

  unsigned char H[64]; /* hLen ≤ 64 */
  if (mbedtls_md(md_info, M_prime, 8 + hLen + sLen, H) != 0) {
    ck_free(salt);
    return CKR_FUNCTION_FAILED;
  }

  /* -------- DB = PS || 0x01 || salt -------- */
  const CK_ULONG dbLen = emLen - hLen - 1;
  const CK_ULONG psLen = dbLen - sLen - 1;

  unsigned char *DB = ck_malloc(dbLen);
  if (!DB) {
    ck_free(salt);
    return CKR_HOST_MEMORY;
  }
  memset(DB, 0, psLen);
  DB[psLen] = 0x01;
  memcpy(DB + psLen + 1, salt, sLen);
  ck_free(salt);

  /* -------- dbMask = MGF1(H, dbLen) -------- */
  unsigned char *dbMask = ck_malloc(dbLen);
  if (!dbMask) {
    ck_free(DB);
    return CKR_HOST_MEMORY;
  }

  const CK_ULONG reps = (dbLen + hLen - 1) / hLen;
  for (CK_ULONG c = 0; c < reps; c++) {
    unsigned char C[4] = {(unsigned char)(c >> 24), (unsigned char)(c >> 16), (unsigned char)(c >> 8),
                          (unsigned char)(c)};
    unsigned char buf[64 + 4]; /* H || C */
    memcpy(buf, H, hLen);
    memcpy(buf + hLen, C, 4);

    unsigned char hash[64];
    mbedtls_md(md_info, buf, hLen + 4, hash);

    const CK_ULONG off = c * hLen;
    const CK_ULONG clen = (off + hLen <= dbLen) ? hLen : dbLen - off;
    memcpy(dbMask + off, hash, clen);
  }

  /* maskedDB = DB ⊕ dbMask */
  for (CK_ULONG i = 0; i < dbLen; i++)
    DB[i] ^= dbMask[i];
  ck_free(dbMask);

  /* Clear the leftmost (8*emLen - emBits) bits */
  const unsigned leftBits = 8 * emLen - emBits;
  DB[0] &= 0xFFu >> leftBits;

  /* -------- EM = maskedDB || H || 0xBC -------- */
  memcpy(out, DB, dbLen);
  memcpy(out + dbLen, H, hLen);
  out[emLen - 1] = 0xBC;
  *outLen = emLen;

  mbedtls_platform_zeroize(DB, dbLen);
  ck_free(DB);
  return CKR_OK;
}

// Helper function to determine if a mechanism is a combined SHAxxx_RSA mechanism
static CK_BBOOL is_sha_rsa_mechanism(CK_MECHANISM_TYPE mech_type) {
  switch (mech_type) {
  case CKM_SHA1_RSA_PKCS:
  case CKM_SHA256_RSA_PKCS:
  case CKM_SHA384_RSA_PKCS:
  case CKM_SHA512_RSA_PKCS:
  case CKM_SHA224_RSA_PKCS:
  case CKM_SHA3_256_RSA_PKCS:
  case CKM_SHA3_384_RSA_PKCS:
  case CKM_SHA3_512_RSA_PKCS:
  case CKM_SHA3_224_RSA_PKCS:
  case CKM_SHA1_RSA_PKCS_PSS:
  case CKM_SHA256_RSA_PKCS_PSS:
  case CKM_SHA384_RSA_PKCS_PSS:
  case CKM_SHA512_RSA_PKCS_PSS:
  case CKM_SHA224_RSA_PKCS_PSS:
  case CKM_SHA3_256_RSA_PKCS_PSS:
  case CKM_SHA3_384_RSA_PKCS_PSS:
  case CKM_SHA3_512_RSA_PKCS_PSS:
  case CKM_SHA3_224_RSA_PKCS_PSS:
    return CK_TRUE;
  default:
    return CK_FALSE;
  }
}

// Get the hash algorithm type from a combined mechanism
static CK_MECHANISM_TYPE get_hash_from_mechanism(CK_MECHANISM_TYPE mech_type) {
  switch (mech_type) {
  case CKM_SHA1_RSA_PKCS:
  case CKM_SHA1_RSA_PKCS_PSS:
    return CKM_SHA_1;
  case CKM_SHA256_RSA_PKCS:
  case CKM_SHA256_RSA_PKCS_PSS:
    return CKM_SHA256;
  case CKM_SHA384_RSA_PKCS:
  case CKM_SHA384_RSA_PKCS_PSS:
    return CKM_SHA384;
  case CKM_SHA512_RSA_PKCS:
  case CKM_SHA512_RSA_PKCS_PSS:
    return CKM_SHA512;
  case CKM_SHA224_RSA_PKCS:
  case CKM_SHA224_RSA_PKCS_PSS:
    return CKM_SHA224;
  // Add SHA3 variants if needed
  default:
    return CKM_VENDOR_DEFINED; // Invalid
  }
}

// Helper function to get mbedtls hash type and length
static CK_RV get_md_type_and_len(CK_MECHANISM_TYPE hash_type, mbedtls_md_type_t *md_type, size_t *hash_len) {
  switch (hash_type) {
  case CKM_SHA_1:
    *md_type = MBEDTLS_MD_SHA1;
    *hash_len = 20;
    break;
  case CKM_SHA256:
    *md_type = MBEDTLS_MD_SHA256;
    *hash_len = 32;
    break;
  case CKM_SHA384:
    *md_type = MBEDTLS_MD_SHA384;
    *hash_len = 48;
    break;
  case CKM_SHA512:
    *md_type = MBEDTLS_MD_SHA512;
    *hash_len = 64;
    break;
  case CKM_SHA224:
    *md_type = MBEDTLS_MD_SHA224;
    *hash_len = 28;
    break;
  default:
    CNK_DEBUG("Unsupported hashAlg: %lu", hash_type);
    return CKR_MECHANISM_PARAM_INVALID;
  }
  return CKR_OK;
}

// Helper function to get mbedtls hash type from MGF
static CK_RV get_md_type_from_mgf(CK_RSA_PKCS_MGF_TYPE mgf_hash, mbedtls_md_type_t *md_type) {
  switch (mgf_hash) {
  case CKG_MGF1_SHA1:
    *md_type = MBEDTLS_MD_SHA1;
    break;
  case CKG_MGF1_SHA224:
    *md_type = MBEDTLS_MD_SHA224;
    break;
  case CKG_MGF1_SHA256:
    *md_type = MBEDTLS_MD_SHA256;
    break;
  case CKG_MGF1_SHA384:
    *md_type = MBEDTLS_MD_SHA384;
    break;
  case CKG_MGF1_SHA512:
    *md_type = MBEDTLS_MD_SHA512;
    break;
  case CKG_MGF1_SHA3_224:
    *md_type = MBEDTLS_MD_SHA3_224;
    break;
  case CKG_MGF1_SHA3_256:
    *md_type = MBEDTLS_MD_SHA3_256;
    break;
  case CKG_MGF1_SHA3_384:
    *md_type = MBEDTLS_MD_SHA3_384;
    break;
  case CKG_MGF1_SHA3_512:
    *md_type = MBEDTLS_MD_SHA3_512;
    break;
  default:
    CNK_DEBUG("Unsupported MGF type: %lu", mgf_hash);
    return CKR_MECHANISM_PARAM_INVALID;
  }
  return CKR_OK;
}

// Helper function to prepare data for RSA signing based on mechanism
CK_RV cnk_prepare_rsa_sign_data(CK_MECHANISM_PTR pMechanism, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                                CK_BYTE_PTR pModulus, CK_ULONG ulModulusLen, CK_BYTE bAlgorithmType,
                                CK_BYTE_PTR pPreparedData, CK_ULONG_PTR pulPreparedDataLen) {

#define HANDLE_FIRST_CALL()                                                                                            \
  if (!pPreparedData) {                                                                                                \
    *pulPreparedDataLen = ulModulusBytes;                                                                              \
    CNK_RET_OK;                                                                                                        \
  }                                                                                                                    \
  if (*pulPreparedDataLen < ulModulusBytes)                                                                            \
    CNK_RETURN(CKR_BUFFER_TOO_SMALL, "Buffer too small");                                                              \
  *pulPreparedDataLen = ulModulusBytes;

  CNK_LOG_FUNC(cnk_prepare_rsa_sign_data, " algorithm_type: %d", bAlgorithmType);

  CK_RV rv = CKR_OK;
  mbedtls_md_type_t md_type;
  size_t hash_len = 0;
  CK_MECHANISM_TYPE mech_type = pMechanism->mechanism;
  unsigned char hash[64] = {0}; // Large enough for any hash output
  CK_MECHANISM_TYPE hash_type = CKM_VENDOR_DEFINED;
  CK_BBOOL need_hashing = CK_FALSE;

  // Get modulus size from algorithm_type
  CK_ULONG ulModulusBytes;
  switch (bAlgorithmType) {
  case PIV_ALG_RSA_2048:
    ulModulusBytes = 2048 / 8;
    break;
  case PIV_ALG_RSA_3072:
    ulModulusBytes = 3072 / 8;
    break;
  case PIV_ALG_RSA_4096:
    ulModulusBytes = 4096 / 8;
    break;
  default:
    CNK_ERROR("Unknown RSA key size");
    CNK_RETURN(CKR_ARGUMENTS_BAD, "Unknown RSA key size");
  }
  CNK_DEBUG("Using modulus size: %lu bits", ulModulusBytes * 8);

  // For CKM_RSA_X_509, compute output length based on key size and pad with leading zeros
  if (mech_type == CKM_RSA_X_509) {
    HANDLE_FIRST_CALL();

    // Zero out the buffer first
    memset(pPreparedData, 0, ulModulusBytes);

    // Copy data to the right side of the buffer (left-pad with zeros)
    if (ulDataLen <= ulModulusBytes) {
      memcpy(pPreparedData + (ulModulusBytes - ulDataLen), pData, ulDataLen);
    } else {
      // Data is larger than modulus - only use rightmost bytes
      memcpy(pPreparedData, pData + (ulDataLen - ulModulusBytes), ulModulusBytes);
    }

    CNK_RET_OK;
  }

  // Determine if we need to hash the data
  if (is_sha_rsa_mechanism(mech_type)) {
    // For mechanisms like CKM_SHA1_RSA_PKCS, we need to hash the data
    hash_type = get_hash_from_mechanism(mech_type);
    if (hash_type == CKM_VENDOR_DEFINED)
      CNK_RETURN(CKR_MECHANISM_INVALID, "Invalid mechanism, cannot determine hash type");

    need_hashing = CK_TRUE;
  } else if (mech_type == CKM_RSA_PKCS || mech_type == CKM_RSA_PKCS_PSS) {
    need_hashing = CK_FALSE;
  } else {
    CNK_RETURN(CKR_MECHANISM_INVALID, "Invalid mechanism");
  }

  // If we need to hash, do it now
  if (need_hashing) {
    rv = get_md_type_and_len(hash_type, &md_type, &hash_len);
    if (rv != CKR_OK)
      CNK_RETURN(rv, "Failed to get MD type and length");

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
    if (md_info == NULL)
      CNK_RETURN(CKR_MECHANISM_INVALID, "Invalid hash type");

    if (mbedtls_md(md_info, pData, ulDataLen, hash) != 0)
      CNK_RETURN(CKR_FUNCTION_FAILED, "Failed to hash data");
  }

  // Handle PKCS#1 v1.5 padding
  if (mech_type == CKM_RSA_PKCS || mech_type == CKM_SHA1_RSA_PKCS || mech_type == CKM_SHA256_RSA_PKCS ||
      mech_type == CKM_SHA384_RSA_PKCS || mech_type == CKM_SHA512_RSA_PKCS || mech_type == CKM_SHA224_RSA_PKCS ||
      mech_type == CKM_SHA3_256_RSA_PKCS || mech_type == CKM_SHA3_384_RSA_PKCS || mech_type == CKM_SHA3_512_RSA_PKCS ||
      mech_type == CKM_SHA3_224_RSA_PKCS) {

    HANDLE_FIRST_CALL();

    // Apply padding to hashed data or raw data
    if (need_hashing) {
      CNK_DEBUG("Applying PKCS#1 v1.5 padding to hashed data (%lu bytes)", hash_len);
      rv = pkcs1_v1_5_pad(hash, hash_len, pPreparedData, *pulPreparedDataLen, hash_type);
    } else {
      CNK_DEBUG("Applying PKCS#1 v1.5 padding to raw data (%lu bytes)", ulDataLen);
      rv = pkcs1_v1_5_pad(pData, ulDataLen, pPreparedData, *pulPreparedDataLen, mech_type);
    }

    return CNK_ENSURE_OK(rv);
  }

  // Handle PSS padding
  if (mech_type == CKM_RSA_PKCS_PSS || mech_type == CKM_SHA1_RSA_PKCS_PSS || mech_type == CKM_SHA256_RSA_PKCS_PSS ||
      mech_type == CKM_SHA384_RSA_PKCS_PSS || mech_type == CKM_SHA512_RSA_PKCS_PSS ||
      mech_type == CKM_SHA224_RSA_PKCS_PSS || mech_type == CKM_SHA3_256_RSA_PKCS_PSS ||
      mech_type == CKM_SHA3_384_RSA_PKCS_PSS || mech_type == CKM_SHA3_512_RSA_PKCS_PSS ||
      mech_type == CKM_SHA3_224_RSA_PKCS_PSS) {

    CNK_ENSURE_NONNULL(pModulus);

    // PSS padding requires specific parameters
    CK_RSA_PKCS_PSS_PARAMS *pss_params = pMechanism->pParameter;
    CNK_ENSURE_NONNULL(pss_params);

    mbedtls_md_type_t pss_hash_type;
    // Get the hash algorithm from the parameters
    CNK_ENSURE_OK(get_md_type_and_len(pss_params->hashAlg, &pss_hash_type, &hash_len));
    if (need_hashing) {
      CNK_ENSURE_EQUAL_REASON(md_type, pss_hash_type, "MD type does not match hash type");
    } else {
      CNK_ENSURE_EQUAL_REASON(hash_len, ulDataLen, "Hash length does not match data length");
    }

    // Get MGF hash algorithm
    CNK_ENSURE_OK(get_md_type_from_mgf(pss_params->mgf, &pss_hash_type));
    if (need_hashing)
      CNK_ENSURE_EQUAL_REASON(md_type, pss_hash_type, "MD type does not match MGF hash type");

    HANDLE_FIRST_CALL();

    // We need random data for the salt in PSS padding
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const char *pers = "rsa_pss_sign";
    int ret =
        mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
      CNK_ERROR("Failed to seed RNG: -0x%04x", -ret);
      mbedtls_entropy_free(&entropy);
      mbedtls_ctr_drbg_free(&ctr_drbg);
      return CKR_FUNCTION_FAILED;
    }

    CNK_DEBUG("Salt length: %lu bytes", pss_params->sLen);

    // For PSS, apply encoding to hashed data or raw data
    if (need_hashing) {
      // For SHAxxx_RSA_PKCS_PSS mechanisms, we've already hashed the data
      CNK_DEBUG("Applying PSS encoding to hashed data (%lu bytes)", hash_len);
      rv = pss_encode(hash, hash_len, pModulus, ulModulusLen, pss_params->sLen, md_type, &ctr_drbg, pPreparedData,
                      pulPreparedDataLen);
    } else if (mech_type == CKM_RSA_PKCS_PSS) {
      // For CKM_RSA_PKCS_PSS, the input data is already a hash value
      CNK_DEBUG("Applying PSS encoding to input hash value (%lu bytes)", ulDataLen);

      rv = pss_encode(pData, ulDataLen, pModulus, ulModulusLen, pss_params->sLen, pss_hash_type, &ctr_drbg,
                      pPreparedData, pulPreparedDataLen);
    } else {
      // This case should not be reached with the current logic
      CNK_ERROR("Unexpected code path in PSS encoding");
      mbedtls_entropy_free(&entropy);
      mbedtls_ctr_drbg_free(&ctr_drbg);
      return CKR_FUNCTION_FAILED;
    }

    if (rv != CKR_OK) {
      CNK_ERROR("PSS encoding failed: 0x%08lX", rv);
    } else {
      CNK_DEBUG("PSS encoding succeeded, output length: %lu bytes", *pulPreparedDataLen);
    }

    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    return rv;
  }

  CNK_DEBUG("Unsupported mechanism: 0x%08lX", mech_type);
  return CKR_MECHANISM_INVALID;
}
