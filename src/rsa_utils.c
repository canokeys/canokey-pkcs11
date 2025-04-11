#include "rsa_utils.h"
#include "logging.h"      // For logging macros
#include "pcsc_backend.h" // For ck_malloc and ck_free
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

// Implements the EMSA-PSS encoding operation as defined in PKCS#1 v2.1
static CK_RV pss_encode(CK_BYTE_PTR mHash, CK_ULONG mHashLen, CK_ULONG modBits, CK_ULONG sLen,
                        mbedtls_md_type_t md_type, mbedtls_md_type_t mgf_md_type, mbedtls_ctr_drbg_context *ctr_drbg,
                        CK_BYTE_PTR output, CK_ULONG_PTR output_len) {
  CK_ULONG emLen = (modBits + 7) / 8; // Length in bytes of the modulus

  // Check if output buffer is large enough
  if (*output_len < emLen)
    return CKR_BUFFER_TOO_SMALL;

  // Check if the output length is at least emLen bytes
  if (emLen < mHashLen + sLen + 2)
    return CKR_MECHANISM_PARAM_INVALID;

  // Step 1: Generate a random salt of length sLen
  unsigned char *salt = (unsigned char *)ck_malloc(sLen);
  if (salt == NULL)
    return CKR_HOST_MEMORY;

  if (mbedtls_ctr_drbg_random(ctr_drbg, salt, sLen) != 0) {
    ck_free(salt);
    return CKR_FUNCTION_FAILED;
  }

  // Step 2: Construct the message M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
  const size_t k = 8; // Length of padding prefix
  unsigned char *M_prime = (unsigned char *)ck_malloc(k + mHashLen + sLen);
  if (M_prime == NULL) {
    ck_free(salt);
    return CKR_HOST_MEMORY;
  }

  // Pad with zeros
  memset(M_prime, 0, k);

  // Append the message hash
  memcpy(M_prime + k, mHash, mHashLen);

  // Append the salt
  memcpy(M_prime + k + mHashLen, salt, sLen);

  // Step 3: Compute H = Hash(M')
  unsigned char H[64]; // Large enough for any hash output
  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
  if (md_info == NULL) {
    ck_free(salt);
    ck_free(M_prime);
    return CKR_MECHANISM_INVALID;
  }

  if (mbedtls_md(md_info, M_prime, k + mHashLen + sLen, H) != 0) {
    ck_free(salt);
    ck_free(M_prime);
    return CKR_FUNCTION_FAILED;
  }

  size_t hLen = mbedtls_md_get_size(md_info);

  // Step 4: Generate the padding string PS
  CK_ULONG dbLen = emLen - hLen - 1; // Length of DB
  unsigned char *DB = (unsigned char *)ck_malloc(dbLen);
  if (DB == NULL) {
    ck_free(salt);
    ck_free(M_prime);
    return CKR_HOST_MEMORY;
  }

  // First byte is 0x01, rest is zero-padded, followed by 0x01 again, then the salt
  memset(DB, 0, dbLen - sLen - 1);
  DB[dbLen - sLen - 1] = 0x01;
  memcpy(DB + dbLen - sLen, salt, sLen);

  // Step 5: Apply MGF1 (Mask Generation Function)
  unsigned char *dbMask = (unsigned char *)ck_malloc(dbLen);
  if (dbMask == NULL) {
    ck_free(salt);
    ck_free(M_prime);
    ck_free(DB);
    return CKR_HOST_MEMORY;
  }

  // MGF1 calculation (simplified)
  const mbedtls_md_info_t *mgf_md_info = mbedtls_md_info_from_type(mgf_md_type);
  if (mgf_md_info == NULL) {
    ck_free(salt);
    ck_free(M_prime);
    ck_free(DB);
    ck_free(dbMask);
    return CKR_MECHANISM_INVALID;
  }

  // Simple MGF1 implementation
  unsigned char counter[4] = {0, 0, 0, 0};
  unsigned char mgf_hash[64]; // Large enough for any hash
  size_t mgf_hash_len = mbedtls_md_get_size(mgf_md_info);

  for (CK_ULONG i = 0; i < dbLen; i += mgf_hash_len) {
    // Increment counter
    counter[3]++;
    if (counter[3] == 0) {
      counter[2]++;
      if (counter[2] == 0) {
        counter[1]++;
        if (counter[1] == 0) {
          counter[0]++;
        }
      }
    }

    // Create temporary buffer for MGF input
    unsigned char *mgf_input = (unsigned char *)ck_malloc(hLen + 4);
    if (mgf_input == NULL) {
      ck_free(salt);
      ck_free(M_prime);
      ck_free(DB);
      ck_free(dbMask);
      return CKR_HOST_MEMORY;
    }

    // Copy H and counter
    memcpy(mgf_input, H, hLen);
    memcpy(mgf_input + hLen, counter, 4);

    // Compute hash
    if (mbedtls_md(mgf_md_info, mgf_input, hLen + 4, mgf_hash) != 0) {
      ck_free(salt);
      ck_free(M_prime);
      ck_free(DB);
      ck_free(dbMask);
      ck_free(mgf_input);
      return CKR_FUNCTION_FAILED;
    }

    // Copy output to dbMask
    CK_ULONG copy_len = (i + mgf_hash_len <= dbLen) ? mgf_hash_len : dbLen - i;
    memcpy(dbMask + i, mgf_hash, copy_len);

    ck_free(mgf_input);
  }

  // Step 6: XOR DB with dbMask to create maskedDB
  for (CK_ULONG i = 0; i < dbLen; i++) {
    DB[i] ^= dbMask[i];
  }

  // Step 7: Set the leftmost bits in maskedDB to zero
  CK_ULONG leftmostBits = 8 * emLen - modBits;
  if (leftmostBits > 0 && leftmostBits <= 8) {
    DB[0] &= 0xFF >> leftmostBits;
  }

  // Step 8: Construct the encoded message EM = maskedDB || H || 0xbc
  memcpy(output, DB, dbLen);
  memcpy(output + dbLen, H, hLen);
  output[emLen - 1] = 0xbc;

  *output_len = emLen;

  // Free allocated memory
  ck_free(salt);
  ck_free(M_prime);
  ck_free(DB);
  ck_free(dbMask);

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
    return CKR_MECHANISM_INVALID;
  }
  return CKR_OK;
}

// Helper function to prepare data for RSA signing based on mechanism
CK_RV cnk_prepare_rsa_sign_data(CK_MECHANISM_PTR mechanism_ptr, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                                CK_BYTE algorithm_type, CK_BYTE_PTR pPreparedData, CK_ULONG_PTR pulPreparedDataLen) {
  CNK_LOG_FUNC(cnk_prepare_rsa_sign_data, " algorithm_type: %d\n", algorithm_type);

  CK_RV rv = CKR_OK;
  mbedtls_md_type_t md_type;
  size_t hash_len = 0;
  CK_MECHANISM_TYPE mech_type = mechanism_ptr->mechanism;
  unsigned char hash[64] = {0}; // Large enough for any hash output
  CK_MECHANISM_TYPE hash_type = CKM_VENDOR_DEFINED;
  CK_BBOOL need_hashing = CK_FALSE;

  // For CKM_RSA_X_509, just pad with leading zeros
  if (mech_type == CKM_RSA_X_509) {
    if (!pPreparedData) {
      *pulPreparedDataLen = ulDataLen;
      return CKR_OK;
    }

    if (*pulPreparedDataLen < ulDataLen)
      return CKR_BUFFER_TOO_SMALL;

    // Zero out the buffer first if needed
    if (*pulPreparedDataLen > ulDataLen) {
      // Zero out the buffer first
      memset(pPreparedData, 0, *pulPreparedDataLen);
      // Copy data to the right side of the buffer (left-pad with zeros)
      memcpy(pPreparedData + (*pulPreparedDataLen - ulDataLen), pData, ulDataLen);
    } else {
      memcpy(pPreparedData, pData, ulDataLen);
    }

    *pulPreparedDataLen = ulDataLen;
    return CKR_OK;
  }

  // Determine if we need to hash the data
  if (is_sha_rsa_mechanism(mech_type)) {
    // For mechanisms like CKM_SHA1_RSA_PKCS, we need to hash the data
    hash_type = get_hash_from_mechanism(mech_type);
    if (hash_type == CKM_VENDOR_DEFINED)
      return CKR_MECHANISM_INVALID;

    need_hashing = CK_TRUE;
  } else if (mech_type == CKM_RSA_PKCS) {
    // For CKM_RSA_PKCS, we just apply padding to the raw data
    need_hashing = CK_FALSE;
  } else if (mech_type == CKM_RSA_PKCS_PSS) {
    // For CKM_RSA_PKCS_PSS, we need to hash using algorithm_type
    hash_type = algorithm_type;
    need_hashing = CK_TRUE;
  } else {
    return CKR_MECHANISM_INVALID;
  }

  // If we need to hash, do it now
  if (need_hashing) {
    rv = get_md_type_and_len(hash_type, &md_type, &hash_len);
    if (rv != CKR_OK)
      return rv;

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
    if (md_info == NULL)
      return CKR_MECHANISM_INVALID;

    if (mbedtls_md(md_info, pData, ulDataLen, hash) != 0)
      return CKR_FUNCTION_FAILED;
  }

  // Handle PKCS#1 v1.5 padding
  if (mech_type == CKM_RSA_PKCS || (is_sha_rsa_mechanism(mech_type) && mech_type != CKM_SHA1_RSA_PKCS_PSS &&
                                    mech_type != CKM_SHA256_RSA_PKCS_PSS && mech_type != CKM_SHA384_RSA_PKCS_PSS &&
                                    mech_type != CKM_SHA512_RSA_PKCS_PSS && mech_type != CKM_SHA224_RSA_PKCS_PSS &&
                                    mech_type != CKM_SHA3_256_RSA_PKCS_PSS && mech_type != CKM_SHA3_384_RSA_PKCS_PSS &&
                                    mech_type != CKM_SHA3_512_RSA_PKCS_PSS && mech_type != CKM_SHA3_224_RSA_PKCS_PSS)) {

    // Get modulus size from algorithm_type
    CK_ULONG modBits;
    CK_ULONG modBytes;
    switch (algorithm_type) {
    case PIV_ALG_RSA_2048:
      modBits = 2048;
      break;
    case PIV_ALG_RSA_3072:
      modBits = 3072;
      break;
    case PIV_ALG_RSA_4096:
      modBits = 4096;
      break;
    default:
      CNK_DEBUG("Unknown RSA key size, defaulting to 2048 bits\n");
      modBits = 2048;
      break;
    }
    modBytes = modBits / 8;
    CNK_DEBUG("Using modulus size: %lu bits (%lu bytes) for PKCS#1 v1.5 padding\n", modBits, modBytes);

    // Apply PKCS#1 v1.5 padding
    if (!pPreparedData) {
      // For size estimation
      *pulPreparedDataLen = modBytes;
      CNK_DEBUG("Buffer size estimation for PKCS#1 v1.5: %lu bytes\n", *pulPreparedDataLen);
      return CKR_OK;
    }

    // Make sure output buffer is modulus size
    if (*pulPreparedDataLen < modBytes) {
      CNK_ERROR("Output buffer too small: %lu bytes, need %lu bytes\n", *pulPreparedDataLen, modBytes);
      return CKR_BUFFER_TOO_SMALL;
    }
    *pulPreparedDataLen = modBytes;

    // Apply padding to hashed data or raw data
    if (need_hashing) {
      CNK_DEBUG("Applying PKCS#1 v1.5 padding to hashed data (%lu bytes)\n", hash_len);
      rv = pkcs1_v1_5_pad(hash, hash_len, pPreparedData, *pulPreparedDataLen, hash_type);
    } else {
      CNK_DEBUG("Applying PKCS#1 v1.5 padding to raw data (%lu bytes)\n", ulDataLen);
      rv = pkcs1_v1_5_pad(pData, ulDataLen, pPreparedData, *pulPreparedDataLen, mech_type);
    }
    
    if (rv != CKR_OK) {
      CNK_ERROR("PKCS#1 v1.5 padding failed: 0x%08lX\n", rv);
    } else {
      CNK_DEBUG("PKCS#1 v1.5 padding succeeded\n");
    }
    
    return rv;
  } else if (mech_type == CKM_RSA_PKCS_PSS || mech_type == CKM_SHA1_RSA_PKCS_PSS ||
             mech_type == CKM_SHA256_RSA_PKCS_PSS || mech_type == CKM_SHA384_RSA_PKCS_PSS ||
             mech_type == CKM_SHA512_RSA_PKCS_PSS || mech_type == CKM_SHA224_RSA_PKCS_PSS ||
             mech_type == CKM_SHA3_256_RSA_PKCS_PSS || mech_type == CKM_SHA3_384_RSA_PKCS_PSS ||
             mech_type == CKM_SHA3_512_RSA_PKCS_PSS || mech_type == CKM_SHA3_224_RSA_PKCS_PSS) {

    // PSS padding requires specific parameters
    CK_RSA_PKCS_PSS_PARAMS *pss_params = mechanism_ptr->pParameter;
    if (pss_params == NULL) {
      CNK_DEBUG("PSS parameters are missing\n");
      return CKR_MECHANISM_PARAM_INVALID;
    }

    // Get MGF hash algorithm
    mbedtls_md_type_t mgf_md_type;
    CK_MECHANISM_TYPE mgf_hash = CKM_VENDOR_DEFINED;

    // Check MGF type - typically only MGF1 is supported
    if (pss_params->mgf != 1) { // CKG_MGF1_SHA1, etc.
      CNK_DEBUG("Unsupported MGF type: %lu\n", pss_params->mgf);
      return CKR_MECHANISM_PARAM_INVALID;
    }

    // Get hash algorithm for MGF
    switch (pss_params->hashAlg) {
    case CKM_SHA_1:
      mgf_md_type = MBEDTLS_MD_SHA1;
      break;
    case CKM_SHA256:
      mgf_md_type = MBEDTLS_MD_SHA256;
      break;
    case CKM_SHA384:
      mgf_md_type = MBEDTLS_MD_SHA384;
      break;
    case CKM_SHA512:
      mgf_md_type = MBEDTLS_MD_SHA512;
      break;
    case CKM_SHA224:
      mgf_md_type = MBEDTLS_MD_SHA224;
      break;
    case CKM_SHA3_224:
      mgf_md_type = MBEDTLS_MD_SHA3_224;
      break;
    case CKM_SHA3_256:
      mgf_md_type = MBEDTLS_MD_SHA3_256;
      break;
    case CKM_SHA3_384:
      mgf_md_type = MBEDTLS_MD_SHA3_384;
      break;
    case CKM_SHA3_512:
      mgf_md_type = MBEDTLS_MD_SHA3_512;
      break;
    default:
      CNK_DEBUG("Unsupported hash algorithm for MGF: %lu\n", pss_params->hashAlg);
      return CKR_MECHANISM_PARAM_INVALID;
    }

    // For PSS padding, we need to properly encode the data using EMSA-PSS
    if (!pPreparedData) {
      // Estimate needed buffer size (modulus size in bytes)
      // For PSS, we need at least modulus length in bytes
      size_t data_len = need_hashing ? hash_len : ulDataLen;
      *pulPreparedDataLen = (*pulPreparedDataLen > data_len + pss_params->sLen + 2) ? *pulPreparedDataLen
                                                                                    : data_len + pss_params->sLen + 2;
      CNK_DEBUG("Buffer size estimation for PSS: %lu bytes\n", *pulPreparedDataLen);
      return CKR_OK;
    }

    // We need random data for the salt in PSS padding
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "rsa_pss_sign";
    int ret;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
      CNK_ERROR("Failed to seed RNG: -0x%04x\n", -ret);
      mbedtls_entropy_free(&entropy);
      mbedtls_ctr_drbg_free(&ctr_drbg);
      return CKR_FUNCTION_FAILED;
    }

    // Get modulus size from algorithm_type
    // In a real implementation, this should come from the actual RSA key
    CK_ULONG modBits;
    switch (algorithm_type) {
    case PIV_ALG_RSA_2048:
      modBits = 2048;
      break;
    case PIV_ALG_RSA_3072:
      modBits = 3072;
      break;
    case PIV_ALG_RSA_4096:
      modBits = 4096;
      break;
    default:
      CNK_DEBUG("Unknown RSA key size, defaulting to 2048 bits\n");
      modBits = 2048;
      break;
    }

    CNK_DEBUG("Using modulus size: %lu bits\n", modBits);
    CNK_DEBUG("Salt length: %lu bytes\n", pss_params->sLen);

    // For PSS, apply encoding to hashed data or raw data
    if (need_hashing) {
      CNK_DEBUG("Applying PSS encoding to hashed data (%lu bytes)\n", hash_len);
      rv = pss_encode(hash, hash_len, modBits, pss_params->sLen, md_type, mgf_md_type, &ctr_drbg, pPreparedData,
                      pulPreparedDataLen);
      if (rv != CKR_OK) {
        CNK_ERROR("PSS encoding failed: 0x%08lX\n", rv);
      } else {
        CNK_DEBUG("PSS encoding succeeded, output length: %lu bytes\n", *pulPreparedDataLen);
      }
    } else {
      // For raw data with PSS, hash it first with the same algorithm used for MGF
      CNK_DEBUG("Hashing raw data (%lu bytes) before PSS encoding\n", ulDataLen);
      unsigned char temp_hash[64]; // Big enough for any supported hash
      size_t temp_hash_len;

      const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(mgf_md_type);
      if (md_info == NULL) {
        CNK_ERROR("Failed to get MD info for type %d\n", mgf_md_type);
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        return CKR_FUNCTION_FAILED;
      }

      temp_hash_len = mbedtls_md_get_size(md_info);
      if (temp_hash_len > sizeof(temp_hash)) {
        CNK_ERROR("Hash size too large for buffer: %zu\n", temp_hash_len);
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        return CKR_FUNCTION_FAILED;
      }

      ret = mbedtls_md(md_info, pData, ulDataLen, temp_hash);
      if (ret != 0) {
        CNK_ERROR("Hash operation failed: -0x%04x\n", -ret);
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        return CKR_FUNCTION_FAILED;
      }

      CNK_DEBUG("Data hashed, hash length: %zu bytes\n", temp_hash_len);
      rv = pss_encode(temp_hash, temp_hash_len, modBits, pss_params->sLen, mgf_md_type, mgf_md_type, &ctr_drbg,
                      pPreparedData, pulPreparedDataLen);
      if (rv != CKR_OK) {
        CNK_ERROR("PSS encoding failed: 0x%08lX\n", rv);
      } else {
        CNK_DEBUG("PSS encoding succeeded, output length: %lu bytes\n", *pulPreparedDataLen);
      }
    }

    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    return rv;
  }

  CNK_DEBUG("Unsupported mechanism: 0x%08lX\n", mech_type);
  return CKR_MECHANISM_INVALID;
}