#include "internal/rsa.h"
#include "backend/pcsc.h"     // For ck_malloc and ck_free
#include "internal/logging.h" // For logging macros
#include "internal/util.h"
#include "pkcs11.h"

#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/private/bignum.h>
#include <mbedtls/private/ctr_drbg.h>
#include <mbedtls/private/entropy.h>
#include <mbedtls/private/rsa.h>
#include <psa/crypto.h>
#include <string.h>

CK_RV cnk_rsa_public(const CK_BYTE *modulus, CK_ULONG modulusLen, const CK_BYTE *exponent, CK_ULONG exponentLen,
                     const CK_BYTE *input, CK_ULONG inputLen, CK_BYTE *output) {
  // This is the common host primitive for RSA Encrypt and Verify. Inputs and
  // outputs are fixed-width big-endian encoded messages.
  CNK_ENSURE_NONNULL(modulus, exponent, input, output);
  if (inputLen != modulusLen)
    return CKR_DATA_LEN_RANGE;

  mbedtls_rsa_context rsa;
  mbedtls_rsa_init(&rsa);
  CK_RV rv = CKR_FUNCTION_FAILED;
  if (mbedtls_mpi_read_binary(&rsa.MBEDTLS_PRIVATE(N), modulus, modulusLen) != 0 ||
      mbedtls_mpi_read_binary(&rsa.MBEDTLS_PRIVATE(E), exponent, exponentLen) != 0) {
    rv = CKR_KEY_HANDLE_INVALID;
    goto cleanup;
  }
  rsa.MBEDTLS_PRIVATE(len) = mbedtls_mpi_size(&rsa.MBEDTLS_PRIVATE(N));
  if (rsa.MBEDTLS_PRIVATE(len) != modulusLen || mbedtls_rsa_check_pubkey(&rsa) != 0) {
    rv = CKR_KEY_HANDLE_INVALID;
    goto cleanup;
  }
  rv = mbedtls_rsa_public(&rsa, input, output) == 0 ? CKR_OK : CKR_DATA_INVALID;

cleanup:
  mbedtls_rsa_free(&rsa);
  return rv;
}

// PKCS#1 v1.5 padding for signature
CK_RV pkcs1_v1_5_pad(CK_BYTE_PTR pbInput, CK_ULONG cbInput, CK_BYTE_PTR pbOutput, CK_ULONG cbOutput,
                     mbedtls_md_type_t mdType) {
  // Check if output buffer is large enough
  if (cbOutput < cbInput + 11)
    return CKR_BUFFER_TOO_SMALL;

  // PKCS#1 v1.5 padding structure:
  // 0x00 | 0x01 | PS | 0x00 | T
  // where PS is a string of 0xFF bytes and T is the data
  // The minimum length of PS is 8 bytes

  // DER encoding for hash algorithms
  static const CK_BYTE md_sha1_der[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
                                        0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
  static const CK_BYTE md_sha224_der[] = {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                          0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c};
  static const CK_BYTE md_sha256_der[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                          0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
  static const CK_BYTE md_sha384_der[] = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                          0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
  static const CK_BYTE md_sha512_der[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                          0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};
  static const CK_BYTE md_sha3_224_der[] = {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                            0x65, 0x03, 0x04, 0x02, 0x07, 0x05, 0x00, 0x04, 0x1c};
  static const CK_BYTE md_sha3_256_der[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                            0x65, 0x03, 0x04, 0x02, 0x08, 0x05, 0x00, 0x04, 0x20};
  static const CK_BYTE md_sha3_384_der[] = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                            0x65, 0x03, 0x04, 0x02, 0x09, 0x05, 0x00, 0x04, 0x30};
  static const CK_BYTE md_sha3_512_der[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                            0x65, 0x03, 0x04, 0x02, 0x0a, 0x05, 0x00, 0x04, 0x40};

  const CK_BYTE *der = NULL;
  CK_ULONG cbDer = 0;

  // Select DER encoding based on digest algorithm
  // Only apply DER prefix for hash algorithms
  if (mdType != MBEDTLS_MD_NONE) {
    switch (mdType) {
    case MBEDTLS_MD_SHA1:
      der = md_sha1_der;
      cbDer = sizeof(md_sha1_der);
      break;
    case MBEDTLS_MD_SHA224:
      der = md_sha224_der;
      cbDer = sizeof(md_sha224_der);
      break;
    case MBEDTLS_MD_SHA256:
      der = md_sha256_der;
      cbDer = sizeof(md_sha256_der);
      break;
    case MBEDTLS_MD_SHA384:
      der = md_sha384_der;
      cbDer = sizeof(md_sha384_der);
      break;
    case MBEDTLS_MD_SHA512:
      der = md_sha512_der;
      cbDer = sizeof(md_sha512_der);
      break;
    case MBEDTLS_MD_SHA3_224:
      der = md_sha3_224_der;
      cbDer = sizeof(md_sha3_224_der);
      break;
    case MBEDTLS_MD_SHA3_256:
      der = md_sha3_256_der;
      cbDer = sizeof(md_sha3_256_der);
      break;
    case MBEDTLS_MD_SHA3_384:
      der = md_sha3_384_der;
      cbDer = sizeof(md_sha3_384_der);
      break;
    case MBEDTLS_MD_SHA3_512:
      der = md_sha3_512_der;
      cbDer = sizeof(md_sha3_512_der);
      break;
    default:
      // For unknown digest, use raw data with no DER prefix
      der = NULL;
      cbDer = 0;
      break;
    }
  }

  // Calculate total data length with DER encoding
  CK_ULONG tlen = cbDer + cbInput;

  // Check if output is large enough for padded data
  if (cbOutput < tlen + 11)
    return CKR_BUFFER_TOO_SMALL;

  // Calculate padding length
  CK_ULONG cbPad = cbOutput - tlen - 3;

  // First byte must be 0
  *pbOutput++ = 0;
  // Block type for signature is 0x01
  *pbOutput++ = 0x01;

  // Fill padding with 0xFF
  memset(pbOutput, 0xFF, cbPad);
  pbOutput += cbPad;

  // Add separator 0x00
  *pbOutput++ = 0x00;

  // Add DER encoding if present
  if (cbDer > 0) {
    memcpy(pbOutput, der, cbDer);
    pbOutput += cbDer;
  }

  // Finally add the input data
  memcpy(pbOutput, pbInput, cbInput);

  return CKR_OK;
}

/**
 * pss_encode - Implements EMSA-PSS encoding as defined in PKCS#1 v2.1.
 *
 * This function expects the caller to pass a message digest.
 * It assumes that the message digest algorithm used for both hashing and the mask generation
 * function is the same (i.e. md_type == mgf_md_type).
 *
 * The encoding is performed as follows:
 *   1. Receive mHash, the message digest computed by the caller.
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
 * @param pbHash     Pointer to the digest of the raw message.
 * @param cbHash     Length of the message digest.
 * @param pbModulus  RSA modulus.
 * @param cbModulus  Length of the modulus.
 * @param cbSalt     Length of the salt in bytes.
 * @param mdType     Message digest type (for both hashing and MGF1).
 * @param pbOutput   Pointer to the buffer that will receive the encoded message (EM).
 *
 * @return           CKR_OK on success; otherwise an error code.
 */
CK_RV pss_encode(CK_BYTE_PTR pbHash, CK_ULONG cbHash, CK_BYTE_PTR pbModulus, CK_ULONG cbModulus, CK_ULONG cbSalt,
                 mbedtls_md_type_t mdType, CK_BYTE_PTR pbOutput) {
  const mbedtls_md_info_t *pMdInfo = mbedtls_md_info_from_type(mdType);
  CNK_ENSURE_NONNULL(pMdInfo);

  const size_t hLen = mbedtls_md_get_size(pMdInfo);
  if (cbHash != hLen)
    return CKR_DATA_LEN_RANGE;

  CK_RV rv = CKR_OK;
  CK_BYTE_PTR pSalt = NULL_PTR;
  CK_BYTE_PTR pMPrime = NULL_PTR;
  CK_BYTE_PTR pDB = NULL_PTR;
  CK_BYTE_PTR pDBMask = NULL_PTR;
  mbedtls_mpi modulus_mpi;

  mbedtls_entropy_context entropyCtx;
  mbedtls_ctr_drbg_context ctrDrbgCtx;
  mbedtls_entropy_init(&entropyCtx);
  mbedtls_ctr_drbg_init(&ctrDrbgCtx);

  /* emBits = modBits - 1 per RFC 8017 section 9.1.1. */
  mbedtls_mpi_init(&modulus_mpi);
  mbedtls_mpi_read_binary(&modulus_mpi, pbModulus, cbModulus);
  const CK_ULONG modBits = mbedtls_mpi_bitlen(&modulus_mpi);
  const CK_ULONG emBits = modBits - 1;
  const CK_ULONG emLen = (emBits + 7) / 8;

  if (emLen < hLen + cbSalt + 2) {
    CNK_ERROR("Output buffer too small");
    rv = CKR_MECHANISM_PARAM_INVALID;
    goto cleanup;
  }

  /* -------- Generate salt -------- */
  const char *pers = "rsa_pss_sign";
  int ret =
      mbedtls_ctr_drbg_seed(&ctrDrbgCtx, mbedtls_entropy_func, &entropyCtx, (const unsigned char *)pers, strlen(pers));
  if (ret != 0) {
    CNK_ERROR("Failed to seed RNG: -0x%04x", -ret);
    rv = CKR_FUNCTION_FAILED;
    goto cleanup;
  }

  if (cbSalt > 0) {
    pSalt = ck_malloc(cbSalt);
    if (!pSalt) {
      CNK_ERROR("Failed to allocate salt buffer");
      rv = CKR_HOST_MEMORY;
      goto cleanup;
    }
    if (mbedtls_ctr_drbg_random(&ctrDrbgCtx, pSalt, cbSalt) != 0) {
      CNK_ERROR("Failed to generate salt");
      rv = CKR_FUNCTION_FAILED;
      goto cleanup;
    }
  }

  /* -------- H = Hash( eight zero bytes || mHash || salt ) -------- */
  CK_ULONG mPrimeLen = 8 + hLen + cbSalt;
  pMPrime = ck_malloc(mPrimeLen);
  if (pMPrime == NULL) {
    rv = CKR_HOST_MEMORY;
    goto cleanup;
  }
  memset(pMPrime, 0, 8);
  memcpy(pMPrime + 8, pbHash, hLen);
  if (cbSalt > 0)
    memcpy(pMPrime + 8 + hLen, pSalt, cbSalt);

  CK_BYTE H[64]; /* hLen <= 64 */
  if (mbedtls_md(pMdInfo, pMPrime, mPrimeLen, H) != 0) {
    CNK_ERROR("Failed to generate hash");
    rv = CKR_FUNCTION_FAILED;
    goto cleanup;
  }

  /* -------- DB = PS || 0x01 || salt -------- */
  const CK_ULONG dbLen = emLen - hLen - 1;
  const CK_ULONG psLen = dbLen - cbSalt - 1;

  pDB = ck_malloc(dbLen);
  if (!pDB) {
    CNK_ERROR("Failed to allocate DB buffer");
    rv = CKR_HOST_MEMORY;
    goto cleanup;
  }
  memset(pDB, 0, psLen);
  pDB[psLen] = 0x01;
  if (cbSalt > 0)
    memcpy(pDB + psLen + 1, pSalt, cbSalt);

  /* -------- dbMask = MGF1(H, dbLen) -------- */
  pDBMask = ck_malloc(dbLen);
  if (!pDBMask) {
    CNK_ERROR("Failed to allocate dbMask buffer");
    rv = CKR_HOST_MEMORY;
    goto cleanup;
  }

  const CK_ULONG reps = (dbLen + hLen - 1) / hLen;
  for (CK_ULONG c = 0; c < reps; c++) {
    unsigned char C[4] = {
        (unsigned char)(c >> 24),
        (unsigned char)(c >> 16),
        (unsigned char)(c >> 8),
        (unsigned char)(c),
    };
    unsigned char buf[64 + 4]; /* H || C */
    memcpy(buf, H, hLen);
    memcpy(buf + hLen, C, 4);

    unsigned char hash[64];
    if (mbedtls_md(pMdInfo, buf, hLen + 4, hash) != 0) {
      CNK_ERROR("Failed to generate hash");
      rv = CKR_FUNCTION_FAILED;
      goto cleanup;
    }

    const CK_ULONG off = c * hLen;
    const CK_ULONG clen = (off + hLen <= dbLen) ? hLen : dbLen - off;
    memcpy(pDBMask + off, hash, clen);
  }

  /* maskedDB = DB XOR dbMask */
  for (CK_ULONG i = 0; i < dbLen; i++)
    pDB[i] ^= pDBMask[i];

  /* Clear the leftmost (8*emLen - emBits) bits */
  const unsigned leftBits = 8 * emLen - emBits;
  pDB[0] &= 0xFFu >> leftBits;

  /* -------- EM = maskedDB || H || 0xBC -------- */
  memcpy(pbOutput, pDB, dbLen);
  memcpy(pbOutput + dbLen, H, hLen);
  pbOutput[emLen - 1] = 0xBC;

  mbedtls_platform_zeroize(pDB, dbLen);

cleanup:
  mbedtls_ctr_drbg_free(&ctrDrbgCtx);
  mbedtls_entropy_free(&entropyCtx);
  mbedtls_mpi_free(&modulus_mpi);
  if (pSalt != NULL)
    mbedtls_platform_zeroize(pSalt, cbSalt);
  if (pMPrime != NULL)
    mbedtls_platform_zeroize(pMPrime, 8 + hLen + cbSalt);
  ck_free(pSalt);
  ck_free(pMPrime);
  ck_free(pDB);
  ck_free(pDBMask);
  CNK_RETURN(rv, "pss_encode finished");
}

static CK_RV mgf1(const CK_BYTE *seed, CK_ULONG seed_len, CK_BYTE *mask, CK_ULONG mask_len, mbedtls_md_type_t md_type) {
  // RFC 8017 MGF1 hashes seed || I2OSP(counter, 4) until the mask is full.
  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
  if (md_info == NULL)
    return CKR_MECHANISM_PARAM_INVALID;

  CK_ULONG hash_len = mbedtls_md_get_size(md_info);
  CK_ULONG offset = 0;
  CK_ULONG counter = 0;
  CK_BYTE digest[64];

  while (offset < mask_len) {
    CK_BYTE c[4] = {
        (CK_BYTE)(counter >> 24),
        (CK_BYTE)(counter >> 16),
        (CK_BYTE)(counter >> 8),
        (CK_BYTE)counter,
    };
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, md_info, 0) != 0 || mbedtls_md_starts(&ctx) != 0 ||
        mbedtls_md_update(&ctx, seed, seed_len) != 0 || mbedtls_md_update(&ctx, c, sizeof(c)) != 0 ||
        mbedtls_md_finish(&ctx, digest) != 0) {
      mbedtls_md_free(&ctx);
      mbedtls_platform_zeroize(digest, sizeof(digest));
      return CKR_FUNCTION_FAILED;
    }
    mbedtls_md_free(&ctx);

    CK_ULONG copy_len = (offset + hash_len <= mask_len) ? hash_len : mask_len - offset;
    memcpy(mask + offset, digest, copy_len);
    offset += copy_len;
    counter++;
  }

  mbedtls_platform_zeroize(digest, sizeof(digest));
  return CKR_OK;
}

CK_RV pkcs1_v1_5_encrypt_pad(const CK_BYTE *input, CK_ULONG inputLen, CK_BYTE *output, CK_ULONG outputLen) {
  CNK_ENSURE_NONNULL(output);
  if (input == NULL && inputLen > 0)
    return CKR_ARGUMENTS_BAD;
  if (outputLen < 11 || inputLen > outputLen - 11)
    return CKR_DATA_LEN_RANGE;

  // EME-PKCS1-v1_5 uses block type 2 and requires every PS byte to be nonzero.
  CK_ULONG paddingLen = outputLen - inputLen - 3;
  output[0] = 0;
  output[1] = 2;
  if (psa_generate_random(output + 2, paddingLen) != PSA_SUCCESS)
    return CKR_RANDOM_NO_RNG;
  for (CK_ULONG i = 0; i < paddingLen; i++) {
    while (output[2 + i] == 0) {
      if (psa_generate_random(output + 2 + i, 1) != PSA_SUCCESS) {
        mbedtls_platform_zeroize(output, outputLen);
        return CKR_RANDOM_NO_RNG;
      }
    }
  }
  output[2 + paddingLen] = 0;
  if (inputLen > 0)
    memcpy(output + outputLen - inputLen, input, inputLen);
  return CKR_OK;
}

CK_RV oaep_pad(const CK_BYTE *input, CK_ULONG inputLen, CK_BYTE *output, CK_ULONG outputLen, mbedtls_md_type_t mdType,
               mbedtls_md_type_t mgfMdType, const CK_BYTE *label, CK_ULONG labelLen) {
  CNK_ENSURE_NONNULL(output);
  if ((input == NULL && inputLen > 0) || (label == NULL && labelLen > 0))
    return CKR_ARGUMENTS_BAD;

  const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(mdType);
  const mbedtls_md_info_t *mgfInfo = mbedtls_md_info_from_type(mgfMdType);
  if (mdInfo == NULL || mgfInfo == NULL)
    return CKR_MECHANISM_PARAM_INVALID;
  CK_ULONG hashLen = mbedtls_md_get_size(mdInfo);
  if (outputLen < 2 * hashLen + 2 || inputLen > outputLen - 2 * hashLen - 2)
    return CKR_DATA_LEN_RANGE;

  // Build EM = 0x00 || maskedSeed || maskedDB in the caller's modulus-sized
  // buffer. PKCS#11 permits hashAlg and MGF to use different digests.
  CK_ULONG dbLen = outputLen - hashLen - 1;
  CK_BYTE *seed = output + 1;
  CK_BYTE *db = output + 1 + hashLen;
  CK_BYTE *mask = ck_malloc(dbLen > hashLen ? dbLen : hashLen);
  if (mask == NULL)
    return CKR_HOST_MEMORY;

  CK_RV rv = CKR_OK;
  output[0] = 0;
  if (mbedtls_md(mdInfo, label, labelLen, db) != 0) {
    rv = CKR_FUNCTION_FAILED;
    goto cleanup;
  }
  CK_ULONG paddingLen = dbLen - hashLen - inputLen - 1;
  memset(db + hashLen, 0, paddingLen);
  db[hashLen + paddingLen] = 1;
  if (inputLen > 0)
    memcpy(db + dbLen - inputLen, input, inputLen);
  if (psa_generate_random(seed, hashLen) != PSA_SUCCESS) {
    rv = CKR_RANDOM_NO_RNG;
    goto cleanup;
  }

  rv = mgf1(seed, hashLen, mask, dbLen, mgfMdType);
  if (rv != CKR_OK)
    goto cleanup;
  for (CK_ULONG i = 0; i < dbLen; i++)
    db[i] ^= mask[i];

  rv = mgf1(db, dbLen, mask, hashLen, mgfMdType);
  if (rv != CKR_OK)
    goto cleanup;
  for (CK_ULONG i = 0; i < hashLen; i++)
    seed[i] ^= mask[i];

cleanup:
  mbedtls_platform_zeroize(mask, dbLen > hashLen ? dbLen : hashLen);
  ck_free(mask);
  if (rv != CKR_OK)
    mbedtls_platform_zeroize(output, outputLen);
  return rv;
}

CK_RV pss_verify(const CK_BYTE *hash, CK_ULONG hashLen, const CK_BYTE *modulus, CK_ULONG modulusLen, CK_ULONG saltLen,
                 mbedtls_md_type_t mdType, const CK_BYTE *encoded, CK_ULONG encodedLen) {
  CNK_ENSURE_NONNULL(hash, modulus, encoded);
  const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(mdType);
  if (mdInfo == NULL)
    return CKR_MECHANISM_PARAM_INVALID;
  CK_ULONG expectedHashLen = mbedtls_md_get_size(mdInfo);
  if (hashLen != expectedHashLen)
    return CKR_DATA_LEN_RANGE;

  mbedtls_mpi modulusMpi;
  mbedtls_mpi_init(&modulusMpi);
  if (mbedtls_mpi_read_binary(&modulusMpi, modulus, modulusLen) != 0) {
    mbedtls_mpi_free(&modulusMpi);
    return CKR_KEY_HANDLE_INVALID;
  }
  CK_ULONG modulusBits = mbedtls_mpi_bitlen(&modulusMpi);
  mbedtls_mpi_free(&modulusMpi);
  CK_ULONG encodedBits = modulusBits - 1;
  CK_ULONG expectedEncodedLen = (encodedBits + 7) / 8;
  if (encodedLen != expectedEncodedLen || encodedLen < expectedHashLen + saltLen + 2)
    return CKR_SIGNATURE_LEN_RANGE;
  if (encoded[encodedLen - 1] != 0xBC)
    return CKR_SIGNATURE_INVALID;

  // Reverse EMSA-PSS: unmask DB, validate PS || 0x01 || salt, then recompute H.
  CK_ULONG dbLen = encodedLen - expectedHashLen - 1;
  CK_BYTE *db = ck_malloc(dbLen);
  CK_BYTE *mask = ck_malloc(dbLen);
  if (db == NULL || mask == NULL) {
    ck_free(db);
    ck_free(mask);
    return CKR_HOST_MEMORY;
  }
  const CK_BYTE *encodedHash = encoded + dbLen;
  CK_RV rv = mgf1(encodedHash, expectedHashLen, mask, dbLen, mdType);
  if (rv != CKR_OK)
    goto cleanup;
  for (CK_ULONG i = 0; i < dbLen; i++)
    db[i] = encoded[i] ^ mask[i];

  unsigned unusedBits = (unsigned)(8 * expectedEncodedLen - encodedBits);
  CK_BYTE highMask = (CK_BYTE)(0xFFu << (8 - unusedBits));
  if ((encoded[0] & highMask) != 0) {
    rv = CKR_SIGNATURE_INVALID;
    goto cleanup;
  }
  db[0] &= (CK_BYTE)~highMask;

  CK_ULONG separator = dbLen - saltLen - 1;
  for (CK_ULONG i = 0; i < separator; i++) {
    if (db[i] != 0) {
      rv = CKR_SIGNATURE_INVALID;
      goto cleanup;
    }
  }
  if (db[separator] != 1) {
    rv = CKR_SIGNATURE_INVALID;
    goto cleanup;
  }

  CK_BYTE recomputed[MBEDTLS_MD_MAX_SIZE];
  CK_BYTE zeros[8] = {0};
  mbedtls_md_context_t context;
  mbedtls_md_init(&context);
  if (mbedtls_md_setup(&context, mdInfo, 0) != 0 || mbedtls_md_starts(&context) != 0 ||
      mbedtls_md_update(&context, zeros, sizeof(zeros)) != 0 || mbedtls_md_update(&context, hash, hashLen) != 0 ||
      mbedtls_md_update(&context, db + separator + 1, saltLen) != 0 || mbedtls_md_finish(&context, recomputed) != 0) {
    rv = CKR_FUNCTION_FAILED;
  } else if (memcmp(recomputed, encodedHash, expectedHashLen) != 0) {
    rv = CKR_SIGNATURE_INVALID;
  } else {
    rv = CKR_OK;
  }
  mbedtls_md_free(&context);
  mbedtls_platform_zeroize(recomputed, sizeof(recomputed));

cleanup:
  mbedtls_platform_zeroize(db, dbLen);
  mbedtls_platform_zeroize(mask, dbLen);
  ck_free(db);
  ck_free(mask);
  return rv;
}

CK_RV pkcs1_v1_5_unpad(CK_BYTE_PTR pbInput, CK_ULONG cbInput, CK_BYTE_PTR pbOutput, CK_ULONG_PTR pcbOutput) {
  CNK_ENSURE_NONNULL(pbInput, pcbOutput);

  if (cbInput < 11 || pbInput[0] != 0x00 || pbInput[1] != 0x02)
    return CKR_ENCRYPTED_DATA_INVALID;

  CK_ULONG pos = 2;
  while (pos < cbInput && pbInput[pos] != 0x00)
    pos++;

  if (pos < 10 || pos >= cbInput)
    return CKR_ENCRYPTED_DATA_INVALID;

  CK_ULONG cbPlaintext = cbInput - pos - 1;
  if (pbOutput == NULL_PTR) {
    *pcbOutput = cbPlaintext;
    return CKR_OK;
  }

  if (*pcbOutput < cbPlaintext) {
    *pcbOutput = cbPlaintext;
    return CKR_BUFFER_TOO_SMALL;
  }

  memcpy(pbOutput, pbInput + pos + 1, cbPlaintext);
  *pcbOutput = cbPlaintext;
  return CKR_OK;
}

CK_RV oaep_unpad(CK_BYTE_PTR pbInput, CK_ULONG cbInput, CK_BYTE_PTR pbOutput, CK_ULONG_PTR pcbOutput,
                 mbedtls_md_type_t mdType, mbedtls_md_type_t mgfMdType, CK_BYTE_PTR pLabel, CK_ULONG cbLabel) {
  CNK_ENSURE_NONNULL(pbInput, pcbOutput);

  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(mdType);
  const mbedtls_md_info_t *mgf_md_info = mbedtls_md_info_from_type(mgfMdType);
  if (md_info == NULL || mgf_md_info == NULL)
    return CKR_MECHANISM_PARAM_INVALID;

  CK_ULONG h_len = mbedtls_md_get_size(md_info);
  if (cbInput < 2 * h_len + 2 || pbInput[0] != 0x00)
    return CKR_ENCRYPTED_DATA_INVALID;

  CK_RV rv = CKR_OK;
  CK_ULONG db_len = cbInput - h_len - 1;
  CK_BYTE *masked_seed = pbInput + 1;
  CK_BYTE *masked_db = pbInput + 1 + h_len;
  CK_BYTE *seed = NULL_PTR;
  CK_BYTE *db = NULL_PTR;
  CK_BYTE *mask = NULL_PTR;
  CK_BYTE label_hash[64];

  seed = ck_malloc(h_len);
  db = ck_malloc(db_len);
  mask = ck_malloc(db_len > h_len ? db_len : h_len);
  if (seed == NULL_PTR || db == NULL_PTR || mask == NULL_PTR) {
    rv = CKR_HOST_MEMORY;
    goto cleanup;
  }

  rv = mgf1(masked_db, db_len, mask, h_len, mgfMdType);
  if (rv != CKR_OK)
    goto cleanup;

  for (CK_ULONG i = 0; i < h_len; i++)
    seed[i] = masked_seed[i] ^ mask[i];

  rv = mgf1(seed, h_len, mask, db_len, mgfMdType);
  if (rv != CKR_OK)
    goto cleanup;

  for (CK_ULONG i = 0; i < db_len; i++)
    db[i] = masked_db[i] ^ mask[i];

  static const CK_BYTE empty_label[] = {0};
  const CK_BYTE_PTR label = (cbLabel == 0 && pLabel == NULL_PTR) ? (CK_BYTE_PTR)empty_label : pLabel;

  if (mbedtls_md(md_info, label, cbLabel, label_hash) != 0) {
    rv = CKR_FUNCTION_FAILED;
    goto cleanup;
  }

  if (memcmp(db, label_hash, h_len) != 0) {
    rv = CKR_ENCRYPTED_DATA_INVALID;
    goto cleanup;
  }

  CK_ULONG pos = h_len;
  while (pos < db_len && db[pos] == 0x00)
    pos++;
  if (pos >= db_len || db[pos] != 0x01) {
    rv = CKR_ENCRYPTED_DATA_INVALID;
    goto cleanup;
  }
  pos++;

  CK_ULONG cbPlaintext = db_len - pos;
  if (pbOutput == NULL_PTR) {
    *pcbOutput = cbPlaintext;
    goto cleanup;
  }

  if (*pcbOutput < cbPlaintext) {
    *pcbOutput = cbPlaintext;
    rv = CKR_BUFFER_TOO_SMALL;
    goto cleanup;
  }

  memcpy(pbOutput, db + pos, cbPlaintext);
  *pcbOutput = cbPlaintext;

cleanup:
  mbedtls_platform_zeroize(label_hash, sizeof(label_hash));
  if (seed != NULL_PTR)
    mbedtls_platform_zeroize(seed, h_len);
  if (db != NULL_PTR)
    mbedtls_platform_zeroize(db, db_len);
  if (mask != NULL_PTR)
    mbedtls_platform_zeroize(mask, db_len > h_len ? db_len : h_len);
  ck_free(seed);
  ck_free(db);
  ck_free(mask);
  return rv;
}
