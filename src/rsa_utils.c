#include "rsa_utils.h"
#include "logging.h"      // For logging macros
#include "pcsc_backend.h" // For ck_malloc and ck_free
#include "pkcs11.h"
#include "utils.h"

#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <string.h>

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
  if (cbSalt > hLen)
    return CKR_MECHANISM_PARAM_INVALID;

  CK_RV rv = CKR_OK;
  CK_BYTE_PTR pSalt = NULL_PTR;
  CK_BYTE_PTR pDB = NULL_PTR;
  CK_BYTE_PTR pDBMask = NULL_PTR;
  mbedtls_mpi modulus_mpi;

  mbedtls_entropy_context entropyCtx;
  mbedtls_ctr_drbg_context ctrDrbgCtx;
  mbedtls_entropy_init(&entropyCtx);
  mbedtls_ctr_drbg_init(&ctrDrbgCtx);

  /* emBits = modBits - 1  ——  RFC 8017 §9.1.1 */
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

  /* -------- H = Hash( 0x00×8 || mHash || salt ) -------- */
  CK_BYTE M_prime[8 + 64 + 64];
  memset(M_prime, 0, 8);
  memcpy(M_prime + 8, pbHash, hLen);
  memcpy(M_prime + 8 + hLen, pSalt, cbSalt);

  CK_BYTE H[64]; /* hLen ≤ 64 */
  if (mbedtls_md(pMdInfo, M_prime, 8 + hLen + cbSalt, H) != 0) {
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

  /* maskedDB = DB ⊕ dbMask */
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
  ck_free(pSalt);
  ck_free(pDB);
  ck_free(pDBMask);
  CNK_RETURN(rv, "pss_encode finished");
}
