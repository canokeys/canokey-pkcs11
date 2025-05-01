// clang-format off
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stddef.h>
#include <cmocka.h>
// clang-format on

#include "logging.h"
#include "pcsc_backend.h"
#include "pkcs11.h"
#include "rsa_utils.h"

#include <mbedtls/bignum.h>
#include <mbedtls/md.h>

// Mock functions and data structures
static unsigned char test_data[] = "test data for RSA sign operation";
static size_t test_data_len = 32; // Length of test_data
static unsigned char modulus[] = {
    0xba, 0x80, 0x55, 0x39, 0x42, 0x0b, 0x63, 0x12, 0x77, 0x86, 0xcd, 0x25, 0xbc, 0xbb, 0xd9, 0xcb, 0x10, 0xfe, 0xee,
    0xa7, 0xc5, 0x6d, 0x61, 0xf4, 0x22, 0x41, 0xe0, 0xeb, 0xf3, 0xa3, 0x38, 0xd3, 0xba, 0x6c, 0x8a, 0x02, 0x6a, 0x27,
    0xc6, 0x6a, 0x20, 0xa4, 0xe8, 0xf3, 0x45, 0x3e, 0xa2, 0xc6, 0xa3, 0x6b, 0x7d, 0xf4, 0xa1, 0x88, 0x3f, 0xc1, 0x41,
    0xb8, 0xf8, 0xce, 0xe7, 0x80, 0xd9, 0xb9, 0x3a, 0x5f, 0x91, 0x1a, 0xbb, 0x57, 0xce, 0x59, 0x19, 0xf9, 0x26, 0x20,
    0xee, 0xba, 0x0c, 0xa4, 0xf3, 0xd2, 0xd3, 0x3f, 0x40, 0xe9, 0x6e, 0x52, 0x22, 0x81, 0xc4, 0x6f, 0x25, 0x6e, 0x16,
    0x73, 0x3f, 0x29, 0x5e, 0xe8, 0x47, 0x93, 0xa3, 0xe6, 0xcb, 0xe5, 0xb4, 0x61, 0x1e, 0x80, 0xf2, 0x6f, 0xc7, 0x9b,
    0xd9, 0x85, 0xf6, 0x3d, 0x5d, 0x00, 0x82, 0x16, 0x87, 0x61, 0x2d, 0xb8, 0x4f, 0x08, 0xb2, 0xe4, 0xf5, 0x93, 0x55,
    0x53, 0xea, 0x7e, 0x01, 0xa6, 0x66, 0xf1, 0xfc, 0xfd, 0x7f, 0xeb, 0xd3, 0x2d, 0x42, 0x42, 0xd9, 0x19, 0x3b, 0x25,
    0x3c, 0x72, 0x3e, 0xed, 0x26, 0x12, 0x33, 0x00, 0x86, 0x02, 0xad, 0x1e, 0xd2, 0xc5, 0xc8, 0x78, 0xe0, 0xa7, 0xd7,
    0x8d, 0x47, 0x16, 0xe1, 0xa3, 0xde, 0x80, 0xaf, 0x2b, 0xd6, 0xea, 0xa4, 0xaf, 0xd4, 0x22, 0x1d, 0x47, 0x0c, 0x80,
    0xbb, 0x64, 0xd6, 0x31, 0x67, 0x86, 0xde, 0x46, 0xb2, 0x75, 0xab, 0x69, 0xcc, 0xd7, 0x54, 0x14, 0xfc, 0xf4, 0x8f,
    0xdf, 0x24, 0x59, 0x80, 0x91, 0x77, 0x81, 0xa1, 0x25, 0xf2, 0xe5, 0x1d, 0xd2, 0x32, 0x0d, 0x37, 0x87, 0xcb, 0x28,
    0x53, 0x23, 0xf2, 0xfb, 0x35, 0x68, 0xd3, 0x27, 0xdb, 0x5a, 0xb1, 0x55, 0xfd, 0x7d, 0x3c, 0xfd, 0x58, 0x37, 0x9e,
    0x07, 0xa7, 0xe7, 0xf5, 0x3e, 0xdf, 0xe6, 0x10, 0xdb};

// Function to set up the test mechanism
static void setup_mechanism(CK_MECHANISM *mechanism, CK_MECHANISM_TYPE mech_type, void *parameter,
                            CK_ULONG parameter_len) {
  mechanism->mechanism = mech_type;
  mechanism->pParameter = parameter;
  mechanism->ulParameterLen = parameter_len;
}

static CK_RV mgf1(const unsigned char *seed, size_t seed_len, unsigned char *mask, size_t mask_len,
                  mbedtls_md_type_t mgf_md_type) {
  const mbedtls_md_info_t *mgf_md_info = mbedtls_md_info_from_type(mgf_md_type);
  if (mgf_md_info == NULL)
    return CKR_MECHANISM_INVALID;
  size_t mgf_hash_len = mbedtls_md_get_size(mgf_md_info);
  size_t iterations = (mask_len + mgf_hash_len - 1) / mgf_hash_len;
  unsigned char counter[4];
  int ret = 0;
  for (size_t c = 0; c < iterations; c++) {
    counter[0] = (unsigned char)((c >> 24) & 0xFF);
    counter[1] = (unsigned char)((c >> 16) & 0xFF);
    counter[2] = (unsigned char)((c >> 8) & 0xFF);
    counter[3] = (unsigned char)(c & 0xFF);
    unsigned char digest[64] = {0};
    unsigned char buf[seed_len + 4];
    memcpy(buf, seed, seed_len);
    memcpy(buf + seed_len, counter, 4);

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    ret = mbedtls_md_setup(&ctx, mgf_md_info, 0);
    if (ret != 0) {
      printf("mgf1: mbedtls_md_setup failed with error 0x%08x\n", (unsigned int)ret);
      mbedtls_md_free(&ctx);
      return CKR_FUNCTION_FAILED;
    }
    ret = mbedtls_md_starts(&ctx);
    if (ret != 0) {
      printf("mgf1: mbedtls_md_starts failed with error 0x%08x\n", (unsigned int)ret);
      mbedtls_md_free(&ctx);
      return CKR_FUNCTION_FAILED;
    }
    ret = mbedtls_md_update(&ctx, buf, seed_len + 4);
    if (ret != 0) {
      printf("mgf1: mbedtls_md_update failed with error 0x%08x\n", (unsigned int)ret);
      mbedtls_md_free(&ctx);
      return CKR_FUNCTION_FAILED;
    }
    ret = mbedtls_md_finish(&ctx, digest);
    if (ret != 0) {
      printf("mgf1: mbedtls_md_finish failed with error 0x%08x\n", (unsigned int)ret);
      mbedtls_md_free(&ctx);
      return CKR_FUNCTION_FAILED;
    }
    mbedtls_md_free(&ctx);

    size_t offset = c * mgf_hash_len;
    size_t to_copy = (offset + mgf_hash_len <= mask_len) ? mgf_hash_len : mask_len - offset;
    memcpy(mask + offset, digest, to_copy);
  }
  return CKR_OK;
}

// Unmasks the maskedDB using mgf1, checks that DB has the structure (PS || 0x01 || salt),
// reconstructs M' = (8 zero bytes || mHash || salt), computes H', and compares H' with H.
static CK_RV verify_pss_encoding(CK_BYTE_PTR encoded, CK_ULONG encoded_len, CK_BYTE_PTR message, CK_ULONG message_len,
                                 mbedtls_md_type_t md_type, mbedtls_md_type_t mgf_md_type, CK_ULONG salt_len,
                                 CK_BYTE_PTR pModulus, CK_ULONG ulModulusLen, CK_BBOOL is_message_prehashed) {
  /* ---------- 1. trailer byte ---------- */
  if (encoded_len < 2 || encoded[encoded_len - 1] != 0xBC)
    return CKR_FUNCTION_FAILED;

  /* ---------- 2. Get digest ---------- */
  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
  const mbedtls_md_info_t *mgf_info = mbedtls_md_info_from_type(mgf_md_type);
  if (md_info == NULL || mgf_info == NULL)
    return CKR_FUNCTION_FAILED;

  const size_t hash_len = mbedtls_md_get_size(md_info);
  if (encoded_len < hash_len + 2)
    return CKR_FUNCTION_FAILED;

  /* ---------- 3. modBits / emBits ---------- */
  mbedtls_mpi modulus_mpi;
  mbedtls_mpi_init(&modulus_mpi);
  if (mbedtls_mpi_read_binary(&modulus_mpi, pModulus, ulModulusLen) != 0) {
    mbedtls_mpi_free(&modulus_mpi);
    return CKR_FUNCTION_FAILED;
  }
  const CK_ULONG modBits = mbedtls_mpi_bitlen(&modulus_mpi);
  mbedtls_mpi_free(&modulus_mpi);

  const CK_ULONG emBits = modBits - 1; /* RFC 8017 §9.1.1 */
  const CK_ULONG expected_emLen = (emBits + 7) / 8;
  if (encoded_len != expected_emLen)
    return CKR_VENDOR_DEFINED; /* EM 长度不符 */

  /* ---------- 4. Split EM ---------- */
  CK_ULONG dbLen = encoded_len - hash_len - 1;
  if (dbLen < salt_len + 1)
    return CKR_FUNCTION_FAILED;

  CK_BYTE *maskedDB = encoded;  /* [0 .. dbLen‑1]   */
  CK_BYTE *H = encoded + dbLen; /* [dbLen .. dbLen+hash_len‑1] */

  /* ---------- 5. dbMask and decode ---------- */
  unsigned char *mask = ck_malloc(dbLen);
  if (!mask)
    return CKR_HOST_MEMORY;

  CK_RV rv = mgf1(H, hash_len, mask, dbLen, mgf_md_type);
  if (rv != CKR_OK) {
    ck_free(mask);
    return rv;
  }

  unsigned char *DB = ck_malloc(dbLen);
  if (!DB) {
    ck_free(mask);
    return CKR_HOST_MEMORY;
  }
  for (CK_ULONG i = 0; i < dbLen; i++)
    DB[i] = maskedDB[i] ^ mask[i];
  ck_free(mask);

  /* ---------- 6. Clear leftmost bits ---------- */
  const unsigned leftBits = (unsigned)(8 * encoded_len - emBits); /* 1‑7 或 0 */
  if (leftBits)
    DB[0] &= 0xFFu >> leftBits;

  /* ---------- 7. Check DB = PS || 0x01 || salt ---------- */
  CK_ULONG psLen = dbLen - salt_len - 1;
  for (CK_ULONG i = 0; i < psLen; i++) {
    if (DB[i] != 0x00) {
      ck_free(DB);
      return CKR_VENDOR_DEFINED;
    }
  }
  if (DB[psLen] != 0x01) {
    ck_free(DB);
    return CKR_VENDOR_DEFINED;
  }
  unsigned char *extracted_salt = DB + psLen + 1;

  /* ---------- 8. Compute mHash ---------- */
  unsigned char mHash[64] = {0};
  if (is_message_prehashed) {
    if (message_len != hash_len) {
      ck_free(DB);
      return CKR_VENDOR_DEFINED;
    }
    memcpy(mHash, message, hash_len);
  } else {
    if (mbedtls_md(md_info, message, message_len, mHash) != 0) {
      ck_free(DB);
      return CKR_FUNCTION_FAILED;
    }
  }

  /* ---------- 9. Compute H' ---------- */
  const CK_ULONG mprime_len = 8 + hash_len + salt_len;
  unsigned char *M_prime = ck_malloc(mprime_len);
  if (!M_prime) {
    ck_free(DB);
    return CKR_HOST_MEMORY;
  }

  memset(M_prime, 0, 8); /* 0x00×8            */
  memcpy(M_prime + 8, mHash, hash_len);
  memcpy(M_prime + 8 + hash_len, extracted_salt, salt_len);

  unsigned char H_prime[64];
  if (mbedtls_md(md_info, M_prime, mprime_len, H_prime) != 0) {
    ck_free(M_prime);
    ck_free(DB);
    return CKR_FUNCTION_FAILED;
  }
  ck_free(M_prime);

  /* ---------- 10. Compare H ---------- */
  if (memcmp(H, H_prime, hash_len) != 0) {
    ck_free(DB);
    return CKR_VENDOR_DEFINED;
  }

  ck_free(DB);
  return CKR_OK;
}

// Test for CKM_RSA_X_509 padding (raw padding with leading zeros)
static void test_x509_padding(void **state) {
  (void)state; // Unused

  CK_MECHANISM mechanism;
  CK_BYTE output[256] = {0}; // 2048 bits = 256 bytes
  CK_ULONG output_len = sizeof(output);
  CK_RV rv;

  // Setup mechanism for X.509
  setup_mechanism(&mechanism, CKM_RSA_X_509, NULL, 0);

  // Test size estimation (pPreparedData = NULL)
  rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, NULL, 256, NULL, &output_len);
  assert_int_equal(rv, CKR_OK);
  assert_int_equal(output_len, 256);

  // Reset output length for actual padding
  output_len = sizeof(output);

  // Test actual padding with buffer larger than data
  rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, NULL, 256, output, &output_len);
  assert_int_equal(rv, CKR_OK);
  assert_int_equal(output_len, 256);

  // Verify the output: should have leading zeros followed by the test data
  unsigned char expected[256] = {0};
  memcpy(expected + (sizeof(output) - test_data_len), test_data, test_data_len);

  // Check the first bytes are zero (leading padding)
  for (size_t i = 0; i < (sizeof(output) - test_data_len); i++) {
    assert_int_equal(output[i], 0);
  }

  // Check that the data is correctly placed at the end
  assert_memory_equal(output + (sizeof(output) - test_data_len), test_data, test_data_len);

  // Note: For CKM_RSA_X_509, output buffer must be at least the modulus size
  // The following tests use a 256-byte (modulus size) buffer instead of a small buffer

  unsigned char small_output[256] = {0};
  output_len = sizeof(small_output);

  // Test another valid padding operation
  rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, NULL, 256, small_output, &output_len);
  assert_int_equal(rv, CKR_OK);
  assert_int_equal(output_len, 256);

  // Test with too small buffer
  output_len = 128; // Half the required size for RSA-2048
  rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, NULL, 256, small_output, &output_len);
  assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);
}

// Test for PKCS#1 v1.5 padding with CKM_RSA_PKCS (direct data padding)
static void test_pkcs1_v1_5_direct_padding(void **state) {
  (void)state; // Unused

  CK_MECHANISM mechanism;
  CK_BYTE output[256] = {0}; // 2048 bits = 256 bytes
  CK_ULONG output_len = sizeof(output);
  CK_RV rv;

  // Setup mechanism for PKCS#1 v1.5
  setup_mechanism(&mechanism, CKM_RSA_PKCS, NULL, 0);

  // Test size estimation (pPreparedData = NULL)
  rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, NULL, 256, NULL, &output_len);
  assert_int_equal(rv, CKR_OK);
  assert_int_equal(output_len, 256); // 2048 bits = 256 bytes

  // Reset output length for actual padding
  output_len = sizeof(output);

  // Test actual padding
  rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, NULL, 256, output, &output_len);
  assert_int_equal(rv, CKR_OK);
  assert_int_equal(output_len, 256);

  // Verify basic PKCS#1 v1.5 structure
  // First byte should be 0x00, second byte should be 0x01 (for private key operations)
  assert_int_equal(output[0], 0x00);
  assert_int_equal(output[1], 0x01);

  // The padding should be 0xFF until a 0x00 byte is encountered
  size_t i = 2;
  while (i < output_len && output[i] == 0xFF) {
    i++;
  }

  // Next byte should be 0x00 separator
  assert_int_equal(output[i], 0x00);
  i++;

  // Remaining data should be the input data
  assert_memory_equal(output + i, test_data, test_data_len);

  // Test with output buffer too small
  output_len = 128; // Too small for 2048-bit key
  rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, NULL, 256, output, &output_len);
  assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);
}

// Test for PKCS#1 v1.5 padding with SHA1_RSA_PKCS (hash and pad)
static void test_pkcs1_v1_5_sha1_padding(void **state) {
  (void)state; // Unused

  CK_MECHANISM mechanism;
  CK_BYTE output[256] = {0}; // 2048 bits = 256 bytes
  CK_ULONG output_len = sizeof(output);
  CK_RV rv;

  // Setup mechanism for SHA1-RSA-PKCS
  setup_mechanism(&mechanism, CKM_SHA1_RSA_PKCS, NULL, 0);

  // Test size estimation (pPreparedData = NULL)
  rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, NULL, 256, NULL, &output_len);
  assert_int_equal(rv, CKR_OK);
  assert_int_equal(output_len, 256); // 2048 bits = 256 bytes

  // Reset output length for actual padding
  output_len = sizeof(output);

  // Test actual padding
  rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, NULL, 256, output, &output_len);
  assert_int_equal(rv, CKR_OK);
  assert_int_equal(output_len, 256);

  // Verify basic PKCS#1 v1.5 structure
  // First byte should be 0x00, second byte should be 0x01 (for private key operations)
  assert_int_equal(output[0], 0x00);
  assert_int_equal(output[1], 0x01);

  // The padding should be 0xFF until a 0x00 byte is encountered
  size_t i = 2;
  while (i < output_len && output[i] == 0xFF) {
    i++;
  }

  // Next byte should be 0x00 separator
  assert_int_equal(output[i], 0x00);
  i++;

  // For SHA1, there should be an ASN.1 header for the digest (DER encoding)
  // SHA1 OID is 1.3.14.3.2.26
  // Check for ASN.1 SEQUENCE tag and length
  assert_int_equal(output[i], 0x30); // SEQUENCE
  i++;

  // Skip over the length byte(s)
  if ((output[i] & 0x80) == 0) {
    // Short form
    i++;
  } else {
    // Long form
    int len_bytes = output[i] & 0x7F;
    i += len_bytes + 1;
  }

  // Check for ASN.1 SEQUENCE tag for AlgorithmIdentifier
  assert_int_equal(output[i], 0x30); // SEQUENCE
  i++;

  // Skip over the length byte(s) and the OID structure to reach the actual hash
  // This is implementation-dependent, but we can search for the NULL marker
  // that comes at the end of the AlgorithmIdentifier
  while (i < output_len) {
    if (output[i] == 0x05 && output[i + 1] == 0x00) { // NULL tag + length
      i += 2;
      break;
    }
    i++;
  }

  // The next part should be the OCTET STRING containing the hash
  assert_int_equal(output[i], 0x04); // OCTET STRING
  i++;

  // The length of the hash should be 20 bytes for SHA-1
  assert_int_equal(output[i], 20);
  i++;

  // Calculate the expected SHA-1 hash of the test data
  unsigned char expected_hash[20];
  mbedtls_md_context_t md_ctx;
  mbedtls_md_init(&md_ctx);

  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
  assert_non_null(md_info);

  rv = mbedtls_md_setup(&md_ctx, md_info, 0);
  assert_int_equal(rv, 0);

  rv = mbedtls_md_starts(&md_ctx);
  assert_int_equal(rv, 0);

  rv = mbedtls_md_update(&md_ctx, test_data, test_data_len);
  assert_int_equal(rv, 0);

  rv = mbedtls_md_finish(&md_ctx, expected_hash);
  assert_int_equal(rv, 0);

  mbedtls_md_free(&md_ctx);

  // Compare the hash in the padded output with the expected hash
  assert_memory_equal(output + i, expected_hash, 20);
}

// Test for PKCS#1 v1.5 padding with SHA256_RSA_PKCS (hash and pad)
static void test_pkcs1_v1_5_sha256_padding(void **state) {
  (void)state; // Unused

  CK_MECHANISM mechanism;
  CK_BYTE output[256] = {0}; // 2048 bits = 256 bytes
  CK_ULONG output_len = sizeof(output);
  CK_RV rv;

  // Setup mechanism for SHA256-RSA-PKCS
  setup_mechanism(&mechanism, CKM_SHA256_RSA_PKCS, NULL, 0);

  // Test size estimation (pPreparedData = NULL)
  rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, NULL, 256, NULL, &output_len);
  assert_int_equal(rv, CKR_OK);
  assert_int_equal(output_len, 256); // 2048 bits = 256 bytes

  // Reset output length for actual padding
  output_len = sizeof(output);

  // Test actual padding
  rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, NULL, 256, output, &output_len);
  assert_int_equal(rv, CKR_OK);
  assert_int_equal(output_len, 256);

  // Similar checks as SHA1, but with SHA256 ASN.1 structure
  assert_int_equal(output[0], 0x00);
  assert_int_equal(output[1], 0x01);

  // The padding should be 0xFF until a 0x00 byte is encountered
  size_t i = 2;
  while (i < output_len && output[i] == 0xFF) {
    i++;
  }

  // Next byte should be 0x00 separator
  assert_int_equal(output[i], 0x00);
  i++;

  // For SHA256, there should be an ASN.1 header for the digest (DER encoding)
  // SHA256 OID is 2.16.840.1.101.3.4.2.1
  // Check for ASN.1 SEQUENCE tag and length
  assert_int_equal(output[i], 0x30); // SEQUENCE
  i++;

  // Skip over the length byte(s)
  if ((output[i] & 0x80) == 0) {
    // Short form
    i++;
  } else {
    // Long form
    int len_bytes = output[i] & 0x7F;
    i += len_bytes + 1;
  }

  // Check for ASN.1 SEQUENCE tag for AlgorithmIdentifier
  assert_int_equal(output[i], 0x30); // SEQUENCE
  i++;

  // Skip over the length byte(s) and the OID structure to reach the actual hash
  // This is implementation-dependent, but we can search for the NULL marker
  // that comes at the end of the AlgorithmIdentifier
  while (i < output_len) {
    if (output[i] == 0x05 && output[i + 1] == 0x00) { // NULL tag + length
      i += 2;
      break;
    }
    i++;
  }

  // The next part should be the OCTET STRING containing the hash
  assert_int_equal(output[i], 0x04); // OCTET STRING
  i++;

  // The length of the hash should be 32 bytes for SHA-256
  assert_int_equal(output[i], 32);
  i++;

  // Calculate the expected SHA-256 hash of the test data
  unsigned char expected_hash[32];
  mbedtls_md_context_t md_ctx;
  mbedtls_md_init(&md_ctx);

  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  assert_non_null(md_info);

  rv = mbedtls_md_setup(&md_ctx, md_info, 0);
  assert_int_equal(rv, 0);

  rv = mbedtls_md_starts(&md_ctx);
  assert_int_equal(rv, 0);

  rv = mbedtls_md_update(&md_ctx, test_data, test_data_len);
  assert_int_equal(rv, 0);

  rv = mbedtls_md_finish(&md_ctx, expected_hash);
  assert_int_equal(rv, 0);

  mbedtls_md_free(&md_ctx);

  // Compare the hash in the padded output with the expected hash
  assert_memory_equal(output + i, expected_hash, 32);
}

static void test_pss_padding(void **state) {
  (void)state; // Unused

  CK_MECHANISM mechanism;
  CK_RSA_PKCS_PSS_PARAMS pss_params = {
      .hashAlg = CKM_SHA256,
      .mgf = CKG_MGF1_SHA256, // use MGF1 with SHA-256
      .sLen = 32              // salt length of 32 bytes
  };
  CK_BYTE output[256] = {0}; // 2048 bits = 256 bytes
  CK_ULONG output_len = sizeof(output);
  CK_RV rv;

  // For CKM_RSA_PKCS_PSS, when using prehashed input we first compute the SHA-256 hash.
  unsigned char message_hash[32];
  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  assert_non_null(md_info);

  rv = mbedtls_md(md_info, test_data, test_data_len, message_hash);
  assert_int_equal(rv, 0);

  // Set up the mechanism for RSA-PSS.
  setup_mechanism(&mechanism, CKM_RSA_PKCS_PSS, &pss_params, sizeof(pss_params));

  // Test size estimation when pPreparedData is NULL.
  rv = cnk_prepare_rsa_sign_data(&mechanism, message_hash, sizeof(message_hash), modulus, sizeof(modulus), NULL,
                                 &output_len);
  assert_int_equal(rv, CKR_OK);

  // Reset output length and perform the actual padding.
  output_len = sizeof(output);
  rv = cnk_prepare_rsa_sign_data(&mechanism, message_hash, sizeof(message_hash), modulus, sizeof(modulus), output,
                                 &output_len);
  assert_int_equal(rv, CKR_OK);

  // Verify the PSS encoding structure for the prehashed case.
  rv = verify_pss_encoding(output, output_len, message_hash, sizeof(message_hash), MBEDTLS_MD_SHA256, MBEDTLS_MD_SHA256,
                           pss_params.sLen, modulus, sizeof(modulus), CK_TRUE);
  assert_int_equal(rv, CKR_OK);
  assert_int_equal(output[output_len - 1], 0xbc);
  printf("PSS encoding (prehashed) verification passed\n");

  // Test the raw message case (non-prehashed): the function will internally hash the message.
  CK_BYTE output2[256] = {0};
  CK_ULONG output_len2 = sizeof(output2);
  setup_mechanism(&mechanism, CKM_SHA256_RSA_PKCS_PSS, &pss_params, sizeof(pss_params));
  rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, modulus, sizeof(modulus), output2, &output_len2);
  assert_int_equal(rv, CKR_OK);

  rv = verify_pss_encoding(output2, output_len2, test_data, test_data_len, MBEDTLS_MD_SHA256, MBEDTLS_MD_SHA256,
                           pss_params.sLen, modulus, sizeof(modulus), CK_FALSE);
  assert_int_equal(rv, CKR_OK);
  assert_int_equal(output2[output_len2 - 1], 0xbc);
  printf("PSS encoding (raw message) verification passed\n");
}

// Test PSS padding with different salt lengths
static void test_pss_different_salt_lengths(void **state) {
  (void)state; // Unused

  CK_MECHANISM mechanism;
  CK_RSA_PKCS_PSS_PARAMS pss_params = {
      .hashAlg = CKM_SHA256,
      .mgf = CKG_MGF1_SHA256, // MGF1 with SHA-256
      .sLen = 0               // Zero salt length
  };
  CK_BYTE output[256] = {0}; // 2048 bits = 256 bytes
  CK_ULONG output_len = sizeof(output);
  CK_RV rv;

  // For CKM_RSA_PKCS_PSS, the input must be a hash value of the correct length
  // Create a SHA-256 hash of the test data to use as input
  unsigned char message_hash[32];
  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  assert_non_null(md_info);

  rv = mbedtls_md(md_info, test_data, test_data_len, message_hash);
  assert_int_equal(rv, 0);

  // Test with zero salt length
  setup_mechanism(&mechanism, CKM_RSA_PKCS_PSS, &pss_params, sizeof(pss_params));
  rv = cnk_prepare_rsa_sign_data(&mechanism, message_hash, sizeof(message_hash), modulus, sizeof(modulus), output,
                                 &output_len);
  assert_int_equal(rv, CKR_OK);

  // Test with maximum salt length
  pss_params.sLen = 32; // Max for SHA256
  memset(output, 0, sizeof(output));
  output_len = sizeof(output);

  rv = cnk_prepare_rsa_sign_data(&mechanism, message_hash, sizeof(message_hash), modulus, sizeof(modulus), output,
                                 &output_len);
  assert_int_equal(rv, CKR_OK);
}

// Test different RSA key sizes
static void test_different_rsa_key_sizes(void **state) {
  (void)state; // Unused

  CK_MECHANISM mechanism;
  CK_ULONG output_len = 512;
  CK_RV rv;

  // Setup mechanism for PKCS#1 v1.5
  setup_mechanism(&mechanism, CKM_RSA_PKCS, NULL, 0);

  // Test with 2048-bit key
  rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, NULL, 256, NULL, &output_len);
  assert_int_equal(rv, CKR_OK);
  assert_int_equal(output_len, 256); // 2048 bits = 256 bytes

  // Test with 3072-bit key
  output_len = 512;
  rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, NULL, 384, NULL, &output_len);
  assert_int_equal(rv, CKR_OK);
  assert_int_equal(output_len, 384); // 3072 bits = 384 bytes

  // Test with 4096-bit key
  output_len = 512;
  rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, NULL, 512, NULL, &output_len);
  assert_int_equal(rv, CKR_OK);
  assert_int_equal(output_len, 512); // 4096 bits = 512 bytes
}

// Test error conditions
static void test_error_conditions(void **state) {
  (void)state; // Unused

  CK_MECHANISM mechanism;
  CK_BYTE output[256] = {0};
  CK_ULONG output_len = sizeof(output);
  CK_RV rv;

  // Test invalid mechanism
  setup_mechanism(&mechanism, CKM_VENDOR_DEFINED, NULL, 0);
  rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, NULL, 256, NULL, &output_len);
  assert_int_equal(rv, CKR_MECHANISM_INVALID);

  // Test PSS with missing parameters
  setup_mechanism(&mechanism, CKM_RSA_PKCS_PSS, NULL, 0);
  rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, NULL, 256, NULL, &output_len);
  assert_int_equal(rv, CKR_ARGUMENTS_BAD);

  // Test PSS with invalid MGF
  CK_RSA_PKCS_PSS_PARAMS pss_params = {.hashAlg = CKM_SHA256,
                                       .mgf = 99, // Invalid MGF
                                       .sLen = 32};
  setup_mechanism(&mechanism, CKM_RSA_PKCS_PSS, &pss_params, sizeof(pss_params));
  rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, modulus, sizeof(modulus), NULL, &output_len);
  assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);

  // Test PSS with invalid hash algorithm
  pss_params.mgf = 1;                      // Valid MGF
  pss_params.hashAlg = CKM_VENDOR_DEFINED; // Invalid hash
  setup_mechanism(&mechanism, CKM_RSA_PKCS_PSS, &pss_params, sizeof(pss_params));
  rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, modulus, sizeof(modulus), NULL, &output_len);
  assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);
}

// Main function to run all tests
int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_x509_padding),
      cmocka_unit_test(test_pkcs1_v1_5_direct_padding),
      cmocka_unit_test(test_pkcs1_v1_5_sha1_padding),
      cmocka_unit_test(test_pkcs1_v1_5_sha256_padding),
      cmocka_unit_test(test_pss_padding),
      cmocka_unit_test(test_pss_different_salt_lengths),
      cmocka_unit_test(test_different_rsa_key_sizes),
      cmocka_unit_test(test_error_conditions),
  };

  C_CNK_ConfigLogging(CNK_LOG_LEVEL_DEBUG, NULL);

  return cmocka_run_group_tests(tests, NULL, NULL);
}
