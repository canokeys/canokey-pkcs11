// clang-format off
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
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
static size_t test_data_len = sizeof(test_data) - 1; // Length of test_data

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

// Helper function to verify PKCS#1 v1.5 padding structure
static void verify_pkcs1_v1_5_padding(CK_BYTE *output, CK_ULONG outputSize, CK_BYTE *expectedData, CK_ULONG dataSize,
                                      CK_BYTE *derPrefix, CK_ULONG derSize) {
  // Verify basic structure: 0x00 | 0x01 | PS | 0x00 | [DER] | Data
  assert_int_equal(output[0], 0x00);
  assert_int_equal(output[1], 0x01);

  // Find the separator byte (after PS)
  size_t i = 2;
  while (i < outputSize && output[i] == 0xFF) {
    i++;
  }

  // Verify separator byte
  assert_int_equal(output[i], 0x00);
  i++;

  // Verify DER prefix if provided
  if (derPrefix && derSize > 0) {
    assert_memory_equal(output + i, derPrefix, derSize);
    i += derSize;
  }

  // Verify data
  assert_memory_equal(output + i, expectedData, dataSize);
}

// Test pkcs1_v1_5_pad with no digest algorithm (raw data)
static void test_pkcs1_v1_5_pad_no_digest(void **state) {
  (void)state; // Unused

  // Arrange
  CK_BYTE inputData[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A};
  const CK_ULONG inputSize = sizeof(inputData);
  CK_BYTE output[256] = {0};
  CK_ULONG outputSize = sizeof(output);

  // Act: Test with null digest (direct data padding)
  CK_RV rv = pkcs1_v1_5_pad(inputData, inputSize, output, outputSize, MBEDTLS_MD_NONE);

  // Assert
  assert_int_equal(rv, CKR_OK);

  // Verify padding structure
  verify_pkcs1_v1_5_padding(output, outputSize, inputData, inputSize, NULL, 0);
}

// Test pkcs1_v1_5_pad with SHA-1
static void test_pkcs1_v1_5_pad_sha1(void **state) {
  (void)state; // Unused

  // Arrange
  CK_BYTE inputData[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                         0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14};
  const CK_ULONG inputSize = sizeof(inputData);
  CK_BYTE output[256] = {0};
  CK_ULONG outputSize = sizeof(output);

  // SHA-1 DER prefix
  const CK_BYTE expected_sha1_prefix[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
                                          0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};

  // Act: Test with SHA-1
  CK_RV rv = pkcs1_v1_5_pad(inputData, inputSize, output, outputSize, MBEDTLS_MD_SHA1);

  // Assert
  assert_int_equal(rv, CKR_OK);

  // Verify padding structure with SHA-1 DER prefix
  verify_pkcs1_v1_5_padding(output, outputSize, inputData, inputSize, (CK_BYTE *)expected_sha1_prefix,
                            sizeof(expected_sha1_prefix));
}

// Test pkcs1_v1_5_pad with SHA-224
static void test_pkcs1_v1_5_pad_sha224(void **state) {
  (void)state; // Unused

  // Arrange
  CK_BYTE inputData[28]; // SHA-224 outputs 28 bytes
  for (CK_ULONG i = 0; i < sizeof(inputData); i++) {
    inputData[i] = (CK_BYTE)i;
  }
  const CK_ULONG inputSize = sizeof(inputData);
  CK_BYTE output[256] = {0};
  CK_ULONG outputSize = sizeof(output);

  // SHA-224 DER prefix
  const CK_BYTE expected_sha224_prefix[] = {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                            0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c};

  // Act: Test with SHA-224
  CK_RV rv = pkcs1_v1_5_pad(inputData, inputSize, output, outputSize, MBEDTLS_MD_SHA224);

  // Assert
  assert_int_equal(rv, CKR_OK);

  // Verify padding structure with SHA-224 DER prefix
  verify_pkcs1_v1_5_padding(output, outputSize, inputData, inputSize, (CK_BYTE *)expected_sha224_prefix,
                            sizeof(expected_sha224_prefix));
}

// Test pkcs1_v1_5_pad with SHA-256
static void test_pkcs1_v1_5_pad_sha256(void **state) {
  (void)state; // Unused

  // Arrange
  CK_BYTE inputData[32]; // SHA-256 outputs 32 bytes
  for (CK_ULONG i = 0; i < sizeof(inputData); i++) {
    inputData[i] = (CK_BYTE)i;
  }
  const CK_ULONG inputSize = sizeof(inputData);
  CK_BYTE output[256] = {0};
  CK_ULONG outputSize = sizeof(output);

  // SHA-256 DER prefix
  const CK_BYTE expected_sha256_prefix[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                            0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};

  // Act: Test with SHA-256
  CK_RV rv = pkcs1_v1_5_pad(inputData, inputSize, output, outputSize, MBEDTLS_MD_SHA256);

  // Assert
  assert_int_equal(rv, CKR_OK);

  // Verify padding structure with SHA-256 DER prefix
  verify_pkcs1_v1_5_padding(output, outputSize, inputData, inputSize, (CK_BYTE *)expected_sha256_prefix,
                            sizeof(expected_sha256_prefix));
}

// Test pkcs1_v1_5_pad with SHA-384
static void test_pkcs1_v1_5_pad_sha384(void **state) {
  (void)state; // Unused

  // Arrange
  CK_BYTE inputData[48]; // SHA-384 outputs 48 bytes
  for (CK_ULONG i = 0; i < sizeof(inputData); i++) {
    inputData[i] = (CK_BYTE)i;
  }
  const CK_ULONG inputSize = sizeof(inputData);
  CK_BYTE output[256] = {0};
  CK_ULONG outputSize = sizeof(output);

  // SHA-384 DER prefix
  const CK_BYTE expected_sha384_prefix[] = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                            0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};

  // Act: Test with SHA-384
  CK_RV rv = pkcs1_v1_5_pad(inputData, inputSize, output, outputSize, MBEDTLS_MD_SHA384);

  // Assert
  assert_int_equal(rv, CKR_OK);

  // Verify padding structure with SHA-384 DER prefix
  verify_pkcs1_v1_5_padding(output, outputSize, inputData, inputSize, (CK_BYTE *)expected_sha384_prefix,
                            sizeof(expected_sha384_prefix));
}

// Test pkcs1_v1_5_pad with SHA-512
static void test_pkcs1_v1_5_pad_sha512(void **state) {
  (void)state; // Unused

  // Arrange
  CK_BYTE inputData[64]; // SHA-512 outputs 64 bytes
  for (CK_ULONG i = 0; i < sizeof(inputData); i++) {
    inputData[i] = (CK_BYTE)i;
  }
  const CK_ULONG inputSize = sizeof(inputData);
  CK_BYTE output[256] = {0};
  CK_ULONG outputSize = sizeof(output);

  // SHA-512 DER prefix
  const CK_BYTE expected_sha512_prefix[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                            0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};

  // Act: Test with SHA-512
  CK_RV rv = pkcs1_v1_5_pad(inputData, inputSize, output, outputSize, MBEDTLS_MD_SHA512);

  // Assert
  assert_int_equal(rv, CKR_OK);

  // Verify padding structure with SHA-512 DER prefix
  verify_pkcs1_v1_5_padding(output, outputSize, inputData, inputSize, (CK_BYTE *)expected_sha512_prefix,
                            sizeof(expected_sha512_prefix));
}

// Test pkcs1_v1_5_pad with SHA3-224
static void test_pkcs1_v1_5_pad_sha3_224(void **state) {
  (void)state; // Unused

  // Arrange
  CK_BYTE inputData[28]; // SHA3-224 outputs 28 bytes
  for (CK_ULONG i = 0; i < sizeof(inputData); i++) {
    inputData[i] = (CK_BYTE)i;
  }
  const CK_ULONG inputSize = sizeof(inputData);
  CK_BYTE output[256] = {0};
  CK_ULONG outputSize = sizeof(output);

  // SHA3-224 DER prefix
  const CK_BYTE expected_sha3_224_prefix[] = {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                              0x65, 0x03, 0x04, 0x02, 0x07, 0x05, 0x00, 0x04, 0x1c};

  // Act: Test with SHA3-224
  CK_RV rv = pkcs1_v1_5_pad(inputData, inputSize, output, outputSize, MBEDTLS_MD_SHA3_224);

  // Assert
  assert_int_equal(rv, CKR_OK);

  // Verify padding structure with SHA3-224 DER prefix
  verify_pkcs1_v1_5_padding(output, outputSize, inputData, inputSize, (CK_BYTE *)expected_sha3_224_prefix,
                            sizeof(expected_sha3_224_prefix));
}

// Test pkcs1_v1_5_pad with SHA3-256
static void test_pkcs1_v1_5_pad_sha3_256(void **state) {
  (void)state; // Unused

  // Arrange
  CK_BYTE inputData[32]; // SHA3-256 outputs 32 bytes
  for (CK_ULONG i = 0; i < sizeof(inputData); i++) {
    inputData[i] = (CK_BYTE)i;
  }
  const CK_ULONG inputSize = sizeof(inputData);
  CK_BYTE output[256] = {0};
  CK_ULONG outputSize = sizeof(output);

  // SHA3-256 DER prefix
  const CK_BYTE expected_sha3_256_prefix[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                              0x65, 0x03, 0x04, 0x02, 0x08, 0x05, 0x00, 0x04, 0x20};

  // Act: Test with SHA3-256
  CK_RV rv = pkcs1_v1_5_pad(inputData, inputSize, output, outputSize, MBEDTLS_MD_SHA3_256);

  // Assert
  assert_int_equal(rv, CKR_OK);

  // Verify padding structure with SHA3-256 DER prefix
  verify_pkcs1_v1_5_padding(output, outputSize, inputData, inputSize, (CK_BYTE *)expected_sha3_256_prefix,
                            sizeof(expected_sha3_256_prefix));
}

// Test pkcs1_v1_5_pad with SHA3-384
static void test_pkcs1_v1_5_pad_sha3_384(void **state) {
  (void)state; // Unused

  // Arrange
  CK_BYTE inputData[48]; // SHA3-384 outputs 48 bytes
  for (CK_ULONG i = 0; i < sizeof(inputData); i++) {
    inputData[i] = (CK_BYTE)i;
  }
  const CK_ULONG inputSize = sizeof(inputData);
  CK_BYTE output[256] = {0};
  CK_ULONG outputSize = sizeof(output);

  // SHA3-384 DER prefix
  const CK_BYTE expected_sha3_384_prefix[] = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                              0x65, 0x03, 0x04, 0x02, 0x09, 0x05, 0x00, 0x04, 0x30};

  // Act: Test with SHA3-384
  CK_RV rv = pkcs1_v1_5_pad(inputData, inputSize, output, outputSize, MBEDTLS_MD_SHA3_384);

  // Assert
  assert_int_equal(rv, CKR_OK);

  // Verify padding structure with SHA3-384 DER prefix
  verify_pkcs1_v1_5_padding(output, outputSize, inputData, inputSize, (CK_BYTE *)expected_sha3_384_prefix,
                            sizeof(expected_sha3_384_prefix));
}

// Test pkcs1_v1_5_pad with SHA3-512
static void test_pkcs1_v1_5_pad_sha3_512(void **state) {
  (void)state; // Unused

  // Arrange
  CK_BYTE inputData[64]; // SHA3-512 outputs 64 bytes
  for (CK_ULONG i = 0; i < sizeof(inputData); i++) {
    inputData[i] = (CK_BYTE)i;
  }
  const CK_ULONG inputSize = sizeof(inputData);
  CK_BYTE output[256] = {0};
  CK_ULONG outputSize = sizeof(output);

  // SHA3-512 DER prefix
  const CK_BYTE expected_sha3_512_prefix[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                              0x65, 0x03, 0x04, 0x02, 0x0a, 0x05, 0x00, 0x04, 0x40};

  // Act: Test with SHA3-512
  CK_RV rv = pkcs1_v1_5_pad(inputData, inputSize, output, outputSize, MBEDTLS_MD_SHA3_512);

  // Assert
  assert_int_equal(rv, CKR_OK);

  // Verify padding structure with SHA3-512 DER prefix
  verify_pkcs1_v1_5_padding(output, outputSize, inputData, inputSize, (CK_BYTE *)expected_sha3_512_prefix,
                            sizeof(expected_sha3_512_prefix));
}

// Test buffer too small condition
static void test_pkcs1_v1_5_pad_buffer_too_small_case(void **state) {
  (void)state; // Unused

  // Arrange
  CK_BYTE inputData[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A};
  const CK_ULONG inputSize = sizeof(inputData);
  CK_BYTE smallOutput[20]; // Too small for proper padding

  // Act: Test with small buffer
  CK_RV rv = pkcs1_v1_5_pad(inputData, inputSize, smallOutput, sizeof(smallOutput), MBEDTLS_MD_NONE);

  // Assert
  assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);
}

// Test PSS encoding with SHA-1
static void test_pss_encode_sha1(void **state) {
  (void)state; // Unused

  // Arrange
  CK_BYTE hash[20];                 // SHA-1 hash size is 20 bytes
  memset(hash, 0xA1, sizeof(hash)); // Use a recognizable pattern

  CK_ULONG saltLen = 16; // Salt length for test
  CK_BYTE output[256] = {0};

  // Act: Encode the message with PSS using SHA-1
  CK_RV rv = pss_encode(hash, sizeof(hash), modulus, sizeof(modulus), saltLen, MBEDTLS_MD_SHA1, output);

  // Assert
  assert_int_equal(rv, CKR_OK);

  // The last byte must be 0xBC as per PSS encoding
  assert_int_equal(output[sizeof(modulus) - 1], 0xBC);

  // Verify the PSS encoding structure
  rv = verify_pss_encoding(output, sizeof(modulus), hash, sizeof(hash), MBEDTLS_MD_SHA1, MBEDTLS_MD_SHA1, saltLen,
                           modulus, sizeof(modulus), CK_TRUE);
  assert_int_equal(rv, CKR_OK);
}

// Test PSS encoding with SHA-256
static void test_pss_encode_sha256(void **state) {
  (void)state; // Unused

  // Arrange
  CK_BYTE hash[32];                 // SHA-256 hash size is 32 bytes
  memset(hash, 0xA2, sizeof(hash)); // Use a recognizable pattern

  CK_ULONG saltLen = 20; // Common salt length
  CK_BYTE output[256] = {0};

  // Act: Encode the message with PSS using SHA-256
  CK_RV rv = pss_encode(hash, sizeof(hash), modulus, sizeof(modulus), saltLen, MBEDTLS_MD_SHA256, output);

  // Assert
  assert_int_equal(rv, CKR_OK);

  // The last byte must be 0xBC as per PSS encoding
  assert_int_equal(output[sizeof(modulus) - 1], 0xBC);

  // Verify the PSS encoding structure
  rv = verify_pss_encoding(output, sizeof(modulus), hash, sizeof(hash), MBEDTLS_MD_SHA256, MBEDTLS_MD_SHA256, saltLen,
                           modulus, sizeof(modulus), CK_TRUE);
  assert_int_equal(rv, CKR_OK);
}

// Test PSS encoding with SHA-384
static void test_pss_encode_sha384(void **state) {
  (void)state; // Unused

  // Arrange
  CK_BYTE hash[48];                 // SHA-384 hash size is 48 bytes
  memset(hash, 0xA3, sizeof(hash)); // Use a recognizable pattern

  CK_ULONG saltLen = 24; // Salt length for test
  CK_BYTE output[256] = {0};

  // Act: Encode the message with PSS using SHA-384
  CK_RV rv = pss_encode(hash, sizeof(hash), modulus, sizeof(modulus), saltLen, MBEDTLS_MD_SHA384, output);

  // Assert
  assert_int_equal(rv, CKR_OK);

  // The last byte must be 0xBC as per PSS encoding
  assert_int_equal(output[sizeof(modulus) - 1], 0xBC);

  // Verify the PSS encoding structure
  rv = verify_pss_encoding(output, sizeof(modulus), hash, sizeof(hash), MBEDTLS_MD_SHA384, MBEDTLS_MD_SHA384, saltLen,
                           modulus, sizeof(modulus), CK_TRUE);
  assert_int_equal(rv, CKR_OK);
}

// Test PSS encoding with SHA-512
static void test_pss_encode_sha512(void **state) {
  (void)state; // Unused

  // Arrange
  CK_BYTE hash[64];                 // SHA-512 hash size is 64 bytes
  memset(hash, 0xA4, sizeof(hash)); // Use a recognizable pattern

  CK_ULONG saltLen = 32; // Salt length for test
  CK_BYTE output[256] = {0};

  // Act: Encode the message with PSS using SHA-512
  CK_RV rv = pss_encode(hash, sizeof(hash), modulus, sizeof(modulus), saltLen, MBEDTLS_MD_SHA512, output);

  // Assert
  assert_int_equal(rv, CKR_OK);

  // The last byte must be 0xBC as per PSS encoding
  assert_int_equal(output[sizeof(modulus) - 1], 0xBC);

  // Verify the PSS encoding structure
  rv = verify_pss_encoding(output, sizeof(modulus), hash, sizeof(hash), MBEDTLS_MD_SHA512, MBEDTLS_MD_SHA512, saltLen,
                           modulus, sizeof(modulus), CK_TRUE);
  assert_int_equal(rv, CKR_OK);
}

// Test PSS encoding with maximum allowed salt length (equal to hash length)
static void test_pss_encode_max_salt(void **state) {
  (void)state; // Unused

  // Arrange
  CK_BYTE hash[32]; // SHA-256 hash size is 32 bytes
  memset(hash, 0xAA, sizeof(hash));

  // Get maximum salt length (equal to hash length for SHA-256)
  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  assert_non_null(md_info);
  CK_ULONG maxSaltLen = mbedtls_md_get_size(md_info);

  CK_BYTE output[256] = {0};

  // Act: Encode the message with maximum salt length
  CK_RV rv = pss_encode(hash, sizeof(hash), modulus, sizeof(modulus), maxSaltLen, MBEDTLS_MD_SHA256, output);

  // Assert
  assert_int_equal(rv, CKR_OK);

  // The last byte must be 0xBC as per PSS encoding
  assert_int_equal(output[sizeof(modulus) - 1], 0xBC);

  // Verify the PSS encoding structure
  rv = verify_pss_encoding(output, sizeof(modulus), hash, sizeof(hash), MBEDTLS_MD_SHA256, MBEDTLS_MD_SHA256,
                           maxSaltLen, modulus, sizeof(modulus), CK_TRUE);
  assert_int_equal(rv, CKR_OK);
}

// Test PSS encoding with salt length > hash length (should fail)
static void test_pss_encode_invalid_salt(void **state) {
  (void)state; // Unused

  // Arrange
  CK_BYTE hash[32]; // SHA-256 hash size is 32 bytes
  memset(hash, 0xAA, sizeof(hash));

  // Get maximum salt length (equal to hash length for SHA-256)
  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  assert_non_null(md_info);
  CK_ULONG maxSaltLen = mbedtls_md_get_size(md_info);
  CK_ULONG invalidSaltLen = maxSaltLen + 1; // Salt length > hash length (invalid)

  CK_BYTE output[256] = {0};

  // Act: Attempt to encode with invalid salt length
  CK_RV rv = pss_encode(hash, sizeof(hash), modulus, sizeof(modulus), invalidSaltLen, MBEDTLS_MD_SHA256, output);

  // Assert: Should fail according to FIPS 186-4
  assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);
}

// Test PSS encoding with modulus too small for encoding
static void test_pss_encode_small_modulus(void **state) {
  (void)state; // Unused

  // Arrange
  CK_BYTE hash[32]; // SHA-256 hash size is 32 bytes
  memset(hash, 0xAA, sizeof(hash));

  CK_ULONG saltLen = 20; // Common salt length

  // Creating a small modulus (too small for proper PSS encoding)
  CK_BYTE smallModulus[32] = {0}; // 256-bit modulus
  memset(smallModulus, 0xFF, sizeof(smallModulus));

  CK_BYTE output[256] = {0};

  // Act: Attempt to encode with small modulus
  CK_RV rv = pss_encode(hash, sizeof(hash), smallModulus, sizeof(smallModulus), saltLen, MBEDTLS_MD_SHA256, output);

  // Assert: Should fail because emLen < hLen + sLen + 2
  assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);
}

// Test pkcs1_v1_5_pad with buffer too small error
static void test_pkcs1_v1_5_pad_buffer_too_small(void **state) {
  (void)state; // Unused parameter

  // Define test data and buffers
  CK_BYTE_PTR input = (CK_BYTE_PTR)test_data;
  CK_ULONG input_len = 32;

  // Create a small output buffer
  CK_BYTE output[10]; // Too small for input_len + 11
  CK_ULONG output_len = sizeof(output);

  // Test with SHA256
  CK_RV rv = pkcs1_v1_5_pad(input, input_len, output, output_len, MBEDTLS_MD_SHA256);

  // Expect buffer too small error
  assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);
}

// Test pkcs1_v1_5_pad with no DER encoding (MBEDTLS_MD_NONE)
static void test_pkcs1_v1_5_pad_no_der(void **state) {
  (void)state; // Unused parameter

  // Define test data and buffers
  CK_BYTE_PTR input = (CK_BYTE_PTR)test_data;
  CK_ULONG input_len = 32;

  // Output buffer large enough for padded data
  CK_BYTE output[256];
  CK_ULONG output_len = sizeof(output);

  // Test with no hash algorithm (no DER encoding)
  CK_RV rv = pkcs1_v1_5_pad(input, input_len, output, output_len, MBEDTLS_MD_NONE);

  // Should succeed
  assert_int_equal(rv, CKR_OK);

  // Verify format: 0x00 | 0x01 | PS | 0x00 | T
  assert_int_equal(output[0], 0x00);
  assert_int_equal(output[1], 0x01);

  // Find the 0x00 separator
  CK_ULONG separator_pos = 0;
  for (CK_ULONG i = 2; i < output_len - input_len; i++) {
    if (output[i] == 0x00) {
      separator_pos = i;
      break;
    }
  }

  // Verify separator exists and is followed by raw data (no DER)
  assert_true(separator_pos > 0);

  // Verify padding is all 0xFF
  for (CK_ULONG i = 2; i < separator_pos; i++) {
    assert_int_equal(output[i], 0xFF);
  }

  // Verify input data was copied correctly
  assert_memory_equal(input, &output[separator_pos + 1], input_len);
}

// Test pkcs1_v1_5_pad with various hash algorithms
static void test_pkcs1_v1_5_pad_hash_algorithms(void **state) {
  (void)state; // Unused parameter

  // Define test data and buffers
  CK_BYTE_PTR input = (CK_BYTE_PTR)test_data;
  CK_ULONG input_len = 20; // SHA1 hash length

  // Output buffer large enough for padded data
  CK_BYTE output[256];
  CK_ULONG output_len = sizeof(output);

  // Test array of hash algorithms
  mbedtls_md_type_t hash_types[] = {MBEDTLS_MD_SHA1,     MBEDTLS_MD_SHA224,   MBEDTLS_MD_SHA256,
                                    MBEDTLS_MD_SHA384,   MBEDTLS_MD_SHA512,   MBEDTLS_MD_SHA3_224,
                                    MBEDTLS_MD_SHA3_256, MBEDTLS_MD_SHA3_384, MBEDTLS_MD_SHA3_512};

  for (CK_ULONG i = 0; i < sizeof(hash_types) / sizeof(hash_types[0]); i++) {
    // Clear output buffer
    memset(output, 0, output_len);

    // Apply padding with current hash algorithm
    CK_RV rv = pkcs1_v1_5_pad(input, input_len, output, output_len, hash_types[i]);

    // Should succeed
    assert_int_equal(rv, CKR_OK);

    // Basic structure verification
    assert_int_equal(output[0], 0x00);
    assert_int_equal(output[1], 0x01);
  }
}

// Test pss_encode with different salt lengths
static void test_pss_encode_salt_lengths(void **state) {
  (void)state; // Unused parameter

  // Create a hash (SHA-256)
  CK_BYTE hash[32];
  CK_ULONG hash_len = sizeof(hash);

  // Generate a hash value
  for (CK_ULONG i = 0; i < hash_len; i++) {
    hash[i] = (CK_BYTE)i;
  }

  // Prepare output buffer
  CK_BYTE output[256];

  // Test with various salt lengths
  CK_ULONG salt_lengths[] = {0, 8, 16, 32};

  for (CK_ULONG i = 0; i < sizeof(salt_lengths) / sizeof(salt_lengths[0]); i++) {
    CK_ULONG salt_len = salt_lengths[i];

    // Skip if salt_len > hash_len (invalid case, tested separately)
    if (salt_len > hash_len)
      continue;

    // Clear output buffer
    memset(output, 0, sizeof(output));

    // Encode with current salt length
    CK_RV rv = pss_encode(hash, hash_len, modulus, sizeof(modulus), salt_len, MBEDTLS_MD_SHA256, output);

    // Should succeed
    assert_int_equal(rv, CKR_OK);

    // Verify trailer byte (last byte should be 0xBC)
    assert_int_equal(output[sizeof(modulus) - 1], 0xBC);
  }
}

// Test pss_encode with error conditions
static void test_pss_encode_errors(void **state) {
  (void)state; // Unused parameter

  // Create a hash (SHA-256)
  CK_BYTE hash[32];
  CK_ULONG hash_len = sizeof(hash);

  // Generate a hash value
  for (CK_ULONG i = 0; i < hash_len; i++) {
    hash[i] = (CK_BYTE)i;
  }

  // Prepare output buffer
  CK_BYTE output[256];

  // Test 1: Hash length doesn't match MD type
  CK_RV rv = pss_encode(hash, hash_len - 1, modulus, sizeof(modulus), 20, MBEDTLS_MD_SHA256, output);
  assert_int_equal(rv, CKR_DATA_LEN_RANGE);

  // Test 2: Salt length > hash length (should fail)
  rv = pss_encode(hash, hash_len, modulus, sizeof(modulus), hash_len + 1, MBEDTLS_MD_SHA256, output);
  assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);
}

// Test pss_encode with different hash algorithms
static void test_pss_encode_hash_algorithms(void **state) {
  (void)state; // Unused parameter

  // Prepare different hash outputs for different algorithms
  CK_BYTE hash_sha1[20];
  CK_BYTE hash_sha256[32];
  CK_BYTE hash_sha384[48];
  CK_BYTE hash_sha512[64];

  // Initialize hash values (normally these would be real hash outputs)
  memset(hash_sha1, 0xA1, sizeof(hash_sha1));
  memset(hash_sha256, 0xA2, sizeof(hash_sha256));
  memset(hash_sha384, 0xA3, sizeof(hash_sha384));
  memset(hash_sha512, 0xA4, sizeof(hash_sha512));

  // Prepare output buffer
  CK_BYTE output[256];

  // Test with SHA-1
  CK_RV rv = pss_encode(hash_sha1, sizeof(hash_sha1), modulus, sizeof(modulus), 10, MBEDTLS_MD_SHA1, output);
  assert_int_equal(rv, CKR_OK);

  // Test with SHA-256
  rv = pss_encode(hash_sha256, sizeof(hash_sha256), modulus, sizeof(modulus), 10, MBEDTLS_MD_SHA256, output);
  assert_int_equal(rv, CKR_OK);

  // Test with SHA-384
  rv = pss_encode(hash_sha384, sizeof(hash_sha384), modulus, sizeof(modulus), 10, MBEDTLS_MD_SHA384, output);
  assert_int_equal(rv, CKR_OK);

  // Test with SHA-512
  rv = pss_encode(hash_sha512, sizeof(hash_sha512), modulus, sizeof(modulus), 10, MBEDTLS_MD_SHA512, output);
  assert_int_equal(rv, CKR_OK);
}

// Main function to run all tests
int main(void) {
  const struct CMUnitTest tests[] = {
      // PKCS#1 v1.5 individual digest algorithm tests
      cmocka_unit_test(test_pkcs1_v1_5_pad_no_digest),
      cmocka_unit_test(test_pkcs1_v1_5_pad_sha1),
      cmocka_unit_test(test_pkcs1_v1_5_pad_sha224),
      cmocka_unit_test(test_pkcs1_v1_5_pad_sha256),
      cmocka_unit_test(test_pkcs1_v1_5_pad_sha384),
      cmocka_unit_test(test_pkcs1_v1_5_pad_sha512),
      cmocka_unit_test(test_pkcs1_v1_5_pad_sha3_224),
      cmocka_unit_test(test_pkcs1_v1_5_pad_sha3_256),
      cmocka_unit_test(test_pkcs1_v1_5_pad_sha3_384),
      cmocka_unit_test(test_pkcs1_v1_5_pad_sha3_512),
      cmocka_unit_test(test_pkcs1_v1_5_pad_buffer_too_small_case),

      // PSS encoding tests
      cmocka_unit_test(test_pss_encode_sha1),
      cmocka_unit_test(test_pss_encode_sha256),
      cmocka_unit_test(test_pss_encode_sha384),
      cmocka_unit_test(test_pss_encode_sha512),
      cmocka_unit_test(test_pss_encode_max_salt),
      cmocka_unit_test(test_pss_encode_invalid_salt),
      cmocka_unit_test(test_pss_encode_small_modulus),

      // Other test functions
      cmocka_unit_test(test_pkcs1_v1_5_pad_buffer_too_small),
      cmocka_unit_test(test_pkcs1_v1_5_pad_no_der),
      cmocka_unit_test(test_pkcs1_v1_5_pad_hash_algorithms),
      cmocka_unit_test(test_pss_encode_salt_lengths),
      cmocka_unit_test(test_pss_encode_errors),
      cmocka_unit_test(test_pss_encode_hash_algorithms),
  };

  C_CNK_ConfigLogging(CNK_LOG_LEVEL_DEBUG, NULL);
  return cmocka_run_group_tests(tests, NULL, NULL);
}
