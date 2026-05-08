#include "internal/des.h"

#include <stddef.h>
#include <stdint.h>

static const uint8_t IP[] = {58, 50, 42, 34, 26, 18, 10, 2,  60, 52, 44, 36, 28, 20, 12, 4,  62, 54, 46, 38, 30, 22,
                             14, 6,  64, 56, 48, 40, 32, 24, 16, 8,  57, 49, 41, 33, 25, 17, 9,  1,  59, 51, 43, 35,
                             27, 19, 11, 3,  61, 53, 45, 37, 29, 21, 13, 5,  63, 55, 47, 39, 31, 23, 15, 7};

static const uint8_t FP[] = {40, 8,  48, 16, 56, 24, 64, 32, 39, 7,  47, 15, 55, 23, 63, 31, 38, 6,  46, 14, 54, 22,
                             62, 30, 37, 5,  45, 13, 53, 21, 61, 29, 36, 4,  44, 12, 52, 20, 60, 28, 35, 3,  43, 11,
                             51, 19, 59, 27, 34, 2,  42, 10, 50, 18, 58, 26, 33, 1,  41, 9,  49, 17, 57, 25};

static const uint8_t EXPANSION[] = {32, 1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,  8,  9,  10, 11,
                                    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
                                    22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};

static const uint8_t P[] = {16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
                            2,  8, 24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25};

static const uint8_t PC1[] = {57, 49, 41, 33, 25, 17, 9,  1,  58, 50, 42, 34, 26, 18, 10, 2,  59, 51, 43,
                              35, 27, 19, 11, 3,  60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7,  62, 54,
                              46, 38, 30, 22, 14, 6,  61, 53, 45, 37, 29, 21, 13, 5,  28, 20, 12, 4};

static const uint8_t PC2[] = {14, 17, 11, 24, 1,  5,  3,  28, 15, 6,  21, 10, 23, 19, 12, 4,
                              26, 8,  16, 7,  27, 20, 13, 2,  41, 52, 31, 37, 47, 55, 30, 40,
                              51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};

static const uint8_t SHIFTS[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

static const uint8_t SBOX[8][64] = {
    {14, 4,  13, 1, 2,  15, 11, 8, 3, 10, 6, 12, 5,  9,  0,  7,  0,  15, 7,  4,  14, 2,
     13, 1,  10, 6, 12, 11, 9,  5, 3, 8,  4, 1,  14, 8,  13, 6,  2,  11, 15, 12, 9,  7,
     3,  10, 5,  0, 15, 12, 8,  2, 4, 9,  1, 7,  5,  11, 3,  14, 10, 0,  6,  13},
    {15, 1,  8, 14, 6,  11, 3,  4, 9, 7, 2,  13, 12, 0, 5, 10, 3,  13, 4,  7, 15, 2,  8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0,  14, 7, 11, 10, 4,  13, 1, 5, 8, 12, 6,  9,  3, 2, 15, 13, 8,  10, 1, 3,  15, 4, 2,  11, 6, 7, 12, 0, 5, 14, 9},
    {10, 0,  9,  14, 6, 3,  15, 5,  1,  13, 12, 7, 11, 4,  2,  8,  13, 7, 0,  9, 3, 4,
     6,  10, 2,  8,  5, 14, 12, 11, 15, 1,  13, 6, 4,  9,  8,  15, 3,  0, 11, 1, 2, 12,
     5,  10, 14, 7,  1, 10, 13, 0,  6,  9,  8,  7, 4,  15, 14, 3,  11, 5, 2,  12},
    {7, 13, 14, 3, 0, 6,  9, 10, 1,  2, 8,  5, 11, 12, 4,  15, 13, 8,  11, 5, 6, 15,
     0, 3,  4,  7, 2, 12, 1, 10, 14, 9, 10, 6, 9,  0,  12, 11, 7,  13, 15, 1, 3, 14,
     5, 2,  8,  4, 3, 15, 0, 6,  10, 1, 13, 8, 9,  4,  5,  11, 12, 7,  2,  14},
    {2,  12, 4, 1,  7,  10, 11, 6, 8, 5,  3, 15, 13, 0,  14, 9,  14, 11, 2,  12, 4,  7,
     13, 1,  5, 0,  15, 10, 3,  9, 8, 6,  4, 2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,
     6,  3,  0, 14, 11, 8,  12, 7, 1, 14, 2, 13, 6,  15, 0,  9,  10, 4,  5,  3},
    {12, 1,  10, 15, 9,  2,  6, 8,  0, 13, 3,  4,  14, 7,  5, 11, 10, 15, 4, 2, 7, 12,
     9,  5,  6,  1,  13, 14, 0, 11, 3, 8,  9,  14, 15, 5,  2, 8,  12, 3,  7, 0, 4, 10,
     1,  13, 11, 6,  4,  3,  2, 12, 9, 5,  15, 10, 11, 14, 1, 7,  6,  0,  8, 13},
    {4, 11, 2,  14, 15, 0, 8, 13, 3,  12, 9, 7, 5, 10, 6, 1, 13, 0,  11, 7, 4, 9, 1,  10, 14, 3, 5, 12, 2,  15, 8, 6,
     1, 4,  11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5,  9, 2, 6,  11, 13, 8, 1, 4, 10, 7,  9,  5, 0, 15, 14, 2,  3, 12},
    {13, 2, 8, 4, 6,  15, 11, 1, 10, 9,  3,  14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7,  4,  12, 5, 6, 11, 0, 14, 9, 2, 7,
     11, 4, 1, 9, 12, 14, 2,  0, 6,  10, 13, 15, 3, 5, 8,  2, 1, 14, 7,  4, 10, 8, 13, 15, 12, 9, 0, 3,  5, 6,  11}};

static uint64_t load_be64(const CK_BYTE input[8]) {
  uint64_t value = 0;
  for (size_t i = 0; i < 8; i++)
    value = (value << 8) | input[i];
  return value;
}

static void store_be64(uint64_t value, CK_BYTE output[8]) {
  for (size_t i = 0; i < 8; i++)
    output[7 - i] = (CK_BYTE)(value >> (i * 8));
}

static uint64_t permute(uint64_t input, const uint8_t *table, size_t len, uint8_t inputBits) {
  uint64_t output = 0;
  for (size_t i = 0; i < len; i++) {
    output <<= 1;
    output |= (input >> (inputBits - table[i])) & 1u;
  }
  return output;
}

static uint32_t rotate_left28(uint32_t value, uint8_t bits) {
  return ((value << bits) | (value >> (28 - bits))) & 0x0FFFFFFFu;
}

static void zeroize(void *ptr, size_t len) {
  volatile CK_BYTE *p = (volatile CK_BYTE *)ptr;
  while (len-- > 0)
    *p++ = 0;
}

static void make_subkeys(const CK_BYTE key[8], uint64_t subkeys[16]) {
  const uint64_t permuted = permute(load_be64(key), PC1, sizeof(PC1), 64);
  uint32_t c = (uint32_t)((permuted >> 28) & 0x0FFFFFFFu);
  uint32_t d = (uint32_t)(permuted & 0x0FFFFFFFu);

  for (size_t i = 0; i < 16; i++) {
    c = rotate_left28(c, SHIFTS[i]);
    d = rotate_left28(d, SHIFTS[i]);
    subkeys[i] = permute(((uint64_t)c << 28) | d, PC2, sizeof(PC2), 56);
  }
}

static uint32_t des_f(uint32_t r, uint64_t subkey) {
  const uint64_t expanded = permute(r, EXPANSION, sizeof(EXPANSION), 32) ^ subkey;
  uint32_t sboxOutput = 0;

  for (size_t i = 0; i < 8; i++) {
    const uint8_t chunk = (uint8_t)((expanded >> (42 - (6 * i))) & 0x3Fu);
    const uint8_t row = (uint8_t)(((chunk & 0x20u) >> 4) | (chunk & 0x01u));
    const uint8_t column = (uint8_t)((chunk >> 1) & 0x0Fu);
    sboxOutput = (sboxOutput << 4) | SBOX[i][row * 16 + column];
  }

  return (uint32_t)permute(sboxOutput, P, sizeof(P), 32);
}

static void des_crypt_block(const CK_BYTE key[8], const CK_BYTE input[8], CK_BYTE output[8], CK_BBOOL decrypt) {
  uint64_t subkeys[16];
  uint64_t block;
  uint32_t left;
  uint32_t right;

  make_subkeys(key, subkeys);
  block = permute(load_be64(input), IP, sizeof(IP), 64);
  left = (uint32_t)(block >> 32);
  right = (uint32_t)block;

  for (size_t i = 0; i < 16; i++) {
    const uint64_t subkey = decrypt ? subkeys[15 - i] : subkeys[i];
    const uint32_t previousRight = right;
    right = left ^ des_f(right, subkey);
    left = previousRight;
  }

  block = permute(((uint64_t)right << 32) | left, FP, sizeof(FP), 64);
  store_be64(block, output);
  zeroize(subkeys, sizeof(subkeys));
}

CK_RV cnk_des3_encrypt_block(const CK_BYTE key[24], const CK_BYTE input[8], CK_BYTE output[8]) {
  CK_BYTE first[8];
  CK_BYTE second[8];

  if (key == NULL || input == NULL || output == NULL)
    return CKR_ARGUMENTS_BAD;

  des_crypt_block(key, input, first, CK_FALSE);
  des_crypt_block(key + 8, first, second, CK_TRUE);
  des_crypt_block(key + 16, second, output, CK_FALSE);

  zeroize(first, sizeof(first));
  zeroize(second, sizeof(second));
  return CKR_OK;
}
