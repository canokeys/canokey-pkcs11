// clang-format off
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
// clang-format on

#include "backend/pcsc.h"
#include "internal/piv_object.h"
#include "pkcs11.h"

#include <string.h>

static void test_rsa_import_rejects_ambiguous_prime_width(void **state) {
  (void)state;
  CK_BYTE components[5][64];
  memset(components, 0x01, sizeof(components));
  CK_ATTRIBUTE attributes[] = {
      {CKA_PRIME_1, components[0], sizeof(components[0])},     {CKA_PRIME_2, components[1], sizeof(components[1])},
      {CKA_EXPONENT_1, components[2], sizeof(components[2])},  {CKA_EXPONENT_2, components[3], sizeof(components[3])},
      {CKA_COEFFICIENT, components[4], sizeof(components[4])},
  };
  CK_BYTE output[2048];
  CK_ULONG written = 0;
  CK_BYTE algorithm = 0;
  assert_int_equal(cnk_build_piv_rsa_import(attributes, 5, 1, output, sizeof(output), &written, &algorithm),
                   CKR_KEY_SIZE_RANGE);
}

static void test_rsa_import_rejects_noncanonical_prime_width(void **state) {
  (void)state;
  CK_BYTE prime1[129];
  CK_BYTE prime2[129];
  CK_BYTE exponent1[3] = {1, 0, 1};
  CK_BYTE exponent2[3] = {1, 0, 1};
  CK_BYTE coefficient[129];
  memset(prime1, 0x11, sizeof(prime1));
  memset(prime2, 0x22, sizeof(prime2));
  memset(coefficient, 0x33, sizeof(coefficient));
  CK_ATTRIBUTE attributes[] = {
      {CKA_PRIME_1, prime1, sizeof(prime1)},
      {CKA_PRIME_2, prime2, sizeof(prime2)},
      {CKA_EXPONENT_1, exponent1, sizeof(exponent1)},
      {CKA_EXPONENT_2, exponent2, sizeof(exponent2)},
      {CKA_COEFFICIENT, coefficient, sizeof(coefficient)},
  };
  CK_BYTE output[2048];
  CK_ULONG written = 0;
  CK_BYTE algorithm = 0;
  assert_int_equal(cnk_build_piv_rsa_import(attributes, 5, 1, output, sizeof(output), &written, &algorithm),
                   CKR_KEY_SIZE_RANGE);
}

static void test_rsa_import_pads_omitted_leading_zero(void **state) {
  (void)state;
  CK_BYTE prime1[127];
  CK_BYTE prime2[128];
  CK_BYTE exponent1[3] = {1, 0, 1};
  CK_BYTE exponent2[3] = {1, 0, 1};
  CK_BYTE coefficient[128];
  memset(prime1, 0x11, sizeof(prime1));
  memset(prime2, 0x22, sizeof(prime2));
  memset(coefficient, 0x33, sizeof(coefficient));
  CK_ATTRIBUTE attributes[] = {
      {CKA_PRIME_1, prime1, sizeof(prime1)},
      {CKA_PRIME_2, prime2, sizeof(prime2)},
      {CKA_EXPONENT_1, exponent1, sizeof(exponent1)},
      {CKA_EXPONENT_2, exponent2, sizeof(exponent2)},
      {CKA_COEFFICIENT, coefficient, sizeof(coefficient)},
  };
  CK_BYTE output[2048];
  CK_ULONG written = 0;
  CK_BYTE algorithm = 0;
  assert_int_equal(cnk_build_piv_rsa_import(attributes, 5, 1, output, sizeof(output), &written, &algorithm), CKR_OK);
  assert_int_equal(algorithm, PIV_ALG_RSA_2048);
  assert_int_equal(output[0], 0x01);
  assert_int_equal(output[1], 0x81);
  assert_int_equal(output[2], 0x80);
  assert_int_equal(output[3], 0x00);
}

static void test_ec_import_pads_omitted_leading_zero(void **state) {
  (void)state;
  static const CK_BYTE p256[] = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
  CK_BYTE scalar[31];
  memset(scalar, 0x44, sizeof(scalar));
  CK_ATTRIBUTE attributes[] = {
      {CKA_EC_PARAMS, (CK_BYTE_PTR)p256, sizeof(p256)},
      {CKA_VALUE, scalar, sizeof(scalar)},
  };
  CK_BYTE output[256];
  CK_ULONG written = 0;
  CK_BYTE algorithm = 0;
  assert_int_equal(cnk_build_piv_ec_import(attributes, 2, 1, output, sizeof(output), &written, &algorithm), CKR_OK);
  assert_int_equal(algorithm, PIV_ALG_ECC_256);
  assert_int_equal(output[0], 0x06);
  assert_int_equal(output[1], 0x20);
  assert_int_equal(output[2], 0x00);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_rsa_import_rejects_ambiguous_prime_width),
      cmocka_unit_test(test_rsa_import_rejects_noncanonical_prime_width),
      cmocka_unit_test(test_rsa_import_pads_omitted_leading_zero),
      cmocka_unit_test(test_ec_import_pads_omitted_leading_zero),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
