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
  CNK_PKCS11_SESSION session = {0};
  CNK_PIV_IMPORT material = {0};
  assert_int_equal(cnk_prepare_piv_import(&session, attributes, 5, 1, CKK_RSA, &material), CKR_KEY_SIZE_RANGE);
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
  CNK_PKCS11_SESSION session = {0};
  CNK_PIV_IMPORT material = {0};
  assert_int_equal(cnk_prepare_piv_import(&session, attributes, 5, 1, CKK_RSA, &material), CKR_KEY_SIZE_RANGE);
}

static void test_rsa_import_retains_order_and_omitted_leading_zero(void **state) {
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
  CNK_PKCS11_SESSION session = {0};
  CNK_PIV_IMPORT material = {0};
  assert_int_equal(cnk_prepare_piv_import(&session, attributes, 5, 1, CKK_RSA, &material), CKR_OK);
  assert_int_equal(material.parameters.algorithm, CNK_LIBCANO_ALG_RSA_2048);
  assert_int_equal(material.count, 5);
  for (size_t i = 0; i < 5; ++i) {
    assert_ptr_equal(material.components[i].data, attributes[i].pValue);
    assert_int_equal(material.components[i].len, attributes[i].ulValueLen);
  }
  assert_int_equal(material.parameters.pin_policy, CNK_PIV_PIN_POLICY_ONCE);
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
  CNK_PKCS11_SESSION session = {0};
  CNK_PIV_IMPORT material = {0};
  assert_int_equal(cnk_prepare_piv_import(&session, attributes, 2, 1, CKK_EC, &material), CKR_OK);
  assert_int_equal(material.parameters.algorithm, CNK_LIBCANO_ALG_P256);
  assert_int_equal(material.count, 1);
  assert_ptr_equal(material.components[0].data, material.scalar);
  assert_int_equal(material.components[0].len, 32);
  assert_int_equal(material.scalar[0], 0);
  assert_memory_equal(material.scalar + 1, scalar, sizeof(scalar));
  assert_memory_equal(attributes[1].pValue, scalar, sizeof(scalar));
}

static void test_import_uses_semantic_algorithm_with_remapped_ids(void **state) {
  (void)state;
  CNK_PKCS11_SESSION session = {.mldsa65Algorithm = 0xD1, .x25519Algorithm = 0xD2};
  CNK_PIV_IMPORT material = {0};
  CK_BYTE seed[32] = {0x42};
  CK_ULONG parameterSet = CKP_ML_DSA_65;
  CK_ATTRIBUTE attributes[] = {{CKA_SEED, seed, sizeof(seed)},
                               {CKA_PARAMETER_SET, &parameterSet, sizeof(parameterSet)}};
  assert_int_equal(cnk_prepare_piv_import(&session, attributes, 2, 1, CKK_ML_DSA, &material), CKR_OK);
  assert_int_equal(material.parameters.algorithm, CNK_LIBCANO_ALG_MLDSA65);
  assert_memory_equal(material.components[0].data, seed, sizeof(seed));
  session.mldsa65Algorithm = 0;
  assert_int_equal(cnk_prepare_piv_import(&session, attributes, 2, 1, CKK_ML_DSA, &material), CKR_MECHANISM_INVALID);
  static CK_BYTE x25519[] = {0x06, 0x03, 0x2B, 0x65, 0x6E};
  CK_ATTRIBUTE montgomery[] = {{CKA_VALUE, seed, sizeof(seed)}, {CKA_EC_PARAMS, x25519, sizeof(x25519)}};
  assert_int_equal(cnk_prepare_piv_import(&session, montgomery, 2, 1, CKK_EC_MONTGOMERY, &material), CKR_OK);
  assert_int_equal(material.parameters.algorithm, CNK_LIBCANO_ALG_X25519);
  assert_memory_equal(material.components[0].data, seed, sizeof(seed));
  assert_int_equal(cnk_prepare_piv_import(&session, montgomery, 2, 1, CKK_EC_EDWARDS, &material),
                   CKR_TEMPLATE_INCONSISTENT);
  montgomery[0].ulValueLen--;
  assert_int_equal(cnk_prepare_piv_import(&session, montgomery, 2, 1, CKK_EC_MONTGOMERY, &material),
                   CKR_ATTRIBUTE_VALUE_INVALID);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_rsa_import_rejects_ambiguous_prime_width),
      cmocka_unit_test(test_rsa_import_rejects_noncanonical_prime_width),
      cmocka_unit_test(test_rsa_import_retains_order_and_omitted_leading_zero),
      cmocka_unit_test(test_ec_import_pads_omitted_leading_zero),
      cmocka_unit_test(test_import_uses_semantic_algorithm_with_remapped_ids),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
