// clang-format off
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
// clang-format on

#include "api/object.h"
#include "backend/pcsc.h"
#include "internal/template.h"
#include "pkcs11.h"
#include "pkcs11_canokey.h"

static void test_default_policy_for_slots(void **state) {
  (void)state;

  assert_int_equal(CNK_DefaultPinPolicyForPivObjectId(PIV_SLOT_9E), CNK_PIV_PIN_POLICY_NEVER);
  assert_int_equal(CNK_DefaultPinPolicyForPivObjectId(PIV_SLOT_9A), CNK_PIV_PIN_POLICY_ONCE);
  assert_int_equal(CNK_DefaultPinPolicyForPivObjectId(PIV_SLOT_9C), CNK_PIV_PIN_POLICY_ONCE);
  assert_int_equal(CNK_DefaultPinPolicyForPivObjectId(PIV_SLOT_9D), CNK_PIV_PIN_POLICY_ONCE);
  assert_int_equal(CNK_DefaultPinPolicyForPivObjectId(PIV_SLOT_82), CNK_PIV_PIN_POLICY_ONCE);
  assert_int_equal(CNK_DefaultPinPolicyForPivObjectId(PIV_SLOT_83), CNK_PIV_PIN_POLICY_ONCE);
}

static void test_private_visibility_follows_pin_policy(void **state) {
  (void)state;

  assert_false(CNK_PivPrivateKeyIsPrivate(CNK_PIV_PIN_POLICY_NEVER));
  assert_true(CNK_PivPrivateKeyIsPrivate(CNK_PIV_PIN_POLICY_ONCE));
  assert_true(CNK_PivPrivateKeyIsPrivate(CNK_PIV_PIN_POLICY_ALWAYS));
  assert_true(CNK_PivPrivateKeyIsPrivate(0));
}

static void test_policy_defaults(void **state) {
  (void)state;

  CK_BYTE pinPolicy = 0;
  CK_BYTE touchPolicy = 0;
  CK_RV rv = CNK_GetPivPolicies(NULL, 0, CNK_PIV_PIN_POLICY_ONCE, &pinPolicy, &touchPolicy);

  assert_int_equal(rv, CKR_OK);
  assert_int_equal(pinPolicy, CNK_PIV_PIN_POLICY_ONCE);
  assert_int_equal(touchPolicy, CNK_PIV_TOUCH_POLICY_NEVER);
}

static void test_always_authenticate_sets_pin_policy_always(void **state) {
  (void)state;

  CK_BBOOL alwaysAuthenticate = CK_TRUE;
  CK_ATTRIBUTE attrs[] = {
      {CKA_ALWAYS_AUTHENTICATE, &alwaysAuthenticate, sizeof(alwaysAuthenticate)},
  };
  CK_BYTE pinPolicy = 0;
  CK_BYTE touchPolicy = 0;
  CK_RV rv =
      CNK_GetPivPolicies(attrs, sizeof(attrs) / sizeof(attrs[0]), CNK_PIV_PIN_POLICY_ONCE, &pinPolicy, &touchPolicy);

  assert_int_equal(rv, CKR_OK);
  assert_int_equal(pinPolicy, CNK_PIV_PIN_POLICY_ALWAYS);
  assert_int_equal(touchPolicy, CNK_PIV_TOUCH_POLICY_NEVER);
}

static void test_vendor_pin_policy_overrides_always_authenticate(void **state) {
  (void)state;

  CK_BBOOL alwaysAuthenticate = CK_TRUE;
  CK_BYTE requestedPinPolicy = CNK_PIV_PIN_POLICY_NEVER;
  CK_ATTRIBUTE attrs[] = {
      {CKA_ALWAYS_AUTHENTICATE, &alwaysAuthenticate, sizeof(alwaysAuthenticate)},
      {CKA_CNK_PIV_PIN_POLICY, &requestedPinPolicy, sizeof(requestedPinPolicy)},
  };
  CK_BYTE pinPolicy = 0;
  CK_BYTE touchPolicy = 0;
  CK_RV rv =
      CNK_GetPivPolicies(attrs, sizeof(attrs) / sizeof(attrs[0]), CNK_PIV_PIN_POLICY_ONCE, &pinPolicy, &touchPolicy);

  assert_int_equal(rv, CKR_OK);
  assert_int_equal(pinPolicy, CNK_PIV_PIN_POLICY_NEVER);
  assert_int_equal(touchPolicy, CNK_PIV_TOUCH_POLICY_NEVER);
}

static void test_vendor_touch_policy(void **state) {
  (void)state;

  CK_BYTE requestedTouchPolicy = CNK_PIV_TOUCH_POLICY_CACHED;
  CK_ATTRIBUTE attrs[] = {
      {CKA_CNK_PIV_TOUCH_POLICY, &requestedTouchPolicy, sizeof(requestedTouchPolicy)},
  };
  CK_BYTE pinPolicy = 0;
  CK_BYTE touchPolicy = 0;
  CK_RV rv =
      CNK_GetPivPolicies(attrs, sizeof(attrs) / sizeof(attrs[0]), CNK_PIV_PIN_POLICY_ONCE, &pinPolicy, &touchPolicy);

  assert_int_equal(rv, CKR_OK);
  assert_int_equal(pinPolicy, CNK_PIV_PIN_POLICY_ONCE);
  assert_int_equal(touchPolicy, CNK_PIV_TOUCH_POLICY_CACHED);
}

static void test_reject_invalid_pin_policy(void **state) {
  (void)state;

  CK_BYTE invalidPinPolicy = 0x04;
  CK_ATTRIBUTE attrs[] = {
      {CKA_CNK_PIV_PIN_POLICY, &invalidPinPolicy, sizeof(invalidPinPolicy)},
  };
  CK_BYTE pinPolicy = 0;
  CK_BYTE touchPolicy = 0;
  CK_RV rv =
      CNK_GetPivPolicies(attrs, sizeof(attrs) / sizeof(attrs[0]), CNK_PIV_PIN_POLICY_ONCE, &pinPolicy, &touchPolicy);

  assert_int_equal(rv, CKR_ATTRIBUTE_VALUE_INVALID);
}

static void test_reject_invalid_touch_policy(void **state) {
  (void)state;

  CK_BYTE invalidTouchPolicy = 0x04;
  CK_ATTRIBUTE attrs[] = {
      {CKA_CNK_PIV_TOUCH_POLICY, &invalidTouchPolicy, sizeof(invalidTouchPolicy)},
  };
  CK_BYTE pinPolicy = 0;
  CK_BYTE touchPolicy = 0;
  CK_RV rv =
      CNK_GetPivPolicies(attrs, sizeof(attrs) / sizeof(attrs[0]), CNK_PIV_PIN_POLICY_ONCE, &pinPolicy, &touchPolicy);

  assert_int_equal(rv, CKR_ATTRIBUTE_VALUE_INVALID);
}

static void test_key_capabilities_by_algorithm(void **state) {
  (void)state;
  CNK_PKCS11_SESSION session = {0};
  session.secp521r1Algorithm = PIV_ALG_ECC_521;

  assert_true(CNK_PivPrivateKeyCanSign(&session, PIV_ALG_RSA_2048));
  assert_true(CNK_PivPrivateKeyCanDecrypt(&session, PIV_ALG_RSA_2048));
  assert_false(CNK_PivPrivateKeyCanDerive(&session, PIV_ALG_RSA_2048));

  assert_true(CNK_PivPrivateKeyCanSign(&session, PIV_ALG_ECC_256));
  assert_false(CNK_PivPrivateKeyCanDecrypt(&session, PIV_ALG_ECC_256));
  assert_true(CNK_PivPrivateKeyCanDerive(&session, PIV_ALG_ECC_256));

  assert_true(CNK_PivPrivateKeyCanSign(&session, PIV_ALG_ECC_521));
  assert_false(CNK_PivPrivateKeyCanDecrypt(&session, PIV_ALG_ECC_521));
  assert_true(CNK_PivPrivateKeyCanDerive(&session, PIV_ALG_ECC_521));
}

static void test_configured_extension_algorithm_ids(void **state) {
  (void)state;
  CNK_PKCS11_SESSION session = {0};
  session.rsa3072Algorithm = 0x22;
  session.rsa4096Algorithm = 0x50;
  session.secp256k1Algorithm = 0x53;
  session.secp521r1Algorithm = 0x15;
  session.sm2Algorithm = 0x54;

  assert_int_equal(CNK_PivConfiguredAlgorithm(&session, PIV_ALG_RSA_3072), 0x22);
  assert_true(CNK_PivAlgorithmIsRsa(&session, 0x22));
  assert_true(CNK_PivAlgorithmIsEc(&session, 0x15));
  assert_true(CNK_PivPrivateKeyCanDerive(&session, 0x53));
  assert_false(CNK_PivPrivateKeyCanSign(&session, 0x54));
  assert_false(CNK_PivAlgorithmIsRsa(&session, PIV_ALG_RSA_3072));
}

static void test_p521_named_curve_parameters(void **state) {
  (void)state;
  static const CK_BYTE p521[] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23};
  CK_BYTE algorithmType = 0;

  assert_int_equal(cnk_ec_params_to_piv_algorithm(p521, sizeof(p521), &algorithmType), CKR_OK);
  assert_int_equal(algorithmType, PIV_ALG_ECC_521);
}

static void test_public_key_metadata_capacity_includes_rsa4096(void **state) {
  (void)state;
  // RSA-4096 metadata contains a 512-byte modulus plus the 0x81/0x82 TLVs.
  assert_true(CNK_PIV_MAX_PUBLIC_KEY_DATA_SIZE >= 521);
}

static void test_25519_named_curve_parameters(void **state) {
  (void)state;
  static const CK_BYTE ed25519[] = {0x06, 0x03, 0x2B, 0x65, 0x70};
  static const CK_BYTE x25519[] = {0x06, 0x03, 0x2B, 0x65, 0x6E};
  CK_BYTE algorithmType = 0;

  assert_int_equal(cnk_ec_params_to_piv_algorithm(ed25519, sizeof(ed25519), &algorithmType), CKR_OK);
  assert_int_equal(algorithmType, PIV_ALG_ED25519);
  assert_int_equal(cnk_ec_params_to_piv_algorithm(x25519, sizeof(x25519), &algorithmType), CKR_OK);
  assert_int_equal(algorithmType, PIV_ALG_X25519);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_default_policy_for_slots),
      cmocka_unit_test(test_private_visibility_follows_pin_policy),
      cmocka_unit_test(test_policy_defaults),
      cmocka_unit_test(test_always_authenticate_sets_pin_policy_always),
      cmocka_unit_test(test_vendor_pin_policy_overrides_always_authenticate),
      cmocka_unit_test(test_vendor_touch_policy),
      cmocka_unit_test(test_reject_invalid_pin_policy),
      cmocka_unit_test(test_reject_invalid_touch_policy),
      cmocka_unit_test(test_key_capabilities_by_algorithm),
      cmocka_unit_test(test_configured_extension_algorithm_ids),
      cmocka_unit_test(test_p521_named_curve_parameters),
      cmocka_unit_test(test_public_key_metadata_capacity_includes_rsa4096),
      cmocka_unit_test(test_25519_named_curve_parameters),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
