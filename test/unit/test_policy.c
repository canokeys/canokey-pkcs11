// clang-format off
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
// clang-format on

#include "api/object.h"
#include "backend/pcsc.h"
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

  assert_true(CNK_PivPrivateKeyCanSign(PIV_ALG_RSA_2048));
  assert_true(CNK_PivPrivateKeyCanDecrypt(PIV_ALG_RSA_2048));
  assert_false(CNK_PivPrivateKeyCanDerive(PIV_ALG_RSA_2048));

  assert_true(CNK_PivPrivateKeyCanSign(PIV_ALG_ECC_256));
  assert_false(CNK_PivPrivateKeyCanDecrypt(PIV_ALG_ECC_256));
  assert_true(CNK_PivPrivateKeyCanDerive(PIV_ALG_ECC_256));
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_default_policy_for_slots),
      cmocka_unit_test(test_policy_defaults),
      cmocka_unit_test(test_always_authenticate_sets_pin_policy_always),
      cmocka_unit_test(test_vendor_pin_policy_overrides_always_authenticate),
      cmocka_unit_test(test_vendor_touch_policy),
      cmocka_unit_test(test_reject_invalid_pin_policy),
      cmocka_unit_test(test_reject_invalid_touch_policy),
      cmocka_unit_test(test_key_capabilities_by_algorithm),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
