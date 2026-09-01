#include "internal/mlkem.h"

#include <mbedtls/platform_util.h>
#include <psa/crypto.h>

#define MLK_CONFIG_CUSTOM_ZEROIZE
#define mlk_zeroize mbedtls_platform_zeroize
#define MLK_CONFIG_EXTERNAL_API_QUALIFIER static
#define MLK_CONFIG_INTERNAL_API_QUALIFIER static
#define MLK_CONFIG_NAMESPACE_PREFIX cnk_mlkem768
#define MLK_CONFIG_PARAMETER_SET 768
#define MLK_CONFIG_NO_RANDOMIZED_API
#define MLK_CONFIG_NO_SUPERCOP

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

#include "mlkem_native.c"
#include "mlkem_native.h"

#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

CK_RV cnk_mlkem768_encapsulate(const CK_BYTE publicKey[CNK_MLKEM768_PUBLIC_KEY_BYTES],
                               CK_BYTE ciphertext[CNK_MLKEM768_CIPHERTEXT_BYTES],
                               CK_BYTE sharedSecret[CNK_MLKEM768_SHARED_SECRET_BYTES]) {
  CK_BYTE coins[32];
  psa_status_t status = psa_generate_random(coins, sizeof(coins));
  if (status != PSA_SUCCESS)
    return CKR_RANDOM_NO_RNG;

  int result = cnk_mlkem768_enc_derand(ciphertext, sharedSecret, publicKey, coins);
  mbedtls_platform_zeroize(coins, sizeof(coins));
  return result == 0 ? CKR_OK : CKR_FUNCTION_FAILED;
}
