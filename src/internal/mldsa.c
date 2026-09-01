#include "internal/mldsa.h"

#include <mbedtls/platform_util.h>

#define MLD_CONFIG_PARAMETER_SET 65
#define MLD_CONFIG_NAMESPACE_PREFIX cnk_mldsa65
#define MLD_CONFIG_EXTERNAL_API_QUALIFIER static
#define MLD_CONFIG_INTERNAL_API_QUALIFIER static
#define MLD_CONFIG_NO_RANDOMIZED_API
#define MLD_CONFIG_NO_SUPERCOP
#define MLD_CONFIG_CUSTOM_ZEROIZE
#define mld_zeroize mbedtls_platform_zeroize

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#endif

#include "mldsa_native.c"
#include "mldsa_native.h"

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

CK_RV cnk_mldsa65_verify_signature(const CK_BYTE publicKey[CNK_MLDSA65_PUBLIC_KEY_BYTES], const CK_BYTE *message,
                                   CK_ULONG messageLen, const CK_BYTE signature[CNK_MLDSA65_SIGNATURE_BYTES]) {
  if ((message == NULL && messageLen > 0) || publicKey == NULL || signature == NULL)
    return CKR_ARGUMENTS_BAD;
  int result = cnk_mldsa65_verify(signature, CNK_MLDSA65_SIGNATURE_BYTES, message, messageLen, NULL, 0, publicKey);
  return result == 0 ? CKR_OK : CKR_SIGNATURE_INVALID;
}
