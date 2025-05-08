#ifndef RSA_UTILS_H
#define RSA_UTILS_H

#include <mbedtls/md.h>

#include "pkcs11.h"

CK_RV pkcs1_v1_5_pad(CK_BYTE_PTR pbInput, CK_ULONG cbInput, CK_BYTE_PTR pbOutput, CK_ULONG cbOutput,
                     mbedtls_md_type_t mdType);

CK_RV pss_encode(CK_BYTE_PTR pbHash, CK_ULONG cbHash, CK_BYTE_PTR pbModulus, CK_ULONG cbModulus, CK_ULONG cbSalt,
                 mbedtls_md_type_t mdType, CK_BYTE_PTR pbOutput);

#endif // RSA_UTILS_H
