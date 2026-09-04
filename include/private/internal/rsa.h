#ifndef CNK_INTERNAL_RSA_H
#define CNK_INTERNAL_RSA_H

#include <mbedtls/md.h>

#include "pkcs11.h"

CK_RV pkcs1_v1_5_pad(CK_BYTE_PTR pbInput, CK_ULONG cbInput, CK_BYTE_PTR pbOutput, CK_ULONG cbOutput,
                     mbedtls_md_type_t mdType);

CK_RV pss_encode(CK_BYTE_PTR pbHash, CK_ULONG cbHash, CK_BYTE_PTR pbModulus, CK_ULONG cbModulus, CK_ULONG cbSalt,
                 mbedtls_md_type_t mdType, CK_BYTE_PTR pbOutput);

CK_RV pkcs1_v1_5_unpad(CK_BYTE_PTR pbInput, CK_ULONG cbInput, CK_BYTE_PTR pbOutput, CK_ULONG_PTR pcbOutput);

CK_RV oaep_unpad(CK_BYTE_PTR pbInput, CK_ULONG cbInput, CK_BYTE_PTR pbOutput, CK_ULONG_PTR pcbOutput,
                 mbedtls_md_type_t mdType, mbedtls_md_type_t mgfMdType, CK_BYTE_PTR pLabel, CK_ULONG cbLabel);

CK_RV cnk_rsa_public(const CK_BYTE *modulus, CK_ULONG modulusLen, const CK_BYTE *exponent, CK_ULONG exponentLen,
                     const CK_BYTE *input, CK_ULONG inputLen, CK_BYTE *output);

CK_RV pkcs1_v1_5_encrypt_pad(const CK_BYTE *input, CK_ULONG inputLen, CK_BYTE *output, CK_ULONG outputLen);

CK_RV oaep_pad(const CK_BYTE *input, CK_ULONG inputLen, CK_BYTE *output, CK_ULONG outputLen, mbedtls_md_type_t mdType,
               mbedtls_md_type_t mgfMdType, const CK_BYTE *label, CK_ULONG labelLen);

CK_RV pss_verify(const CK_BYTE *hash, CK_ULONG hashLen, const CK_BYTE *modulus, CK_ULONG modulusLen, CK_ULONG saltLen,
                 mbedtls_md_type_t mdType, const CK_BYTE *encoded, CK_ULONG encodedLen);

#endif // CNK_INTERNAL_RSA_H
