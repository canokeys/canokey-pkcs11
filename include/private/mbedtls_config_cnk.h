#ifndef CNK_MBEDTLS_CONFIG_CNK_H
#define CNK_MBEDTLS_CONFIG_CNK_H

// Complete configuration: upstream defaults must not silently enable algorithms.
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_DEPRECATED_REMOVED
#define MBEDTLS_CHECK_RETURN_WARNING
#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_PSA_BUILTIN_GET_ENTROPY
#define MBEDTLS_CTR_DRBG_C
// AES is retained for CTR-DRBG only; management authentication belongs to Rust.
#define PSA_WANT_KEY_TYPE_AES 1
#define PSA_WANT_ALG_ECB_NO_PADDING 1
#define MBEDTLS_AESNI_C
#define MBEDTLS_AESCE_C
#define MBEDTLS_HAVE_ASM

// Host hashing/padding and ASN.1 OID encoding. Private key operations run on-card.
#define MBEDTLS_MD_C
#define MBEDTLS_ASN1_WRITE_C
#define PSA_WANT_ALG_SHA_1 1
#define PSA_WANT_ALG_SHA_224 1
#define PSA_WANT_ALG_SHA_256 1
#define PSA_WANT_ALG_SHA_384 1
#define PSA_WANT_ALG_SHA_512 1
#define PSA_WANT_ALG_SHA3_224 1
#define PSA_WANT_ALG_SHA3_256 1
#define PSA_WANT_ALG_SHA3_384 1
#define PSA_WANT_ALG_SHA3_512 1

// RSA public operations and ECDSA verification; no host key generation/ECDH.
#define PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY 1
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY 1
#define PSA_WANT_ALG_ECDSA 1
#define PSA_WANT_ECC_SECP_R1_256 1
#define PSA_WANT_ECC_SECP_R1_384 1
#define PSA_WANT_ECC_SECP_R1_521 1
#define PSA_WANT_ECC_SECP_K1_256 1
#define MBEDTLS_ECP_NIST_OPTIM

#endif // CNK_MBEDTLS_CONFIG_CNK_H
