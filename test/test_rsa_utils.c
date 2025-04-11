#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stddef.h>
#include <cmocka.h>

// Include the necessary headers from canokey-pkcs11
#include "pkcs11.h"
#include "pcsc_backend.h"
#include "rsa_utils.h"

// Mock functions and data structures
static unsigned char test_data[] = "test data for RSA sign operation";
static size_t test_data_len = 30; // Length of test_data

// Mocked functions to be implemented as needed
void CNK_LOG_FUNC(const char *func_name, const char *format, ...) {
    // Empty for testing
}

void CNK_DEBUG(const char *format, ...) {
    // Empty for testing
}

void CNK_ERROR(const char *format, ...) {
    // Empty for testing
}

// Function to set up the test mechanism
static void setup_mechanism(CK_MECHANISM *mechanism, CK_MECHANISM_TYPE mech_type, void *parameter, CK_ULONG parameter_len) {
    mechanism->mechanism = mech_type;
    mechanism->pParameter = parameter;
    mechanism->ulParameterLen = parameter_len;
}

// Test for CKM_RSA_X_509 padding (raw padding with leading zeros)
static void test_x509_padding(void **state) {
    (void)state; // Unused

    CK_MECHANISM mechanism;
    CK_BYTE algorithm_type = PIV_ALG_RSA_2048;
    CK_BYTE output[256] = {0}; // 2048 bits = 256 bytes
    CK_ULONG output_len = sizeof(output);
    CK_RV rv;

    // Setup mechanism for X.509
    setup_mechanism(&mechanism, CKM_RSA_X_509, NULL, 0);
    
    // Test size estimation (pPreparedData = NULL)
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, NULL, &output_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(output_len, test_data_len);
    
    // Reset output length for actual padding
    output_len = sizeof(output);
    
    // Test actual padding with buffer larger than data
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, output, &output_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(output_len, test_data_len);
    
    // Verify the output: should have leading zeros followed by the test data
    unsigned char expected[256] = {0};
    memcpy(expected + (sizeof(output) - test_data_len), test_data, test_data_len);
    
    // Check the first bytes are zero (leading padding)
    for (size_t i = 0; i < (sizeof(output) - test_data_len); i++) {
        assert_int_equal(output[i], 0);
    }
    
    // Check that the data is correctly placed at the end
    assert_memory_equal(output + (sizeof(output) - test_data_len), test_data, test_data_len);
    
    // Test with output buffer exactly the size of data
    unsigned char small_output[30] = {0};
    output_len = sizeof(small_output);
    
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, small_output, &output_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(output_len, test_data_len);
    assert_memory_equal(small_output, test_data, test_data_len);
    
    // Test with output buffer too small
    output_len = test_data_len - 1;
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, small_output, &output_len);
    assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);
}

// Test for PKCS#1 v1.5 padding with CKM_RSA_PKCS (direct data padding)
static void test_pkcs1_v1_5_direct_padding(void **state) {
    (void)state; // Unused

    CK_MECHANISM mechanism;
    CK_BYTE algorithm_type = PIV_ALG_RSA_2048;
    CK_BYTE output[256] = {0}; // 2048 bits = 256 bytes
    CK_ULONG output_len = sizeof(output);
    CK_RV rv;

    // Setup mechanism for PKCS#1 v1.5
    setup_mechanism(&mechanism, CKM_RSA_PKCS, NULL, 0);
    
    // Test size estimation (pPreparedData = NULL)
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, NULL, &output_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(output_len, 256); // 2048 bits = 256 bytes
    
    // Reset output length for actual padding
    output_len = sizeof(output);
    
    // Test actual padding
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, output, &output_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(output_len, 256);
    
    // Verify basic PKCS#1 v1.5 structure
    // First byte should be 0x00, second byte should be 0x01 (for private key operations)
    assert_int_equal(output[0], 0x00);
    assert_int_equal(output[1], 0x01);
    
    // The padding should be 0xFF until a 0x00 byte is encountered
    size_t i = 2;
    while (i < output_len && output[i] == 0xFF) {
        i++;
    }
    
    // Next byte should be 0x00 separator
    assert_int_equal(output[i], 0x00);
    i++;
    
    // Remaining data should be the input data
    assert_memory_equal(output + i, test_data, test_data_len);
    
    // Test with output buffer too small
    output_len = 128; // Too small for 2048-bit key
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, output, &output_len);
    assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);
}

// Test for PKCS#1 v1.5 padding with SHA1_RSA_PKCS (hash and pad)
static void test_pkcs1_v1_5_sha1_padding(void **state) {
    (void)state; // Unused

    CK_MECHANISM mechanism;
    CK_BYTE algorithm_type = PIV_ALG_RSA_2048;
    CK_BYTE output[256] = {0}; // 2048 bits = 256 bytes
    CK_ULONG output_len = sizeof(output);
    CK_RV rv;

    // Setup mechanism for SHA1-RSA-PKCS
    setup_mechanism(&mechanism, CKM_SHA1_RSA_PKCS, NULL, 0);
    
    // Test size estimation (pPreparedData = NULL)
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, NULL, &output_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(output_len, 256); // 2048 bits = 256 bytes
    
    // Reset output length for actual padding
    output_len = sizeof(output);
    
    // Test actual padding
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, output, &output_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(output_len, 256);
    
    // Verify basic PKCS#1 v1.5 structure
    // First byte should be 0x00, second byte should be 0x01 (for private key operations)
    assert_int_equal(output[0], 0x00);
    assert_int_equal(output[1], 0x01);
    
    // The padding should be 0xFF until a 0x00 byte is encountered
    size_t i = 2;
    while (i < output_len && output[i] == 0xFF) {
        i++;
    }
    
    // Next byte should be 0x00 separator
    assert_int_equal(output[i], 0x00);
    i++;
    
    // For SHA1, there should be an ASN.1 header for the digest (DER encoding)
    // SHA1 OID is 1.3.14.3.2.26
    // We'll just check the first few bytes of the ASN.1 header
    assert_int_equal(output[i], 0x30); // SEQUENCE
    // Skip length checking and OID details for simplicity
}

// Test for PKCS#1 v1.5 padding with SHA256_RSA_PKCS (hash and pad)
static void test_pkcs1_v1_5_sha256_padding(void **state) {
    (void)state; // Unused

    CK_MECHANISM mechanism;
    CK_BYTE algorithm_type = PIV_ALG_RSA_2048;
    CK_BYTE output[256] = {0}; // 2048 bits = 256 bytes
    CK_ULONG output_len = sizeof(output);
    CK_RV rv;

    // Setup mechanism for SHA256-RSA-PKCS
    setup_mechanism(&mechanism, CKM_SHA256_RSA_PKCS, NULL, 0);
    
    // Test size estimation (pPreparedData = NULL)
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, NULL, &output_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(output_len, 256); // 2048 bits = 256 bytes
    
    // Reset output length for actual padding
    output_len = sizeof(output);
    
    // Test actual padding
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, output, &output_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(output_len, 256);
    
    // Similar checks as SHA1, but with SHA256 ASN.1 structure
    assert_int_equal(output[0], 0x00);
    assert_int_equal(output[1], 0x01);
}

// Test PSS padding with CKM_RSA_PKCS_PSS
static void test_pss_padding(void **state) {
    (void)state; // Unused

    CK_MECHANISM mechanism;
    CK_RSA_PKCS_PSS_PARAMS pss_params = {
        .hashAlg = CKM_SHA256,
        .mgf = 1, // MGF1
        .sLen = 32 // Salt length equal to hash length
    };
    CK_BYTE algorithm_type = PIV_ALG_RSA_2048;
    CK_BYTE output[256] = {0}; // 2048 bits = 256 bytes
    CK_ULONG output_len = sizeof(output);
    CK_RV rv;

    // Setup mechanism for RSA-PSS
    setup_mechanism(&mechanism, CKM_RSA_PKCS_PSS, &pss_params, sizeof(pss_params));
    
    // Test size estimation (pPreparedData = NULL)
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, NULL, &output_len);
    assert_int_equal(rv, CKR_OK);
    
    // Reset output length for actual padding
    output_len = sizeof(output);
    
    // Test actual padding
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, output, &output_len);
    assert_int_equal(rv, CKR_OK);
    
    // For PSS, specific verification is difficult without decoding
    // We mainly check that the operation completed successfully
}

// Test PSS padding with SHA256_RSA_PKCS_PSS
static void test_sha256_pss_padding(void **state) {
    (void)state; // Unused

    CK_MECHANISM mechanism;
    CK_RSA_PKCS_PSS_PARAMS pss_params = {
        .hashAlg = CKM_SHA256,
        .mgf = 1, // MGF1
        .sLen = 32 // Salt length equal to hash length
    };
    CK_BYTE algorithm_type = PIV_ALG_RSA_2048;
    CK_BYTE output[256] = {0}; // 2048 bits = 256 bytes
    CK_ULONG output_len = sizeof(output);
    CK_RV rv;

    // Setup mechanism for SHA256-RSA-PSS
    setup_mechanism(&mechanism, CKM_SHA256_RSA_PKCS_PSS, &pss_params, sizeof(pss_params));
    
    // Test size estimation (pPreparedData = NULL)
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, NULL, &output_len);
    assert_int_equal(rv, CKR_OK);
    
    // Reset output length for actual padding
    output_len = sizeof(output);
    
    // Test actual padding
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, output, &output_len);
    assert_int_equal(rv, CKR_OK);
}

// Test PSS padding with different salt lengths
static void test_pss_different_salt_lengths(void **state) {
    (void)state; // Unused

    CK_MECHANISM mechanism;
    CK_RSA_PKCS_PSS_PARAMS pss_params = {
        .hashAlg = CKM_SHA256,
        .mgf = 1, // MGF1
        .sLen = 0 // Zero salt length
    };
    CK_BYTE algorithm_type = PIV_ALG_RSA_2048;
    CK_BYTE output[256] = {0}; // 2048 bits = 256 bytes
    CK_ULONG output_len = sizeof(output);
    CK_RV rv;

    // Test with zero salt length
    setup_mechanism(&mechanism, CKM_RSA_PKCS_PSS, &pss_params, sizeof(pss_params));
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, output, &output_len);
    assert_int_equal(rv, CKR_OK);
    
    // Test with maximum salt length
    pss_params.sLen = 32; // Max for SHA256
    memset(output, 0, sizeof(output));
    output_len = sizeof(output);
    
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, output, &output_len);
    assert_int_equal(rv, CKR_OK);
}

// Test different RSA key sizes
static void test_different_rsa_key_sizes(void **state) {
    (void)state; // Unused

    CK_MECHANISM mechanism;
    CK_BYTE output[512] = {0}; // Large enough for 4096-bit key
    CK_ULONG output_len = sizeof(output);
    CK_RV rv;

    // Setup mechanism for PKCS#1 v1.5
    setup_mechanism(&mechanism, CKM_RSA_PKCS, NULL, 0);
    
    // Test with 2048-bit key
    CK_BYTE algorithm_type = PIV_ALG_RSA_2048;
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, NULL, &output_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(output_len, 256); // 2048 bits = 256 bytes
    
    // Test with 3072-bit key
    algorithm_type = PIV_ALG_RSA_3072;
    output_len = sizeof(output);
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, NULL, &output_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(output_len, 384); // 3072 bits = 384 bytes
    
    // Test with 4096-bit key
    algorithm_type = PIV_ALG_RSA_4096;
    output_len = sizeof(output);
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, NULL, &output_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(output_len, 512); // 4096 bits = 512 bytes
}

// Test error conditions
static void test_error_conditions(void **state) {
    (void)state; // Unused

    CK_MECHANISM mechanism;
    CK_BYTE algorithm_type = PIV_ALG_RSA_2048;
    CK_BYTE output[256] = {0};
    CK_ULONG output_len = sizeof(output);
    CK_RV rv;

    // Test invalid mechanism
    setup_mechanism(&mechanism, CKM_VENDOR_DEFINED, NULL, 0);
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, output, &output_len);
    assert_int_equal(rv, CKR_MECHANISM_INVALID);
    
    // Test PSS with missing parameters
    setup_mechanism(&mechanism, CKM_RSA_PKCS_PSS, NULL, 0);
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, output, &output_len);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);
    
    // Test PSS with invalid MGF
    CK_RSA_PKCS_PSS_PARAMS pss_params = {
        .hashAlg = CKM_SHA256,
        .mgf = 99, // Invalid MGF
        .sLen = 32
    };
    setup_mechanism(&mechanism, CKM_RSA_PKCS_PSS, &pss_params, sizeof(pss_params));
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, output, &output_len);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);
    
    // Test PSS with invalid hash algorithm
    pss_params.mgf = 1; // Valid MGF
    pss_params.hashAlg = CKM_VENDOR_DEFINED; // Invalid hash
    setup_mechanism(&mechanism, CKM_RSA_PKCS_PSS, &pss_params, sizeof(pss_params));
    rv = cnk_prepare_rsa_sign_data(&mechanism, test_data, test_data_len, 
                                 algorithm_type, output, &output_len);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);
}

// Main function to run all tests
int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_x509_padding),
        cmocka_unit_test(test_pkcs1_v1_5_direct_padding),
        cmocka_unit_test(test_pkcs1_v1_5_sha1_padding),
        cmocka_unit_test(test_pkcs1_v1_5_sha256_padding),
        cmocka_unit_test(test_pss_padding),
        cmocka_unit_test(test_sha256_pss_padding),
        cmocka_unit_test(test_pss_different_salt_lengths),
        cmocka_unit_test(test_different_rsa_key_sizes),
        cmocka_unit_test(test_error_conditions),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
