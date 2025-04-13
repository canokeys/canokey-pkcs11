#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11.h"

#include "mbedtls/md.h"
#include "mbedtls/pk.h"

#define LOG_ERROR(fmt, ...) fprintf(stderr, "ERROR: " fmt "\n", ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) fprintf(stdout, "INFO: " fmt "\n", ##__VA_ARGS__)

// Constants
#define PIN "123456"
#define KEY_ID 2

// Dummy public key constant; replace with your actual public key in PEM format
const char *PUBLIC_KEY_PEM = "-----BEGIN PUBLIC KEY-----\n"
                             "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuoBVOUILYxJ3hs0lvLvZ\n"
                             "yxD+7qfFbWH0IkHg6/OjONO6bIoCaifGaiCk6PNFPqLGo2t99KGIP8FBuPjO54DZ\n"
                             "uTpfkRq7V85ZGfkmIO66DKTz0tM/QOluUiKBxG8lbhZzPyle6EeTo+bL5bRhHoDy\n"
                             "b8eb2YX2PV0AghaHYS24Twiy5PWTVVPqfgGmZvH8/X/r0y1CQtkZOyU8cj7tJhIz\n"
                             "AIYCrR7Sxch44KfXjUcW4aPegK8r1uqkr9QiHUcMgLtk1jFnht5GsnWraczXVBT8\n"
                             "9I/fJFmAkXeBoSXy5R3SMg03h8soUyPy+zVo0yfbWrFV/X08/Vg3ngen5/U+3+YQ\n"
                             "2wIDAQAB\n"
                             "-----END PUBLIC KEY-----\n";

// Global PKCS#11 function pointers
CK_FUNCTION_LIST_PTR pF = NULL;

// Load function pointers from the PKCS#11 module
int cnk_load_pkcs11_functions(void *handle) {
  CK_C_GetFunctionList pC_GetFunctionList = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  if (!pC_GetFunctionList) {
    LOG_ERROR("Failed to load C_GetFunctionList.");
    return -1;
  }
  CK_RV rv = pC_GetFunctionList(&pF);
  if (rv != CKR_OK) {
    LOG_ERROR("C_GetFunctionList failed. rv = 0x%lx", rv);
    return -1;
  }

  if (!pF->C_Initialize || !pF->C_Finalize || !pF->C_GetSlotList || !pF->C_OpenSession || !pF->C_CloseSession ||
      !pF->C_Login || !pF->C_Logout || !pF->C_FindObjectsInit || !pF->C_FindObjects || !pF->C_FindObjectsFinal ||
      !pF->C_SignInit || !pF->C_Sign) {
    LOG_ERROR("Failed to load one or more PKCS#11 functions.");
    return -1;
  }
  return 0;
}

// Helper function to find a key by CKA_ID == KEY_ID
CK_OBJECT_HANDLE cnk_find_key(CK_SESSION_HANDLE session) {
  CK_OBJECT_HANDLE key = 0;
  CK_BYTE key_id = KEY_ID;
  CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE template[] = {{CKA_ID, &key_id, sizeof(key_id)}, {CKA_CLASS, &keyClass, sizeof(keyClass)}};

  CK_RV rv = pF->C_FindObjectsInit(session, template, 2);
  if (rv != CKR_OK) {
    LOG_ERROR("C_FindObjectsInit failed.");
    return 0;
  }
  CK_ULONG foundCount = 0;
  rv = pF->C_FindObjects(session, &key, 1, &foundCount);
  if (rv != CKR_OK || foundCount == 0) {
    LOG_ERROR("Key with CKA_ID=%d not found. rv = 0x%lx", KEY_ID, rv);
    pF->C_FindObjectsFinal(session);
    return 0;
  }
  pF->C_FindObjectsFinal(session);
  return key;
}

// Helper function to verify a signature using mbedtls
int cnk_verify_signature(const unsigned char *data, size_t data_len, const unsigned char *sig, size_t sig_len,
                         int use_sha256) {
  int ret = 0;
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);

  ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char *)PUBLIC_KEY_PEM, strlen(PUBLIC_KEY_PEM) + 1);
  if (ret != 0) {
    LOG_ERROR("Failed to parse public key. ret = -0x%x", -ret);
    return -1;
  }

  ((mbedtls_rsa_context *)pk.private_pk_ctx)->private_padding = MBEDTLS_RSA_PKCS_V21;

  const mbedtls_md_type_t md_alg = use_sha256 ? MBEDTLS_MD_SHA256 : MBEDTLS_MD_NONE;
  unsigned char hash[32];
  if (use_sha256) {
    ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), data, data_len, hash);
    if (ret != 0) {
      LOG_ERROR("Failed to compute SHA256 hash.");
      mbedtls_pk_free(&pk);
      return -1;
    }
  }

  ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, use_sha256 ? hash : data, use_sha256 ? 32 : data_len, sig, sig_len);
  if (ret != 0) {
    LOG_ERROR("Signature verification failed. ret = -0x%x", -ret);
    return -1;
  } else {
    LOG_INFO("Signature verification succeeded.");
  }

  mbedtls_pk_free(&pk);
  return ret;
}

// Helper function to perform a signing test using the specified mechanism
int cnk_test_signing(CK_MECHANISM_TYPE mechanism_type) {
  CK_SESSION_HANDLE session;
  CK_RV rv;

  // Open session on first available slot
  CK_ULONG slotCount = 0;
  rv = pF->C_GetSlotList(CK_TRUE, NULL, &slotCount);
  if (rv != CKR_OK || slotCount == 0) {
    LOG_ERROR("No slot available.");
    return -1;
  }
  CK_SLOT_ID *slots = (CK_SLOT_ID *)malloc(sizeof(CK_SLOT_ID) * slotCount);
  rv = pF->C_GetSlotList(CK_TRUE, slots, &slotCount);
  if (rv != CKR_OK) {
    LOG_ERROR("C_GetSlotList failed.");
    free(slots);
    return -1;
  }
  rv = pF->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
  free(slots);
  if (rv != CKR_OK) {
    LOG_ERROR("C_OpenSession failed. rv = 0x%lx", rv);
    return -1;
  }

  // Login with PIN
  rv = pF->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)PIN, strlen(PIN));
  if (rv != CKR_OK) {
    LOG_ERROR("C_Login failed.");
    pF->C_CloseSession(session);
    return -1;
  }

  // Find the key with CKA_ID = KEY_ID
  CK_OBJECT_HANDLE key = cnk_find_key(session);
  if (key == 0) {
    pF->C_Logout(session);
    pF->C_CloseSession(session);
    return -1;
  }

  // Prepare the mechanism
  CK_MECHANISM mechanism;
  mechanism.mechanism = mechanism_type;
  CK_RSA_PKCS_PSS_PARAMS pss_params;
  pss_params.hashAlg = CKM_SHA256;
  pss_params.mgf = CKG_MGF1_SHA256;
  pss_params.sLen = 32;
  mechanism.pParameter = &pss_params;
  mechanism.ulParameterLen = sizeof(pss_params);

  rv = pF->C_SignInit(session, &mechanism, key);
  if (rv != CKR_OK) {
    LOG_ERROR("C_SignInit failed. rv = 0x%lx", rv);
    pF->C_Logout(session);
    pF->C_CloseSession(session);
    return -1;
  }

  // Data to be signed
  unsigned char data[] = "Test data for RSA PSS signature!";
  CK_ULONG data_len = sizeof(data) - 1;

  // Get signature size
  CK_ULONG sig_len = 0;
  rv = pF->C_Sign(session, data, data_len, NULL, &sig_len);
  if (rv != CKR_OK) {
    LOG_ERROR("C_Sign (get length) failed.");
    pF->C_Logout(session);
    pF->C_CloseSession(session);
    return -1;
  }
  unsigned char *signature = (unsigned char *)malloc(sig_len);
  rv = pF->C_Sign(session, data, data_len, signature, &sig_len);
  if (rv != CKR_OK) {
    LOG_ERROR("C_Sign failed.");
    free(signature);
    pF->C_Logout(session);
    pF->C_CloseSession(session);
    return -1;
  }

  // Verify the signature using mbedtls
  int verify_ret =
      cnk_verify_signature(data, data_len, signature, sig_len, mechanism.mechanism == CKM_SHA256_RSA_PKCS_PSS);
  free(signature);

  // Logout and close session
  pF->C_Logout(session);
  pF->C_CloseSession(session);
  return verify_ret;
}

int main(int argc, char *argv[]) {
  // Path to the PKCS#11 library
  const char *libraryPath = NULL;

  // Check if a library path was provided as a command line argument
  if (argc > 1) {
    libraryPath = argv[1];
  }

  printf("Using PKCS#11 library: %s\n", libraryPath);

  // Load the PKCS#11 library dynamically
  void *library = dlopen(libraryPath, RTLD_LAZY);
  if (!library) {
    printf("Error loading library: %s\n", dlerror());
    return 1;
  }

  if (cnk_load_pkcs11_functions(library) != 0) {
    dlclose(library);
    return -1;
  }

  // Initialize the library
  CK_RV ret = pF->C_Initialize(NULL);
  if (ret != CKR_OK) {
    LOG_ERROR("Error initializing library: 0x%lx", ret);
    dlclose(library);
    return 1;
  }

  // LOG_INFO("Testing CKM_RSA_PKCS_PSS");
  // ret = cnk_test_signing(CKM_RSA_PKCS_PSS);
  // if (ret != 0) {
  //   LOG_ERROR("Test for CKM_RSA_PKCS_PSS failed.");
  // }

  LOG_INFO("Testing CKM_SHA256_RSA_PKCS_PSS");
  ret = cnk_test_signing(CKM_SHA256_RSA_PKCS_PSS);
  if (ret != 0) {
    LOG_ERROR("Test for CKM_SHA256_RSA_PKCS_PSS failed.");
  }

  pF->C_Finalize(NULL);
  dlclose(library);
  return 0;
}
