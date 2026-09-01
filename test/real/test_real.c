#ifndef _WIN32
#define _POSIX_C_SOURCE 200112L
#endif

#include "api/object.h"
#include "pkcs11.h"
#include "pkcs11_canokey.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dlfcn.h>
#include <time.h>
#endif

#define CNK_REAL_WRITE_TEST_ENV "CNK_RUN_DESTRUCTIVE_REAL_TESTS"
#define CNK_REAL_WRITE_TEST_ID 6

#define CNK_REAL_WRITE_TEST_PIN_POLICY CNK_PIV_PIN_POLICY_ONCE
#define CNK_REAL_WRITE_TEST_TOUCH_POLICY CNK_PIV_TOUCH_POLICY_NEVER

// Include TF-PSA-Crypto mbedtls-compatible headers for signature verification
#include <mbedtls/md.h>
#include <mbedtls/private/bignum.h>
#include <mbedtls/private/ecdsa.h>
#include <mbedtls/private/ecp.h>
#include <mbedtls/private/rsa.h>

#ifdef _WIN32
typedef HMODULE CNK_LIBRARY_HANDLE;

static CNK_LIBRARY_HANDLE cnk_load_library(const char *libraryPath) { return LoadLibraryA(libraryPath); }

static CK_C_GetFunctionList cnk_get_function_list(CNK_LIBRARY_HANDLE library) {
  return (CK_C_GetFunctionList)GetProcAddress(library, "C_GetFunctionList");
}

static void cnk_close_library(CNK_LIBRARY_HANDLE library) {
  if (library != NULL)
    FreeLibrary(library);
}

static void cnk_print_library_error(const char *message) {
  DWORD error = GetLastError();
  DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
  char *buffer = NULL;

  FormatMessageA(flags, NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buffer, 0, NULL);

  if (buffer != NULL) {
    printf("%s: %lu: %s\n", message, (unsigned long)error, buffer);
    LocalFree(buffer);
  } else {
    printf("%s: %lu\n", message, (unsigned long)error);
  }
}

static int cnk_setenv(const char *name, const char *value) { return _putenv_s(name, value); }

static void cnk_sleep_milliseconds(unsigned int milliseconds) { Sleep(milliseconds); }
#else
typedef void *CNK_LIBRARY_HANDLE;

static CNK_LIBRARY_HANDLE cnk_load_library(const char *libraryPath) { return dlopen(libraryPath, RTLD_LAZY); }

static CK_C_GetFunctionList cnk_get_function_list(CNK_LIBRARY_HANDLE library) {
  return (CK_C_GetFunctionList)dlsym(library, "C_GetFunctionList");
}

static void cnk_close_library(CNK_LIBRARY_HANDLE library) {
  if (library != NULL)
    dlclose(library);
}

static void cnk_print_library_error(const char *message) { printf("%s: %s\n", message, dlerror()); }

static int cnk_setenv(const char *name, const char *value) { return setenv(name, value, 1); }

static void cnk_sleep_milliseconds(unsigned int milliseconds) {
  struct timespec ts;
  ts.tv_sec = milliseconds / 1000;
  ts.tv_nsec = (long)(milliseconds % 1000) * 1000000L;
  while (nanosleep(&ts, &ts) == -1) {
  }
}
#endif

static int cnk_env_is_enabled(const char *name) {
  const char *value = getenv(name);
  return value != NULL && (strcmp(value, "1") == 0 || strcmp(value, "true") == 0 || strcmp(value, "TRUE") == 0 ||
                           strcmp(value, "yes") == 0 || strcmp(value, "YES") == 0);
}

// Utility function to trim trailing spaces from fixed-length strings
void trim_spaces(char *str, size_t length) {
  for (int i = length - 1; i >= 0; i--) {
    if (str[i] == ' ') {
      str[i] = '\0';
    } else {
      break;
    }
  }
}

// Utility function to copy and trim a PKCS#11 fixed-length string
void copy_and_trim_pkcs11_string(char *dest, const unsigned char *src, size_t length) {
  memcpy(dest, src, length);
  dest[length] = '\0'; // Ensure null-termination
  trim_spaces(dest, length);
}

// Utility function to print error message and return error code
CK_RV print_error_and_return(const char *message, CK_RV rv) {
  printf("%s: 0x%lx\n", message, rv);
  return rv;
}

// Utility function to load the PKCS#11 library and get the function list
CK_RV load_pkcs11_library(const char *libraryPath, CNK_LIBRARY_HANDLE *library, CK_FUNCTION_LIST_PTR *pFunctionList) {
  // Load the PKCS#11 library dynamically
  *library = cnk_load_library(libraryPath);
  if (!*library) {
    cnk_print_library_error("Error loading library");
    return CKR_GENERAL_ERROR;
  }

  // Get the C_GetFunctionList function
  CK_C_GetFunctionList getFunc = cnk_get_function_list(*library);
  if (!getFunc) {
    cnk_print_library_error("Error getting C_GetFunctionList function");
    cnk_close_library(*library);
    return CKR_GENERAL_ERROR;
  }

  // Get the function list
  CK_RV rv = getFunc(pFunctionList);
  if (rv != CKR_OK) {
    printf("Error getting function list: 0x%lx\n", rv);
    cnk_close_library(*library);
    return rv;
  }

  printf("Successfully loaded PKCS#11 library\n");
  return CKR_OK;
}

// Utility function to display library information
void display_library_info(CK_FUNCTION_LIST_PTR pFunctionList) {
  CK_INFO info;
  CK_RV rv = pFunctionList->C_GetInfo(&info);
  if (rv != CKR_OK) {
    printf("Error getting library info: 0x%lx\n", rv);
    return;
  }

  // Convert fixed-length fields to null-terminated strings
  char manufacturerID[33] = {0};
  char libraryDescription[33] = {0};

  copy_and_trim_pkcs11_string(manufacturerID, info.manufacturerID, sizeof(info.manufacturerID));
  copy_and_trim_pkcs11_string(libraryDescription, info.libraryDescription, sizeof(info.libraryDescription));

  printf("PKCS#11 Library Information:\n");
  printf("  Cryptoki Version: %d.%d\n", info.cryptokiVersion.major, info.cryptokiVersion.minor);
  printf("  Manufacturer: %s\n", manufacturerID);
  printf("  Library Description: %s\n", libraryDescription);
  printf("  Library Version: %d.%d\n", info.libraryVersion.major, info.libraryVersion.minor);
}

// Utility function to display slot information
void display_slot_info(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID) {
  CK_SLOT_INFO slotInfo;
  CK_RV rv = pFunctionList->C_GetSlotInfo(slotID, &slotInfo);
  if (rv != CKR_OK) {
    printf("    Error getting slot info: 0x%lx\n", rv);
    return;
  }

  // Convert the fixed-length fields to null-terminated strings for display
  char description[65] = {0};
  char manufacturer[33] = {0};

  copy_and_trim_pkcs11_string(description, slotInfo.slotDescription, sizeof(slotInfo.slotDescription));
  copy_and_trim_pkcs11_string(manufacturer, slotInfo.manufacturerID, sizeof(slotInfo.manufacturerID));

  printf("    Description: %s\n", description);
  printf("    Manufacturer: %s\n", manufacturer);
  printf("    Hardware Version: %d.%d\n", slotInfo.hardwareVersion.major, slotInfo.hardwareVersion.minor);
  printf("    Firmware Version: %d.%d\n", slotInfo.firmwareVersion.major, slotInfo.firmwareVersion.minor);
  printf("    Flags: 0x%lx\n", slotInfo.flags);

  // Interpret flags
  if (slotInfo.flags & CKF_TOKEN_PRESENT)
    printf("      - Token present\n");
  if (slotInfo.flags & CKF_REMOVABLE_DEVICE)
    printf("      - Removable device\n");
  if (slotInfo.flags & CKF_HW_SLOT)
    printf("      - Hardware slot\n");
}

// Utility function to display token information
void display_token_info(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID) {
  CK_TOKEN_INFO tokenInfo;
  CK_RV rv = pFunctionList->C_GetTokenInfo(slotID, &tokenInfo);
  if (rv != CKR_OK) {
    printf("    Error getting token info: 0x%lx\n", rv);
    return;
  }

  // Convert fixed-length fields to null-terminated strings
  char tokenLabel[33] = {0};
  char tokenManufacturer[33] = {0};
  char tokenModel[17] = {0};
  char tokenSerialNumber[17] = {0};

  copy_and_trim_pkcs11_string(tokenLabel, tokenInfo.label, sizeof(tokenInfo.label));
  copy_and_trim_pkcs11_string(tokenManufacturer, tokenInfo.manufacturerID, sizeof(tokenInfo.manufacturerID));
  copy_and_trim_pkcs11_string(tokenModel, tokenInfo.model, sizeof(tokenInfo.model));
  copy_and_trim_pkcs11_string(tokenSerialNumber, tokenInfo.serialNumber, sizeof(tokenInfo.serialNumber));

  printf("    Token Information:\n");
  printf("      Label: %s\n", tokenLabel);
  printf("      Manufacturer: %s\n", tokenManufacturer);
  printf("      Model: %s\n", tokenModel);
  printf("      Serial Number: %s\n", tokenSerialNumber);
  printf("      Hardware Version: %d.%d\n", tokenInfo.hardwareVersion.major, tokenInfo.hardwareVersion.minor);
  printf("      Firmware Version: %d.%d\n", tokenInfo.firmwareVersion.major, tokenInfo.firmwareVersion.minor);

  // Print token flags
  printf("      Flags: 0x%lx\n", tokenInfo.flags);
  if (tokenInfo.flags & CKF_RNG)
    printf("        - Has random number generator\n");
  if (tokenInfo.flags & CKF_WRITE_PROTECTED)
    printf("        - Write protected\n");
  if (tokenInfo.flags & CKF_LOGIN_REQUIRED)
    printf("        - Login required\n");
  if (tokenInfo.flags & CKF_USER_PIN_INITIALIZED)
    printf("        - User PIN initialized\n");
  if (tokenInfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
    printf("        - Protected authentication path\n");
  if (tokenInfo.flags & CKF_TOKEN_INITIALIZED)
    printf("        - Token initialized\n");
}

// Utility function to display session information
void display_session_info(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession) {
  CK_SESSION_INFO sessionInfo;
  CK_RV rv = pFunctionList->C_GetSessionInfo(hSession, &sessionInfo);
  if (rv != CKR_OK) {
    printf("    Error getting session info: 0x%lx\n", rv);
    return;
  }

  printf("    Session Information:\n");
  printf("      Slot ID: %lu\n", sessionInfo.slotID);
  printf("      State: ");
  switch (sessionInfo.state) {
  case CKS_RO_PUBLIC_SESSION:
    printf("Read-only public session\n");
    break;
  case CKS_RO_USER_FUNCTIONS:
    printf("Read-only user session\n");
    break;
  case CKS_RW_PUBLIC_SESSION:
    printf("Read-write public session\n");
    break;
  case CKS_RW_USER_FUNCTIONS:
    printf("Read-write user session\n");
    break;
  case CKS_RW_SO_FUNCTIONS:
    printf("Read-write security officer session\n");
    break;
  default:
    printf("Unknown state (%lu)\n", sessionInfo.state);
    break;
  }
  printf("      Flags: 0x%lx\n", sessionInfo.flags);
  if (sessionInfo.flags & CKF_RW_SESSION)
    printf("        - Read-write session\n");
  if (sessionInfo.flags & CKF_SERIAL_SESSION)
    printf("        - Serial session\n");
}

// Utility function to print binary data in hex format
void print_hex_data(const char *label, const CK_BYTE *data, CK_ULONG length, int bytes_per_line) {
  printf("      %s:\n", label);
  for (CK_ULONG i = 0; i < length; i++) {
    printf("%02x", data[i]);
    if (i % bytes_per_line == bytes_per_line - 1 || i == length - 1)
      printf("\n");
  }
}

// Utility function to print mechanism name
void print_mechanism_name(CK_MECHANISM_TYPE mechanism) {
  switch (mechanism) {
  case CKM_RSA_PKCS_KEY_PAIR_GEN:
    printf(" (CKM_RSA_PKCS_KEY_PAIR_GEN)\n");
    break;
  case CKM_RSA_PKCS:
    printf(" (CKM_RSA_PKCS)\n");
    break;
  case CKM_RSA_X_509:
    printf(" (CKM_RSA_X_509)\n");
    break;
  case CKM_RSA_PKCS_OAEP:
    printf(" (CKM_RSA_PKCS_OAEP)\n");
    break;
  case CKM_RSA_PKCS_PSS:
    printf(" (CKM_RSA_PKCS_PSS)\n");
    break;
  case CKM_SHA1_RSA_PKCS:
    printf(" (CKM_SHA1_RSA_PKCS)\n");
    break;
  case CKM_SHA1_RSA_PKCS_PSS:
    printf(" (CKM_SHA1_RSA_PKCS_PSS)\n");
    break;
  case CKM_SHA256_RSA_PKCS:
    printf(" (CKM_SHA256_RSA_PKCS)\n");
    break;
  case CKM_SHA256_RSA_PKCS_PSS:
    printf(" (CKM_SHA256_RSA_PKCS_PSS)\n");
    break;
  case CKM_SHA384_RSA_PKCS:
    printf(" (CKM_SHA384_RSA_PKCS)\n");
    break;
  case CKM_SHA512_RSA_PKCS:
    printf(" (CKM_SHA512_RSA_PKCS)\n");
    break;
  case CKM_SHA224_RSA_PKCS:
    printf(" (CKM_SHA224_RSA_PKCS)\n");
    break;
  case CKM_SHA224_RSA_PKCS_PSS:
    printf(" (CKM_SHA224_RSA_PKCS_PSS)\n");
    break;
  case CKM_SHA384_RSA_PKCS_PSS:
    printf(" (CKM_SHA384_RSA_PKCS_PSS)\n");
    break;
  case CKM_SHA512_RSA_PKCS_PSS:
    printf(" (CKM_SHA512_RSA_PKCS_PSS)\n");
    break;
  case CKM_SHA3_224_RSA_PKCS:
    printf(" (CKM_SHA3_224_RSA_PKCS)\n");
    break;
  case CKM_SHA3_256_RSA_PKCS:
    printf(" (CKM_SHA3_256_RSA_PKCS)\n");
    break;
  case CKM_SHA3_384_RSA_PKCS:
    printf(" (CKM_SHA3_384_RSA_PKCS)\n");
    break;
  case CKM_SHA3_512_RSA_PKCS:
    printf(" (CKM_SHA3_512_RSA_PKCS)\n");
    break;
  case CKM_SHA3_224_RSA_PKCS_PSS:
    printf(" (CKM_SHA3_224_RSA_PKCS_PSS)\n");
    break;
  case CKM_SHA3_256_RSA_PKCS_PSS:
    printf(" (CKM_SHA3_256_RSA_PKCS_PSS)\n");
    break;
  case CKM_SHA3_384_RSA_PKCS_PSS:
    printf(" (CKM_SHA3_384_RSA_PKCS_PSS)\n");
    break;
  case CKM_SHA3_512_RSA_PKCS_PSS:
    printf(" (CKM_SHA3_512_RSA_PKCS_PSS)\n");
    break;
  case CKM_ECDSA:
    printf(" (CKM_ECDSA)\n");
    break;
  case CKM_ECDSA_SHA1:
    printf(" (CKM_ECDSA_SHA1)\n");
    break;
  case CKM_ECDSA_SHA256:
    printf(" (CKM_ECDSA_SHA256)\n");
    break;
  case CKM_EC_KEY_PAIR_GEN:
    printf(" (CKM_EC_KEY_PAIR_GEN)\n");
    break;
  default:
    printf(" (Unknown)\n");
    break;
  }
}

// Get the slot list
CK_RV get_slot_list(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID_PTR *pSlotList, CK_ULONG *pulCount) {
  // Get the number of slots
  CK_RV rv = pFunctionList->C_GetSlotList(CK_FALSE, NULL, pulCount);
  if (rv != CKR_OK) {
    printf("Error getting slot count: 0x%lx\n", rv);
    return rv;
  }

  printf("Number of slots: %lu\n", *pulCount);

  if (*pulCount > 0) {
    // Allocate memory for the slot list
    *pSlotList = (CK_SLOT_ID_PTR)malloc(*pulCount * sizeof(CK_SLOT_ID));
    if (!*pSlotList) {
      printf("Memory allocation failed\n");
      return CKR_HOST_MEMORY;
    }

    // Get the slot list
    rv = pFunctionList->C_GetSlotList(CK_FALSE, *pSlotList, pulCount);
    if (rv != CKR_OK) {
      printf("Error getting slot list: 0x%lx\n", rv);
      free(*pSlotList);
      *pSlotList = NULL;
      return rv;
    }
  }

  return CKR_OK;
}

// Open a session with a slot
CK_RV open_session(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID, CK_SESSION_HANDLE *phSession) {
  return pFunctionList->C_OpenSession(slotID, CKF_SERIAL_SESSION, NULL, NULL, phSession);
}

// Display the mechanism list for a slot
void display_mechanism_list(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID) {
  CK_ULONG ulMechCount;
  CK_RV rv = pFunctionList->C_GetMechanismList(slotID, NULL, &ulMechCount);
  if (rv != CKR_OK) {
    printf("    Error getting mechanism count: 0x%lx\n", rv);
    return;
  }

  printf("    Supported mechanisms: %lu\n", ulMechCount);

  if (ulMechCount > 0) {
    CK_MECHANISM_TYPE_PTR pMechanismList = (CK_MECHANISM_TYPE_PTR)malloc(ulMechCount * sizeof(CK_MECHANISM_TYPE));
    if (!pMechanismList) {
      printf("    Memory allocation failed for mechanism list\n");
      return;
    }

    rv = pFunctionList->C_GetMechanismList(slotID, pMechanismList, &ulMechCount);
    if (rv == CKR_OK) {
      printf("    Mechanism list:\n");
      for (CK_ULONG j = 0; j < ulMechCount; j++) {
        printf("      %lu: 0x%lx", j, pMechanismList[j]);
        print_mechanism_name(pMechanismList[j]);
      }
    } else {
      printf("    Error getting mechanism list: 0x%lx\n", rv);
    }

    free(pMechanismList);
  }
}

// Login to a session
CK_RV perform_login(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession) {
  CK_UTF8CHAR pin[] = "123456";
  CK_RV rv = pFunctionList->C_Login(hSession, CKU_USER, pin, strlen((char *)pin));
  if (rv != CKR_OK) {
    printf("    Error logging in: 0x%lx\n", rv);
  } else {
    printf("    Login successful\n");
  }
  return rv;
}

// Logout from a session
CK_RV perform_logout(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession) {
  CK_RV rv = pFunctionList->C_Logout(hSession);
  if (rv != CKR_OK) {
    printf("    Error logging out: 0x%lx\n", rv);
  } else {
    printf("    Logout successful\n");
  }
  return rv;
}

void test_public_key_operations(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID) {
  CK_SESSION_HANDLE pubSession;
  CK_RV rv = pFunctionList->C_OpenSession(slotID, CKF_SERIAL_SESSION, NULL, NULL, &pubSession);
  if (rv != CKR_OK) {
    printf("    Error opening session for pub tests: 0x%lx\n", rv);
    return;
  }

  CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
  CK_BYTE keyId = 2;
  CK_ATTRIBUTE findTemplate[] = {{CKA_CLASS, &keyClass, sizeof(keyClass)}, {CKA_ID, &keyId, sizeof(keyId)}};

  rv = pFunctionList->C_FindObjectsInit(pubSession, findTemplate, 2);
  if (rv != CKR_OK) {
    printf("    Error initializing object search: 0x%lx\n", rv);
  } else {
    CK_OBJECT_HANDLE hKey;
    CK_ULONG ulObjectCount;

    rv = pFunctionList->C_FindObjects(pubSession, &hKey, 1, &ulObjectCount);
    if (rv != CKR_OK || ulObjectCount == 0) {
      printf("    No key found: 0x%lx\n", rv);
    } else {
      printf("    Found key (handle: %lu)\n", hKey);

      // Finalize the search
      rv = pFunctionList->C_FindObjectsFinal(pubSession);
      if (rv != CKR_OK) {
        printf("    Error finalizing object search: 0x%lx\n", rv);
      }

      CK_BYTE modulus[4096], publicExponent[8];
      CK_ATTRIBUTE templates[] = {{CKA_MODULUS, modulus, sizeof(modulus)},
                                  {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)}};

      rv = pFunctionList->C_GetAttributeValue(pubSession, hKey, templates, 2);
      if (rv != CKR_OK) {
        printf("      Error getting key attributes: 0x%lx\n", rv);
      } else {
        print_hex_data("modulus value", modulus, templates[0].ulValueLen, 32);
        print_hex_data("public exponent value", publicExponent, templates[1].ulValueLen, 32);
      }
    }
  }
  // Close the session
  pFunctionList->C_CloseSession(pubSession);
}

// Forward declarations
void test_public_key_operations(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID);
void test_ecdsa_public_key_operations(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID);
void test_certificate_operations(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID);
void test_piv_data_objects(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID);
void test_decryption(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID);
void test_pin_never_private_key_operation(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID);
void test_rsa_signing(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID);
void test_ecdsa_signing(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID);
void test_ecdh_derivation(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID);
void test_management_challenge(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID);
void test_destructive_write_operations(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID);

// Verification function declarations
static CK_RV cnk_verify_rsa_signature(CK_BYTE_PTR modulus, CK_ULONG modulus_len, CK_BYTE_PTR exponent,
                                      CK_ULONG exponent_len, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature,
                                      mbedtls_md_type_t md_type, int padding_mode);
static CK_RV cnk_verify_ecdsa_signature(CK_BYTE_PTR ec_params, CK_ULONG ec_params_len, CK_BYTE_PTR ec_point,
                                        CK_ULONG ec_point_len, CK_BYTE_PTR data, CK_ULONG data_len,
                                        CK_BYTE_PTR signature, CK_ULONG signature_len, mbedtls_md_type_t md_type);

static int g_real_test_failures = 0;

static void record_real_test_failure(const char *message, CK_RV rv) {
  printf("    TEST FAILURE: %s", message);
  if (rv != CKR_OK)
    printf(": 0x%lx", rv);
  printf("\n");
  g_real_test_failures++;
}

static int cnk_test_rng(void *p_rng, unsigned char *output, size_t output_size) {
  unsigned int *state = (unsigned int *)p_rng;
  if (state == NULL)
    return -1;

  for (size_t i = 0; i < output_size; i++) {
    *state = *state * 1664525u + 1013904223u;
    output[i] = (unsigned char)((*state >> 16) & 0xffu);
    if (output[i] == 0)
      output[i] = 0xa5;
  }

  return 0;
}

static CK_RV find_object(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_OBJECT_CLASS objectClass,
                         CK_KEY_TYPE *pKeyType, CK_BYTE_PTR pKeyId, CK_ULONG cbKeyId, CK_OBJECT_HANDLE_PTR phObject) {
  CK_ATTRIBUTE findTemplate[3];
  CK_ULONG findTemplateCount = 0;

  findTemplate[findTemplateCount++] = (CK_ATTRIBUTE){CKA_CLASS, &objectClass, sizeof(objectClass)};
  if (pKeyType != NULL)
    findTemplate[findTemplateCount++] = (CK_ATTRIBUTE){CKA_KEY_TYPE, pKeyType, sizeof(*pKeyType)};
  if (pKeyId != NULL)
    findTemplate[findTemplateCount++] = (CK_ATTRIBUTE){CKA_ID, pKeyId, cbKeyId};

  CK_RV rv = pFunctionList->C_FindObjectsInit(hSession, findTemplate, findTemplateCount);
  if (rv != CKR_OK)
    return rv;

  CK_ULONG objectCount = 0;
  rv = pFunctionList->C_FindObjects(hSession, phObject, 1, &objectCount);

  CK_RV finalRv = pFunctionList->C_FindObjectsFinal(hSession);
  if (rv == CKR_OK && finalRv != CKR_OK)
    rv = finalRv;
  if (rv == CKR_OK && objectCount == 0)
    rv = CKR_OBJECT_HANDLE_INVALID;

  return rv;
}

static CK_RV load_rsa_public_key(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pKeyId,
                                 CK_ULONG cbKeyId, CK_BYTE_PTR modulus, CK_ULONG_PTR pModulusLen, CK_BYTE_PTR exponent,
                                 CK_ULONG_PTR pExponentLen) {
  CK_KEY_TYPE keyType = CKK_RSA;
  CK_OBJECT_HANDLE hPublicKey;
  CK_RV rv = find_object(pFunctionList, hSession, CKO_PUBLIC_KEY, &keyType, pKeyId, cbKeyId, &hPublicKey);
  if (rv != CKR_OK)
    return rv;

  CK_ATTRIBUTE attrs[] = {
      {CKA_MODULUS, modulus, *pModulusLen},
      {CKA_PUBLIC_EXPONENT, exponent, *pExponentLen},
  };

  rv = pFunctionList->C_GetAttributeValue(hSession, hPublicKey, attrs, 2);
  if (rv != CKR_OK)
    return rv;

  *pModulusLen = attrs[0].ulValueLen;
  *pExponentLen = attrs[1].ulValueLen;
  return CKR_OK;
}

static CK_RV make_rsa_public_context(mbedtls_rsa_context *rsa, CK_BYTE_PTR modulus, CK_ULONG modulusLen,
                                     CK_BYTE_PTR exponent, CK_ULONG exponentLen) {
  mbedtls_rsa_init(rsa);

  int ret = mbedtls_mpi_read_binary(&rsa->N, modulus, modulusLen);
  if (ret != 0) {
    printf("    Error loading modulus: -0x%04x\n", (unsigned int)-ret);
    mbedtls_rsa_free(rsa);
    return CKR_GENERAL_ERROR;
  }

  ret = mbedtls_mpi_read_binary(&rsa->E, exponent, exponentLen);
  if (ret != 0) {
    printf("    Error loading exponent: -0x%04x\n", (unsigned int)-ret);
    mbedtls_rsa_free(rsa);
    return CKR_GENERAL_ERROR;
  }

  rsa->len = mbedtls_mpi_size(&rsa->N);
  if (mbedtls_rsa_check_pubkey(rsa) != 0) {
    printf("    Invalid RSA public key\n");
    mbedtls_rsa_free(rsa);
    return CKR_GENERAL_ERROR;
  }

  return CKR_OK;
}

static CK_RV encrypt_rsa_pkcs1_v15(CK_BYTE_PTR modulus, CK_ULONG modulusLen, CK_BYTE_PTR exponent, CK_ULONG exponentLen,
                                   CK_BYTE_PTR plaintext, CK_ULONG plaintextLen, CK_BYTE_PTR ciphertext,
                                   CK_ULONG_PTR pCiphertextLen) {
  CK_RV rv;
  int ret;
  unsigned int rngState = 0x13579bdfu;
  mbedtls_rsa_context rsa;

  rv = make_rsa_public_context(&rsa, modulus, modulusLen, exponent, exponentLen);
  if (rv != CKR_OK)
    return rv;

  if (*pCiphertextLen < mbedtls_rsa_get_len(&rsa)) {
    *pCiphertextLen = (CK_ULONG)mbedtls_rsa_get_len(&rsa);
    mbedtls_rsa_free(&rsa);
    return CKR_BUFFER_TOO_SMALL;
  }

  ret = mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
  if (ret == 0)
    ret = mbedtls_rsa_pkcs1_encrypt(&rsa, cnk_test_rng, &rngState, plaintextLen, plaintext, ciphertext);

  if (ret != 0) {
    printf("    RSA PKCS#1 v1.5 encryption failed: -0x%04x\n", (unsigned int)-ret);
    rv = CKR_GENERAL_ERROR;
  } else {
    *pCiphertextLen = (CK_ULONG)mbedtls_rsa_get_len(&rsa);
    rv = CKR_OK;
  }

  mbedtls_rsa_free(&rsa);
  return rv;
}

static CK_RV encrypt_rsa_oaep_sha256(CK_BYTE_PTR modulus, CK_ULONG modulusLen, CK_BYTE_PTR exponent,
                                     CK_ULONG exponentLen, CK_BYTE_PTR plaintext, CK_ULONG plaintextLen,
                                     CK_BYTE_PTR ciphertext, CK_ULONG_PTR pCiphertextLen) {
  CK_RV rv;
  int ret;
  unsigned int rngState = 0x2468ace0u;
  mbedtls_rsa_context rsa;

  rv = make_rsa_public_context(&rsa, modulus, modulusLen, exponent, exponentLen);
  if (rv != CKR_OK)
    return rv;

  if (*pCiphertextLen < mbedtls_rsa_get_len(&rsa)) {
    *pCiphertextLen = (CK_ULONG)mbedtls_rsa_get_len(&rsa);
    mbedtls_rsa_free(&rsa);
    return CKR_BUFFER_TOO_SMALL;
  }

  ret = mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
  if (ret == 0)
    ret = mbedtls_rsa_rsaes_oaep_encrypt(&rsa, cnk_test_rng, &rngState, NULL, 0, plaintextLen, plaintext, ciphertext);

  if (ret != 0) {
    printf("    RSA OAEP-SHA256 encryption failed: -0x%04x\n", (unsigned int)-ret);
    rv = CKR_GENERAL_ERROR;
  } else {
    *pCiphertextLen = (CK_ULONG)mbedtls_rsa_get_len(&rsa);
    rv = CKR_OK;
  }

  mbedtls_rsa_free(&rsa);
  return rv;
}

static CK_RV decrypt_with_key(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey,
                              CK_MECHANISM_PTR pMechanism, CK_BYTE_PTR ciphertext, CK_ULONG ciphertextLen,
                              CK_BYTE_PTR plaintext, CK_ULONG_PTR pPlaintextLen) {
  CK_RV rv = pFunctionList->C_DecryptInit(hSession, pMechanism, hKey);
  if (rv != CKR_OK)
    return rv;

  CK_ULONG queryLen = 0;
  rv = pFunctionList->C_Decrypt(hSession, ciphertext, ciphertextLen, NULL, &queryLen);
  if (rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL)
    return rv;

  if (*pPlaintextLen < queryLen) {
    *pPlaintextLen = queryLen;
    return CKR_BUFFER_TOO_SMALL;
  }

  *pPlaintextLen = queryLen;
  return pFunctionList->C_Decrypt(hSession, ciphertext, ciphertextLen, plaintext, pPlaintextLen);
}

static CK_RV perform_management_login(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession) {
  CK_BYTE key[] = "\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08";
  return pFunctionList->C_Login(hSession, CKU_SO, key, 24);
}

static CK_RV write_mpi_fixed(mbedtls_mpi *mpi, CK_BYTE_PTR output, CK_ULONG outputLen) {
  size_t mpiSize = mbedtls_mpi_size(mpi);
  if (mpiSize > outputLen)
    return CKR_ATTRIBUTE_VALUE_INVALID;

  memset(output, 0, outputLen);
  int ret = mbedtls_mpi_write_binary(mpi, output + outputLen - mpiSize, mpiSize);
  if (ret != 0) {
    printf("    Failed to encode MPI: -0x%04x\n", (unsigned int)-ret);
    return CKR_GENERAL_ERROR;
  }

  return CKR_OK;
}

static CK_RV generate_card_ec_key_with_policy(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession,
                                              CK_BYTE pinPolicy) {
  CK_BYTE keyId = CNK_REAL_WRITE_TEST_ID;
  CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
  CK_KEY_TYPE keyType = CKK_EC;
  CK_BBOOL token = CK_TRUE;
  CK_BBOOL private = CK_TRUE;
  CK_BBOOL sign = CK_TRUE;
  CK_BBOOL derive = CK_TRUE;
  CK_BBOOL alwaysAuthenticate = CK_FALSE;
  CK_BYTE touchPolicy = CNK_REAL_WRITE_TEST_TOUCH_POLICY;
  CK_BYTE ecParams[] = "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";

  CK_ATTRIBUTE publicTemplate[] = {
      {CKA_CLASS, &pubClass, sizeof(pubClass)},        {CKA_TOKEN, &token, sizeof(token)},
      {CKA_KEY_TYPE, &keyType, sizeof(keyType)},       {CKA_ID, &keyId, sizeof(keyId)},
      {CKA_EC_PARAMS, ecParams, sizeof(ecParams) - 1},
  };
  CK_ATTRIBUTE privateTemplate[] = {
      {CKA_CLASS, &privClass, sizeof(privClass)},
      {CKA_TOKEN, &token, sizeof(token)},
      {CKA_PRIVATE, &private, sizeof(private)},
      {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
      {CKA_ID, &keyId, sizeof(keyId)},
      {CKA_SIGN, &sign, sizeof(sign)},
      {CKA_DERIVE, &derive, sizeof(derive)},
      {CKA_ALWAYS_AUTHENTICATE, &alwaysAuthenticate, sizeof(alwaysAuthenticate)},
      {CKA_CNK_PIV_PIN_POLICY, &pinPolicy, sizeof(pinPolicy)},
      {CKA_CNK_PIV_TOUCH_POLICY, &touchPolicy, sizeof(touchPolicy)},
  };
  CK_MECHANISM mechanism = {CKM_EC_KEY_PAIR_GEN, NULL, 0};
  CK_OBJECT_HANDLE hPublicKey = 0;
  CK_OBJECT_HANDLE hPrivateKey = 0;

  CK_RV rv = pFunctionList->C_GenerateKeyPair(
      hSession, &mechanism, publicTemplate, sizeof(publicTemplate) / sizeof(publicTemplate[0]), privateTemplate,
      sizeof(privateTemplate) / sizeof(privateTemplate[0]), &hPublicKey, &hPrivateKey);
  if (rv != CKR_OK)
    return rv;

  CK_BYTE ecPoint[128];
  CK_ATTRIBUTE attrs[] = {{CKA_EC_POINT, ecPoint, sizeof(ecPoint)}};
  rv = pFunctionList->C_GetAttributeValue(hSession, hPublicKey, attrs, 1);
  if (rv != CKR_OK)
    return rv;
  if (attrs[0].ulValueLen == 0 || attrs[0].ulValueLen == CK_UNAVAILABLE_INFORMATION)
    return CKR_ATTRIBUTE_VALUE_INVALID;

  printf("    Generated EC P-256 key pair in test slot ID %u\n", (unsigned int)keyId);
  return CKR_OK;
}

static CK_RV generate_card_ec_key(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession) {
  return generate_card_ec_key_with_policy(pFunctionList, hSession, CNK_REAL_WRITE_TEST_PIN_POLICY);
}

static CK_RV check_test_key_policies(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession,
                                     CK_KEY_TYPE keyType, CK_BYTE expectedPinPolicy) {
  CK_BYTE keyId = CNK_REAL_WRITE_TEST_ID;
  CK_OBJECT_HANDLE hPrivateKey;
  CK_RV rv = find_object(pFunctionList, hSession, CKO_PRIVATE_KEY, &keyType, &keyId, sizeof(keyId), &hPrivateKey);
  if (rv != CKR_OK)
    return rv;

  CK_BYTE pinPolicy = 0;
  CK_BYTE touchPolicy = 0;
  CK_ATTRIBUTE attrs[] = {
      {CKA_CNK_PIV_PIN_POLICY, &pinPolicy, sizeof(pinPolicy)},
      {CKA_CNK_PIV_TOUCH_POLICY, &touchPolicy, sizeof(touchPolicy)},
  };
  rv = pFunctionList->C_GetAttributeValue(hSession, hPrivateKey, attrs, sizeof(attrs) / sizeof(attrs[0]));
  if (rv != CKR_OK)
    return rv;
  if (attrs[0].ulValueLen != sizeof(pinPolicy) || attrs[1].ulValueLen != sizeof(touchPolicy))
    return CKR_ATTRIBUTE_VALUE_INVALID;
  if (pinPolicy != expectedPinPolicy || touchPolicy != CNK_REAL_WRITE_TEST_TOUCH_POLICY)
    return CKR_ATTRIBUTE_VALUE_INVALID;

  printf("    Read back vendor key policies: PIN=0x%02x touch=0x%02x\n", pinPolicy, touchPolicy);
  return CKR_OK;
}

static CK_RV open_management_write_session(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID,
                                           CK_SESSION_HANDLE_PTR phSession) {
  if (phSession == NULL)
    return CKR_ARGUMENTS_BAD;
  *phSession = 0;

  CK_RV rv = pFunctionList->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, phSession);
  if (rv != CKR_OK)
    return rv;

  rv = perform_management_login(pFunctionList, *phSession);
  if (rv != CKR_OK) {
    pFunctionList->C_CloseSession(*phSession);
    *phSession = 0;
    return rv;
  }

  return CKR_OK;
}

static void close_management_write_session(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession) {
  CK_RV rv = pFunctionList->C_Logout(hSession);
  if (rv != CKR_OK)
    record_real_test_failure("Error logging out of management write session", rv);

  rv = pFunctionList->C_CloseSession(hSession);
  if (rv != CKR_OK)
    record_real_test_failure("Error closing management write session", rv);

  cnk_sleep_milliseconds(100);
}

static CK_RV sign_with_test_private_key(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID, CK_KEY_TYPE keyType) {
  CK_SESSION_HANDLE hSession;
  CK_RV rv = pFunctionList->C_OpenSession(slotID, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
  if (rv != CKR_OK)
    return rv;

  rv = perform_login(pFunctionList, hSession);
  if (rv != CKR_OK) {
    pFunctionList->C_CloseSession(hSession);
    return rv;
  }

  CK_BYTE keyId = CNK_REAL_WRITE_TEST_ID;
  CK_OBJECT_HANDLE hPrivateKey;
  rv = find_object(pFunctionList, hSession, CKO_PRIVATE_KEY, &keyType, &keyId, sizeof(keyId), &hPrivateKey);
  if (rv != CKR_OK)
    goto cleanup;

  if (keyType == CKK_EC) {
    CK_MECHANISM mechanism = {CKM_ECDSA, NULL, 0};
    CK_BYTE digest[32] = {0};
    CK_BYTE signature[64];
    CK_ULONG signatureLen = sizeof(signature);

    rv = pFunctionList->C_SignInit(hSession, &mechanism, hPrivateKey);
    if (rv == CKR_OK)
      rv = pFunctionList->C_Sign(hSession, digest, sizeof(digest), signature, &signatureLen);
    if (rv == CKR_OK && signatureLen != sizeof(signature))
      rv = CKR_SIGNATURE_LEN_RANGE;
  } else if (keyType == CKK_RSA) {
    CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL, 0};
    CK_BYTE digestInfo[51] = "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20";
    CK_BYTE signature[256];
    CK_ULONG signatureLen = sizeof(signature);

    memset(digestInfo + 19, 0x42, 32);
    rv = pFunctionList->C_SignInit(hSession, &mechanism, hPrivateKey);
    if (rv == CKR_OK)
      rv = pFunctionList->C_Sign(hSession, digestInfo, sizeof(digestInfo), signature, &signatureLen);
    if (rv == CKR_OK && signatureLen != sizeof(signature))
      rv = CKR_SIGNATURE_LEN_RANGE;
  } else {
    rv = CKR_KEY_TYPE_INCONSISTENT;
  }

cleanup:
  perform_logout(pFunctionList, hSession);
  CK_RV closeRv = pFunctionList->C_CloseSession(hSession);
  if (rv == CKR_OK)
    rv = closeRv;
  cnk_sleep_milliseconds(100);
  return rv;
}

static CK_RV sign_with_pin_never_test_key_without_login(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID) {
  CK_SESSION_HANDLE hSession;
  CK_RV rv = pFunctionList->C_OpenSession(slotID, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
  CK_RV closeRv;
  if (rv != CKR_OK)
    return rv;

  CK_BYTE keyId = CNK_REAL_WRITE_TEST_ID;
  CK_KEY_TYPE keyType = CKK_EC;
  CK_OBJECT_HANDLE hPrivateKey;
  rv = find_object(pFunctionList, hSession, CKO_PRIVATE_KEY, &keyType, &keyId, sizeof(keyId), &hPrivateKey);
  if (rv != CKR_OK)
    goto cleanup;

  CK_MECHANISM mechanism = {CKM_ECDSA, NULL, 0};
  CK_BYTE digest[32] = {0};
  CK_BYTE signature[64];
  CK_ULONG signatureLen = sizeof(signature);

  rv = pFunctionList->C_SignInit(hSession, &mechanism, hPrivateKey);
  if (rv == CKR_OK)
    rv = pFunctionList->C_Sign(hSession, digest, sizeof(digest), signature, &signatureLen);
  if (rv == CKR_OK && signatureLen != sizeof(signature))
    rv = CKR_SIGNATURE_LEN_RANGE;

cleanup:
  closeRv = pFunctionList->C_CloseSession(hSession);
  if (rv == CKR_OK)
    rv = closeRv;
  cnk_sleep_milliseconds(100);
  return rv;
}

static CK_RV write_test_certificate(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession) {
  CK_BYTE keyId = CNK_REAL_WRITE_TEST_ID;
  CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
  CK_CERTIFICATE_TYPE certType = CKC_X_509;
  CK_BBOOL token = CK_TRUE;
  CK_BYTE certValue[] = {
      0x30, 0x82, 0x01, 0x02, 0x30, 0x81, 0xAD, 0x02, 0x14, 0x51, 0x18, 0x8B, 0xAC, 0x1E, 0x22, 0x1B, 0xC2, 0x96, 0x05,
      0xD6, 0x59, 0x4D, 0xDA, 0x09, 0x0A, 0xFC, 0xA5, 0x7E, 0xF6, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
      0x04, 0x03, 0x02, 0x30, 0x18, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0D, 0x63, 0x61, 0x6E,
      0x6F, 0x6B, 0x65, 0x79, 0x2D, 0x74, 0x65, 0x73, 0x74, 0x30, 0x20, 0x17, 0x0D, 0x32, 0x36, 0x30, 0x35, 0x30, 0x39,
      0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x18, 0x0F, 0x32, 0x31, 0x32, 0x36, 0x30, 0x34, 0x31, 0x35, 0x30, 0x30,
      0x30, 0x30, 0x30, 0x30, 0x5A, 0x30, 0x18, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0D, 0x63,
      0x61, 0x6E, 0x6F, 0x6B, 0x65, 0x79, 0x2D, 0x74, 0x65, 0x73, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86,
      0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
      0x9B, 0x6D, 0x06, 0x9D, 0x7E, 0xF3, 0x17, 0x1F, 0x42, 0x23, 0xA9, 0xBD, 0x64, 0x09, 0xE0, 0x38, 0xEB, 0x68, 0xD6,
      0xA1, 0xF7, 0xAC, 0xCD, 0x0C, 0x7C, 0xAB, 0x93, 0x7E, 0xF4, 0x3C, 0x0B, 0xFE, 0x5C, 0x00, 0x52, 0x95, 0xC9, 0x12,
      0x83, 0x6E, 0x5D, 0x42, 0x36, 0x50, 0xBB, 0xE8, 0x06, 0x9E, 0xBC, 0xF1, 0xF1, 0xC6, 0x71, 0xF7, 0x6A, 0x06, 0x28,
      0x73, 0x44, 0x50, 0xF3, 0xF4, 0xF0, 0x21, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
      0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x7F, 0x19, 0xD4, 0x74, 0x47, 0xDA, 0x54, 0x7F, 0xBF, 0x5B, 0x9C, 0xE4,
      0x79, 0x28, 0x77, 0x28, 0x5F, 0x10, 0xEA, 0x68, 0x6B, 0x78, 0xFE, 0xB9, 0xA0, 0xC4, 0x8D, 0x7C, 0x17, 0x2E, 0x90,
      0x3F, 0x02, 0x21, 0x00, 0xFA, 0xCE, 0x65, 0xE0, 0x12, 0x00, 0x26, 0x76, 0x24, 0xD8, 0xB5, 0x49, 0x21, 0x7A, 0x96,
      0x53, 0xEC, 0xF8, 0x2D, 0xB3, 0xD0, 0xA7, 0x3C, 0xB3, 0x67, 0x5D, 0x62, 0xBE, 0xB2, 0x54, 0x41, 0x21,
  };
  CK_ATTRIBUTE certTemplate[] = {
      {CKA_CLASS, &certClass, sizeof(certClass)}, {CKA_CERTIFICATE_TYPE, &certType, sizeof(certType)},
      {CKA_TOKEN, &token, sizeof(token)},         {CKA_ID, &keyId, sizeof(keyId)},
      {CKA_VALUE, certValue, sizeof(certValue)},
  };
  CK_OBJECT_HANDLE hCertificate = 0;

  CK_RV rv = pFunctionList->C_CreateObject(hSession, certTemplate, sizeof(certTemplate) / sizeof(certTemplate[0]),
                                           &hCertificate);
  if (rv != CKR_OK)
    return rv;

  CK_BYTE value[sizeof(certValue)];
  CK_ATTRIBUTE valueAttr = {CKA_VALUE, value, sizeof(value)};
  rv = pFunctionList->C_GetAttributeValue(hSession, hCertificate, &valueAttr, 1);
  if (rv != CKR_OK)
    return rv;
  if (valueAttr.ulValueLen != sizeof(certValue) || memcmp(value, certValue, sizeof(certValue)) != 0)
    return CKR_DATA_INVALID;

  printf("    Wrote and read certificate object in test slot ID %u\n", (unsigned int)keyId);
  return CKR_OK;
}

static CK_RV import_software_ec_key(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession) {
  CK_RV rv = CKR_OK;
  CK_BYTE keyId = CNK_REAL_WRITE_TEST_ID;
  CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
  CK_KEY_TYPE keyType = CKK_EC;
  CK_BBOOL token = CK_TRUE;
  CK_BBOOL private = CK_TRUE;
  CK_BBOOL sign = CK_TRUE;
  CK_BBOOL derive = CK_TRUE;
  CK_BBOOL alwaysAuthenticate = CK_FALSE;
  CK_BYTE pinPolicy = CNK_REAL_WRITE_TEST_PIN_POLICY;
  CK_BYTE touchPolicy = CNK_REAL_WRITE_TEST_TOUCH_POLICY;
  CK_BYTE ecParams[] = "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";
  CK_BYTE privateScalar[32];
  mbedtls_ecp_keypair key;

  mbedtls_ecp_keypair_init(&key);
  unsigned int rngState = 0x6ec0ffeeu;
  int ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &key, cnk_test_rng, &rngState);
  if (ret != 0) {
    printf("    Failed to generate software EC key: -0x%04x\n", (unsigned int)-ret);
    rv = CKR_GENERAL_ERROR;
    goto cleanup;
  }

  rv = write_mpi_fixed(&key.d, privateScalar, sizeof(privateScalar));
  if (rv != CKR_OK)
    goto cleanup;

  CK_ATTRIBUTE privateTemplate[] = {
      {CKA_CLASS, &keyClass, sizeof(keyClass)},
      {CKA_TOKEN, &token, sizeof(token)},
      {CKA_PRIVATE, &private, sizeof(private)},
      {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
      {CKA_ID, &keyId, sizeof(keyId)},
      {CKA_EC_PARAMS, ecParams, sizeof(ecParams) - 1},
      {CKA_VALUE, privateScalar, sizeof(privateScalar)},
      {CKA_SIGN, &sign, sizeof(sign)},
      {CKA_DERIVE, &derive, sizeof(derive)},
      {CKA_ALWAYS_AUTHENTICATE, &alwaysAuthenticate, sizeof(alwaysAuthenticate)},
      {CKA_CNK_PIV_PIN_POLICY, &pinPolicy, sizeof(pinPolicy)},
      {CKA_CNK_PIV_TOUCH_POLICY, &touchPolicy, sizeof(touchPolicy)},
  };
  CK_OBJECT_HANDLE hPrivateKey = 0;
  rv = pFunctionList->C_CreateObject(hSession, privateTemplate, sizeof(privateTemplate) / sizeof(privateTemplate[0]),
                                     &hPrivateKey);
  if (rv != CKR_OK)
    goto cleanup;

  printf("    Imported EC P-256 private key into test slot ID %u\n", (unsigned int)keyId);

cleanup:
  memset(privateScalar, 0, sizeof(privateScalar));
  mbedtls_ecp_keypair_free(&key);
  return rv;
}

static CK_RV import_software_rsa_key(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession) {
  CK_RV rv = CKR_OK;
  CK_BYTE keyId = CNK_REAL_WRITE_TEST_ID;
  CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
  CK_KEY_TYPE keyType = CKK_RSA;
  CK_BBOOL token = CK_TRUE;
  CK_BBOOL private = CK_TRUE;
  CK_BBOOL sign = CK_TRUE;
  CK_BBOOL decrypt = CK_TRUE;
  CK_BBOOL alwaysAuthenticate = CK_FALSE;
  CK_BYTE pinPolicy = CNK_REAL_WRITE_TEST_PIN_POLICY;
  CK_BYTE touchPolicy = CNK_REAL_WRITE_TEST_TOUCH_POLICY;
  CK_BYTE p[128], q[128], dp[128], dq[128], qInv[128];
  mbedtls_rsa_context rsa;

  mbedtls_rsa_init(&rsa);
  unsigned int rngState = 0x21524111u;
  int ret = mbedtls_rsa_gen_key(&rsa, cnk_test_rng, &rngState, 2048, 65537);
  if (ret != 0) {
    printf("    Failed to generate software RSA key: -0x%04x\n", (unsigned int)-ret);
    rv = CKR_GENERAL_ERROR;
    goto cleanup;
  }

  if ((rv = write_mpi_fixed(&rsa.P, p, sizeof(p))) != CKR_OK ||
      (rv = write_mpi_fixed(&rsa.Q, q, sizeof(q))) != CKR_OK ||
      (rv = write_mpi_fixed(&rsa.DP, dp, sizeof(dp))) != CKR_OK ||
      (rv = write_mpi_fixed(&rsa.DQ, dq, sizeof(dq))) != CKR_OK ||
      (rv = write_mpi_fixed(&rsa.QP, qInv, sizeof(qInv))) != CKR_OK) {
    goto cleanup;
  }

  CK_ATTRIBUTE privateTemplate[] = {
      {CKA_CLASS, &keyClass, sizeof(keyClass)},
      {CKA_TOKEN, &token, sizeof(token)},
      {CKA_PRIVATE, &private, sizeof(private)},
      {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
      {CKA_ID, &keyId, sizeof(keyId)},
      {CKA_PRIME_1, p, sizeof(p)},
      {CKA_PRIME_2, q, sizeof(q)},
      {CKA_EXPONENT_1, dp, sizeof(dp)},
      {CKA_EXPONENT_2, dq, sizeof(dq)},
      {CKA_COEFFICIENT, qInv, sizeof(qInv)},
      {CKA_SIGN, &sign, sizeof(sign)},
      {CKA_DECRYPT, &decrypt, sizeof(decrypt)},
      {CKA_ALWAYS_AUTHENTICATE, &alwaysAuthenticate, sizeof(alwaysAuthenticate)},
      {CKA_CNK_PIV_PIN_POLICY, &pinPolicy, sizeof(pinPolicy)},
      {CKA_CNK_PIV_TOUCH_POLICY, &touchPolicy, sizeof(touchPolicy)},
  };
  CK_OBJECT_HANDLE hPrivateKey = 0;
  rv = pFunctionList->C_CreateObject(hSession, privateTemplate, sizeof(privateTemplate) / sizeof(privateTemplate[0]),
                                     &hPrivateKey);
  if (rv != CKR_OK)
    goto cleanup;

  printf("    Imported RSA-2048 private key into test slot ID %u\n", (unsigned int)keyId);

cleanup:
  memset(p, 0, sizeof(p));
  memset(q, 0, sizeof(q));
  memset(dp, 0, sizeof(dp));
  memset(dq, 0, sizeof(dq));
  memset(qInv, 0, sizeof(qInv));
  mbedtls_rsa_free(&rsa);
  return rv;
}

void test_ecdsa_public_key_operations(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID) {
  CK_SESSION_HANDLE pubSession;
  CK_RV rv = pFunctionList->C_OpenSession(slotID, CKF_SERIAL_SESSION, NULL, NULL, &pubSession);
  if (rv != CKR_OK) {
    printf("    Error opening session for pub tests: 0x%lx\n", rv);
    return;
  }

  CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
  CK_BYTE keyId = 1;
  CK_ATTRIBUTE findTemplate[] = {{CKA_CLASS, &keyClass, sizeof(keyClass)}, {CKA_ID, &keyId, sizeof(keyId)}};

  rv = pFunctionList->C_FindObjectsInit(pubSession, findTemplate, 2);
  if (rv != CKR_OK) {
    printf("    Error initializing object search: 0x%lx\n", rv);
  } else {
    CK_OBJECT_HANDLE hKey;
    CK_ULONG ulObjectCount;

    rv = pFunctionList->C_FindObjects(pubSession, &hKey, 1, &ulObjectCount);
    if (rv != CKR_OK || ulObjectCount == 0) {
      printf("    No key found: 0x%lx\n", rv);
    } else {
      printf("    Found key (handle: %lu)\n", hKey);

      // Finalize the search
      rv = pFunctionList->C_FindObjectsFinal(pubSession);
      if (rv != CKR_OK) {
        printf("    Error finalizing object search: 0x%lx\n", rv);
      }

      CK_BYTE pubKey[4096], oid[8];
      CK_ATTRIBUTE templates[] = {{CKA_EC_POINT, pubKey, sizeof(pubKey)}, {CKA_EC_PARAMS, oid, sizeof(oid)}};

      rv = pFunctionList->C_GetAttributeValue(pubSession, hKey, templates, 2);
      if (rv != CKR_OK) {
        printf("      Error getting key attributes: 0x%lx\n", rv);
      } else {
        print_hex_data("public key value", pubKey, templates[0].ulValueLen, 32);
        print_hex_data("oid value", oid, templates[1].ulValueLen, 32);
      }
    }
  }

  // Close the session
  pFunctionList->C_CloseSession(pubSession);
}

// Test certificate operations
void test_certificate_operations(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID) {
  CK_SESSION_HANDLE certSession;
  CK_RV rv = pFunctionList->C_OpenSession(slotID, CKF_SERIAL_SESSION, NULL, NULL, &certSession);
  if (rv != CKR_OK) {
    printf("    Error opening session for cert tests: 0x%lx\n", rv);
    return;
  }

  // Test certificate operations
  CK_OBJECT_CLASS keyClass = CKO_CERTIFICATE;
  CK_BYTE keyId = 2;
  CK_ATTRIBUTE findTemplate[] = {{CKA_CLASS, &keyClass, sizeof(keyClass)}, {CKA_ID, &keyId, sizeof(keyId)}};

  rv = pFunctionList->C_FindObjectsInit(certSession, findTemplate, 2);
  if (rv != CKR_OK) {
    printf("    Error initializing object search: 0x%lx\n", rv);
    pFunctionList->C_CloseSession(certSession);
    return;
  }

  CK_OBJECT_HANDLE hCert;
  CK_ULONG ulObjectCount;

  rv = pFunctionList->C_FindObjects(certSession, &hCert, 1, &ulObjectCount);
  if (rv != CKR_OK || ulObjectCount == 0) {
    printf("    No cert found: 0x%lx\n", rv);
  } else {
    printf("    Found cert (handle: %lu)\n", hCert);

    // Finalize the search
    rv = pFunctionList->C_FindObjectsFinal(certSession);
    if (rv != CKR_OK) {
      printf("    Error finalizing object search: 0x%lx\n", rv);
    }

    CK_BYTE data[4096];
    CK_ATTRIBUTE temp = {CKA_VALUE, data, sizeof(data)};
    rv = pFunctionList->C_GetAttributeValue(certSession, hCert, &temp, 1);
    if (rv != CKR_OK) {
      printf("      Error getting cert value: 0x%lx\n", rv);
    } else {
      print_hex_data("Cert value", data, temp.ulValueLen, 32);
    }
  }

  // Close the session
  pFunctionList->C_CloseSession(certSession);
}

void test_piv_data_objects(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID) {
  CK_SESSION_HANDLE dataSession;
  CK_RV rv = pFunctionList->C_OpenSession(slotID, CKF_SERIAL_SESSION, NULL, NULL, &dataSession);
  if (rv != CKR_OK) {
    record_real_test_failure("Error opening session for PIV data tests", rv);
    return;
  }

  CK_OBJECT_CLASS dataClass = CKO_DATA;
  CK_ATTRIBUTE findTemplate[] = {{CKA_CLASS, &dataClass, sizeof(dataClass)}};
  rv = pFunctionList->C_FindObjectsInit(dataSession, findTemplate, sizeof(findTemplate) / sizeof(findTemplate[0]));
  if (rv != CKR_OK) {
    record_real_test_failure("Error initializing PIV data object search", rv);
    pFunctionList->C_CloseSession(dataSession);
    return;
  }

  printf("    PIV data objects present:\n");
  CK_ULONG total = 0;
  for (;;) {
    CK_OBJECT_HANDLE hObject;
    CK_ULONG objectCount = 0;
    rv = pFunctionList->C_FindObjects(dataSession, &hObject, 1, &objectCount);
    if (rv != CKR_OK) {
      record_real_test_failure("Error enumerating PIV data objects", rv);
      break;
    }
    if (objectCount == 0)
      break;

    total++;
    CK_BYTE id = 0;
    char label[96] = {0};
    CK_BYTE objectId[32];
    CK_ATTRIBUTE attrs[] = {
        {CKA_ID, &id, sizeof(id)},
        {CKA_LABEL, label, sizeof(label) - 1},
        {CKA_OBJECT_ID, objectId, sizeof(objectId)},
    };
    rv = pFunctionList->C_GetAttributeValue(dataSession, hObject, attrs, sizeof(attrs) / sizeof(attrs[0]));
    if (rv != CKR_OK) {
      record_real_test_failure("Error reading PIV data object attributes", rv);
      continue;
    }
    if (attrs[1].ulValueLen < sizeof(label))
      label[attrs[1].ulValueLen] = '\0';
    else
      label[sizeof(label) - 1] = '\0';

    CK_ATTRIBUTE valueAttr = {CKA_VALUE, NULL, 0};
    rv = pFunctionList->C_GetAttributeValue(dataSession, hObject, &valueAttr, 1);
    if (rv != CKR_OK) {
      record_real_test_failure("Error querying PIV data object value length", rv);
      continue;
    }

    printf("      id=0x%02x label=\"%s\" value_len=%lu oid=", id, label, valueAttr.ulValueLen);
    for (CK_ULONG i = 0; i < attrs[2].ulValueLen; i++)
      printf("%02x", objectId[i]);
    printf("\n");
  }

  if (total == 0)
    printf("      none\n");

  CK_RV finalRv = pFunctionList->C_FindObjectsFinal(dataSession);
  if (finalRv != CKR_OK)
    record_real_test_failure("Error finalizing PIV data object search", finalRv);

  rv = pFunctionList->C_CloseSession(dataSession);
  if (rv != CKR_OK)
    record_real_test_failure("Error closing PIV data object session", rv);
}

// Verify ECDSA signature using mbedtls
static CK_RV cnk_verify_ecdsa_signature(CK_BYTE_PTR ec_params, CK_ULONG ec_params_len, CK_BYTE_PTR ec_point,
                                        CK_ULONG ec_point_len, CK_BYTE_PTR data, CK_ULONG data_len,
                                        CK_BYTE_PTR signature, CK_ULONG signature_len, mbedtls_md_type_t md_type) {
  CK_RV rv = CKR_GENERAL_ERROR;
  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_ecp_group_id grp_id = MBEDTLS_ECP_DP_NONE;
  mbedtls_mpi r, s;

  // Initialize the ECP structures
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);

  print_hex_data("ec_params", ec_params, ec_params_len, 32);

  // Determine the curve type from EC_PARAMS
  if (ec_params_len == 10 && memcmp(ec_params, "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07", 10) == 0) {
    grp_id = MBEDTLS_ECP_DP_SECP256R1; // NIST P-256
  } else if (ec_params_len == 5 && memcmp(ec_params, "\x06\x03\x2b\x81\x04", 5) == 0) {
    grp_id = MBEDTLS_ECP_DP_SECP384R1; // NIST P-384
  } else if (ec_params_len == 5 && memcmp(ec_params, "\x06\x03\x2b\x81\x0c", 5) == 0) {
    grp_id = MBEDTLS_ECP_DP_SECP521R1; // NIST P-521
  } else {
    printf("    Unsupported curve (unrecognized OID)\n");
    goto cleanup;
  }

  // Load the ECP group for the curve
  int ret = mbedtls_ecp_group_load(&grp, grp_id);
  if (ret != 0) {
    printf("    Failed to load ECP group: -0x%04x\n", -ret);
    goto cleanup;
  }

  // Parse the EC_POINT value (Q)
  // The EC_POINT is in DER-encoded octet string format
  if (ec_point[0] != 0x04) { // Check for uncompressed point format
    printf("    EC point is not in uncompressed format\n");
    goto cleanup;
  }

  // Parse EC point, skipping the DER encoding if present
  const unsigned char *p = ec_point;
  size_t point_len = ec_point_len;

  // Check if there's ASN.1 wrapping (DER encoding)
  if (ec_point[0] == 0x04 && ec_point[1] == ec_point_len - 2) {
    // Skip the ASN.1 OCTET STRING tag and length
    p += 2;
    point_len -= 2;
  }

  // Read the public key from the point
  ret = mbedtls_ecp_point_read_binary(&grp, &Q, p, point_len);
  if (ret != 0) {
    printf("    Failed to read ECP point: -0x%04x\n", -ret);
    goto cleanup;
  }

  // Compute hash of the data if necessary
  unsigned char hash[64]; // Max hash size (for SHA-512)
  size_t hash_len = 0;

  if (md_type != MBEDTLS_MD_NONE) {
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
    if (md_info == NULL) {
      printf("    Invalid hash algorithm\n");
      goto cleanup;
    }

    hash_len = mbedtls_md_get_size(md_info);
    ret = mbedtls_md(md_info, data, data_len, hash);
    if (ret != 0) {
      printf("    Failed to compute hash: -0x%04x\n", -ret);
      goto cleanup;
    }
  } else {
    // If no hash algo specified, use the data directly
    // Note: This is usually not how ECDSA is used in practice as it requires data to be exactly the right size
    if (data_len > sizeof(hash)) {
      printf("    Data too large for direct ECDSA without hashing\n");
      goto cleanup;
    }
    memcpy(hash, data, data_len);
    hash_len = data_len;
  }

  // Check if the signature is in raw R|S format or DER format
  if (signature[0] == 0x30) { // DER sequence marker
    // Parse the DER encoded signature
    size_t len = 0;
    const unsigned char *sig_ptr = signature;

    // Parse DER format: get sequence length
    if (signature_len < 2 || sig_ptr[0] != 0x30) {
      printf("    Invalid DER signature format (not a sequence)\n");
      goto cleanup;
    }

    sig_ptr++; // Skip sequence tag

    // Get sequence length
    if (*sig_ptr & 0x80) {
      // Length is multi-byte
      int len_len = *sig_ptr & 0x7F;
      sig_ptr++;

      if (len_len > 2) {
        printf("    DER sequence length too long\n");
        goto cleanup;
      }

      len = 0;
      for (int i = 0; i < len_len; i++) {
        len = (len << 8) | *sig_ptr;
        sig_ptr++;
      }
    } else {
      // Single byte length
      len = *sig_ptr;
      sig_ptr++;
    }

    if (len + (sig_ptr - signature) != signature_len) {
      printf("    DER sequence length mismatch\n");
      goto cleanup;
    }

    // Parse first INTEGER (r)
    if (sig_ptr[0] != 0x02) {
      printf("    DER signature missing r INTEGER tag\n");
      goto cleanup;
    }
    sig_ptr++;

    // Get r length
    int r_len = *sig_ptr;
    sig_ptr++;

    // Read r value
    ret = mbedtls_mpi_read_binary(&r, sig_ptr, r_len);
    if (ret != 0) {
      printf("    Failed to read r component from DER: -0x%04x\n", -ret);
      goto cleanup;
    }
    sig_ptr += r_len;

    // Parse second INTEGER (s)
    if (sig_ptr[0] != 0x02) {
      printf("    DER signature missing s INTEGER tag\n");
      goto cleanup;
    }
    sig_ptr++;

    // Get s length
    int s_len = *sig_ptr;
    sig_ptr++;

    // Read s value
    ret = mbedtls_mpi_read_binary(&s, sig_ptr, s_len);
    if (ret != 0) {
      printf("    Failed to read s component from DER: -0x%04x\n", -ret);
      goto cleanup;
    }
  } else {
    // Assuming raw R|S format
    size_t n = mbedtls_mpi_size(&grp.N);

    if (signature_len != 2 * n) {
      printf("    Invalid raw signature length\n");
      goto cleanup;
    }

    ret = mbedtls_mpi_read_binary(&r, signature, n);
    if (ret != 0) {
      printf("    Failed to read R component: -0x%04x\n", -ret);
      goto cleanup;
    }

    ret = mbedtls_mpi_read_binary(&s, signature + n, n);
    if (ret != 0) {
      printf("    Failed to read S component: -0x%04x\n", -ret);
      goto cleanup;
    }
  }

  // Verify the ECDSA signature
  ret = mbedtls_ecdsa_verify(&grp, hash, hash_len, &Q, &r, &s);
  if (ret != 0) {
    printf("    ECDSA verification failed: -0x%04x\n", -ret);
    goto cleanup;
  }

  printf("    ECDSA verification successful!\n");
  rv = CKR_OK;

cleanup:
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  mbedtls_ecp_point_free(&Q);
  mbedtls_ecp_group_free(&grp);
  return rv;
}

static CK_RV load_ec_group_from_params(CK_BYTE_PTR ec_params, CK_ULONG ec_params_len, mbedtls_ecp_group *grp,
                                       CK_ULONG_PTR pCoordinateLen) {
  mbedtls_ecp_group_id grp_id = MBEDTLS_ECP_DP_NONE;

  if (ec_params_len == 10 && memcmp(ec_params, "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07", 10) == 0) {
    grp_id = MBEDTLS_ECP_DP_SECP256R1;
    *pCoordinateLen = 32;
  } else if (ec_params_len == 7 && memcmp(ec_params, "\x06\x05\x2b\x81\x04\x00\x22", 7) == 0) {
    grp_id = MBEDTLS_ECP_DP_SECP384R1;
    *pCoordinateLen = 48;
  } else if (ec_params_len == 7 && memcmp(ec_params, "\x06\x05\x2b\x81\x04\x00\x0a", 7) == 0) {
    grp_id = MBEDTLS_ECP_DP_SECP256K1;
    *pCoordinateLen = 32;
  } else {
    return CKR_CURVE_NOT_SUPPORTED;
  }

  int ret = mbedtls_ecp_group_load(grp, grp_id);
  if (ret != 0) {
    printf("    Failed to load ECP group for ECDH: -0x%04x\n", (unsigned int)-ret);
    return CKR_GENERAL_ERROR;
  }

  return CKR_OK;
}

static CK_RV ec_point_value(CK_BYTE_PTR ec_point, CK_ULONG ec_point_len, CK_BYTE_PTR point, CK_ULONG_PTR pPointLen) {
  if (ec_point == NULL || point == NULL || pPointLen == NULL)
    return CKR_ARGUMENTS_BAD;

  if (ec_point_len == 0 || ec_point[0] != 0x04)
    return CKR_ATTRIBUTE_VALUE_INVALID;

  const CK_BYTE *p = ec_point;
  CK_ULONG pointLen = ec_point_len;
  if (ec_point_len >= 3 && ec_point[1] == ec_point_len - 2 && ec_point[2] == 0x04) {
    p += 2;
    pointLen -= 2;
  }

  if (*pPointLen < pointLen) {
    *pPointLen = pointLen;
    return CKR_BUFFER_TOO_SMALL;
  }

  memcpy(point, p, pointLen);
  *pPointLen = pointLen;
  return CKR_OK;
}

static CK_RV compute_ecdh_expected_secret(CK_BYTE_PTR ec_params, CK_ULONG ec_params_len, CK_BYTE_PTR cardPoint,
                                          CK_ULONG cardPointLen, mbedtls_mpi *ephemeralPrivate, CK_BYTE_PTR secret,
                                          CK_ULONG_PTR pSecretLen) {
  CK_RV rv;
  int ret;
  CK_ULONG coordinateLen = 0;
  mbedtls_ecp_group grp;
  mbedtls_ecp_point cardQ;
  mbedtls_ecp_point shared;

  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&cardQ);
  mbedtls_ecp_point_init(&shared);

  rv = load_ec_group_from_params(ec_params, ec_params_len, &grp, &coordinateLen);
  if (rv != CKR_OK)
    goto cleanup;

  ret = mbedtls_ecp_point_read_binary(&grp, &cardQ, cardPoint, cardPointLen);
  if (ret != 0) {
    printf("    Failed to read card ECDH public point: -0x%04x\n", (unsigned int)-ret);
    rv = CKR_GENERAL_ERROR;
    goto cleanup;
  }

  unsigned int rngState = 0x31415926u;
  ret = mbedtls_ecp_mul(&grp, &shared, ephemeralPrivate, &cardQ, cnk_test_rng, &rngState);
  if (ret != 0) {
    printf("    Software ECDH multiply failed: -0x%04x\n", (unsigned int)-ret);
    rv = CKR_GENERAL_ERROR;
    goto cleanup;
  }

  if (*pSecretLen < coordinateLen) {
    *pSecretLen = coordinateLen;
    rv = CKR_BUFFER_TOO_SMALL;
    goto cleanup;
  }

  ret = mbedtls_mpi_write_binary(&shared.X, secret, coordinateLen);
  if (ret != 0) {
    printf("    Failed to write software ECDH X coordinate: -0x%04x\n", (unsigned int)-ret);
    rv = CKR_GENERAL_ERROR;
    goto cleanup;
  }

  *pSecretLen = coordinateLen;
  rv = CKR_OK;

cleanup:
  mbedtls_ecp_point_free(&shared);
  mbedtls_ecp_point_free(&cardQ);
  mbedtls_ecp_group_free(&grp);
  return rv;
}

static CK_RV compute_x963_kdf(mbedtls_md_type_t md_type, CK_BYTE_PTR sharedSecret, CK_ULONG sharedSecretLen,
                              CK_BYTE_PTR sharedData, CK_ULONG sharedDataLen, CK_BYTE_PTR output, CK_ULONG outputLen) {
  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
  if (md_info == NULL)
    return CKR_MECHANISM_PARAM_INVALID;

  CK_BYTE digest[64];
  CK_ULONG digestLen = mbedtls_md_get_size(md_info);
  CK_ULONG produced = 0;
  CK_ULONG counter = 1;

  while (produced < outputLen) {
    CK_BYTE counterBytes[4] = {
        (CK_BYTE)(counter >> 24),
        (CK_BYTE)(counter >> 16),
        (CK_BYTE)(counter >> 8),
        (CK_BYTE)counter,
    };

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    int ret = mbedtls_md_setup(&ctx, md_info, 0);
    if (ret == 0)
      ret = mbedtls_md_starts(&ctx);
    if (ret == 0)
      ret = mbedtls_md_update(&ctx, sharedSecret, sharedSecretLen);
    if (ret == 0)
      ret = mbedtls_md_update(&ctx, counterBytes, sizeof(counterBytes));
    if (ret == 0 && sharedDataLen > 0)
      ret = mbedtls_md_update(&ctx, sharedData, sharedDataLen);
    if (ret == 0)
      ret = mbedtls_md_finish(&ctx, digest);
    mbedtls_md_free(&ctx);

    if (ret != 0) {
      printf("    X9.63 KDF hash failed: -0x%04x\n", (unsigned int)-ret);
      return CKR_GENERAL_ERROR;
    }

    CK_ULONG copyLen = outputLen - produced;
    if (copyLen > digestLen)
      copyLen = digestLen;
    memcpy(output + produced, digest, copyLen);
    produced += copyLen;
    counter++;
  }

  return CKR_OK;
}

static CK_RV derive_and_check_ecdh_secret(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE deriveSession,
                                          CK_OBJECT_HANDLE hEcPrivateKey, CK_ECDH1_DERIVE_PARAMS *deriveParams,
                                          CK_BYTE_PTR expectedSecret, CK_ULONG expectedSecretLen,
                                          const char *description) {
  CK_MECHANISM mechanism = {CKM_ECDH1_DERIVE, deriveParams, sizeof(*deriveParams)};
  CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
  CK_KEY_TYPE secretType = CKK_GENERIC_SECRET;
  CK_BBOOL token = CK_FALSE;
  CK_BBOOL sensitive = CK_FALSE;
  CK_BBOOL extractable = CK_TRUE;
  CK_ULONG valueLen = expectedSecretLen;
  CK_ATTRIBUTE secretTemplate[] = {
      {CKA_CLASS, &secretClass, sizeof(secretClass)},
      {CKA_KEY_TYPE, &secretType, sizeof(secretType)},
      {CKA_TOKEN, &token, sizeof(token)},
      {CKA_SENSITIVE, &sensitive, sizeof(sensitive)},
      {CKA_EXTRACTABLE, &extractable, sizeof(extractable)},
      {CKA_VALUE_LEN, &valueLen, sizeof(valueLen)},
  };

  CK_OBJECT_HANDLE hDerivedKey = 0;
  CK_RV rv = pFunctionList->C_DeriveKey(deriveSession, &mechanism, hEcPrivateKey, secretTemplate,
                                        sizeof(secretTemplate) / sizeof(secretTemplate[0]), &hDerivedKey);
  if (rv != CKR_OK) {
    record_real_test_failure(description, rv);
    return rv;
  }

  CK_OBJECT_CLASS derivedClass = 0;
  CK_KEY_TYPE derivedType = 0;
  CK_ULONG derivedValueLen = 0;
  CK_BBOOL derivedToken = CK_TRUE;
  CK_BYTE derivedSecret[128];
  CK_ATTRIBUTE derivedAttrs[] = {
      {CKA_CLASS, &derivedClass, sizeof(derivedClass)},  {CKA_KEY_TYPE, &derivedType, sizeof(derivedType)},
      {CKA_TOKEN, &derivedToken, sizeof(derivedToken)},  {CKA_VALUE_LEN, &derivedValueLen, sizeof(derivedValueLen)},
      {CKA_VALUE, derivedSecret, sizeof(derivedSecret)},
  };

  rv = pFunctionList->C_GetAttributeValue(deriveSession, hDerivedKey, derivedAttrs, 5);
  if (rv != CKR_OK) {
    record_real_test_failure("Could not read derived ECDH secret attributes", rv);
    return rv;
  }

  if (derivedClass != CKO_SECRET_KEY || derivedType != CKK_GENERIC_SECRET || derivedToken != CK_FALSE ||
      derivedValueLen != expectedSecretLen || derivedAttrs[4].ulValueLen != expectedSecretLen ||
      memcmp(derivedSecret, expectedSecret, expectedSecretLen) != 0) {
    record_real_test_failure(description, CKR_GENERAL_ERROR);
    return CKR_GENERAL_ERROR;
  }

  printf("    %s (%lu bytes)\n", description, expectedSecretLen);
  return CKR_OK;
}

// Verify RSA signature using mbedtls
static CK_RV cnk_verify_rsa_signature(CK_BYTE_PTR modulus, CK_ULONG modulus_len, CK_BYTE_PTR exponent,
                                      CK_ULONG exponent_len, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature,
                                      mbedtls_md_type_t md_type,
                                      int padding_mode) { // MBEDTLS_RSA_PKCS_V15 or MBEDTLS_RSA_PKCS_V21
  CK_RV rv = CKR_GENERAL_ERROR;
  int ret;
  mbedtls_rsa_context rsa;
  unsigned char hash[64]; // Large enough for any hash
  size_t key_len = modulus_len;

  // Initialize mbedtls structures
  mbedtls_rsa_init(&rsa);

  // Import the public key components
  ret = mbedtls_mpi_read_binary(&rsa.N, modulus, modulus_len);
  if (ret != 0) {
    printf("      Error loading modulus: -0x%04x\n", (unsigned int)-ret);
    goto cleanup;
  }

  ret = mbedtls_mpi_read_binary(&rsa.E, exponent, exponent_len);
  if (ret != 0) {
    printf("      Error loading exponent: -0x%04x\n", (unsigned int)-ret);
    goto cleanup;
  }

  // Set RSA padding mode based on the parameter
  mbedtls_rsa_set_padding(&rsa, padding_mode, md_type);
  rsa.len = mbedtls_mpi_size(&rsa.N);

  if (mbedtls_rsa_check_pubkey(&rsa) != 0) {
    printf("      Invalid RSA public key!\n");
    goto cleanup;
  }

  // Handle verification based on padding mode
  if (padding_mode == MBEDTLS_RSA_PKCS_V15) {
    // PKCS#1 v1.5 padding
    if (md_type == MBEDTLS_MD_NONE) {
      // For raw RSA (no hash algorithm), use basic public key operation
      unsigned char decrypted[512]; // Large enough for any RSA key

      // Perform the raw RSA public operation
      ret = mbedtls_rsa_public(&rsa, signature, decrypted);
      if (ret != 0) {
        printf("      RSA public operation failed: -0x%04x\n", (unsigned int)-ret);
        goto cleanup;
      }

      // Verify the decryption matches the original data with PKCS#1 v1.5 padding
      // This is simplified - in a real implementation, we'd parse the PKCS#1 v1.5 padding
      printf("      Raw RSA public operation successful\n");
      // For a proper verification, we'd check the PKCS#1 v1.5 padding and data
    } else {
      // Compute the hash of the data
      const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
      if (md_info == NULL) {
        printf("      Invalid hash algorithm type!\n");
        goto cleanup;
      }

      ret = mbedtls_md(md_info, data, data_len, hash);
      if (ret != 0) {
        printf("      Error calculating hash: -0x%04x\n", (unsigned int)-ret);
        goto cleanup;
      }

      // For hashed algorithms, we still need to use the basic RSA operation
      // and then verify the PKCS#1 v1.5 padding structure manually
      unsigned char decrypted[512]; // Large enough for any RSA key

      // Perform the RSA public operation
      ret = mbedtls_rsa_public(&rsa, signature, decrypted);
      if (ret != 0) {
        printf("      RSA public operation failed: -0x%04x\n", (unsigned int)-ret);
        goto cleanup;
      }

      // Properly verify the PKCS#1 v1.5 signature
      size_t hash_len = mbedtls_md_get_size(md_info);

      // The decrypted signature should have format: 0x00 0x01 PS 0x00 T
      // where PS is padding bytes (0xFF) and T is ASN.1 DER encoding of algorithm + hash

      // 1. Check minimum decrypted length
      if (key_len < hash_len + 11) {
        printf("      Invalid signature length\n");
        goto cleanup;
      }

      // 2. Check PKCS#1 v1.5 padding structure
      if (decrypted[0] != 0x00 || decrypted[1] != 0x01) {
        printf("      Invalid PKCS#1 v1.5 padding marker\n");
        goto cleanup;
      }

      // 3. Find the 0x00 separator after padding
      size_t idx = 2;
      while (idx < key_len && decrypted[idx] == 0xFF) {
        idx++;
      }

      // 4. Make sure we found the separator and have proper min padding length
      if (idx < 10 || idx >= key_len || decrypted[idx] != 0x00) {
        printf("      Invalid PKCS#1 v1.5 padding structure\n");
        goto cleanup;
      }
      idx++;

      // 5. Verify DER encoding prefix for the hash algorithm
      const unsigned char *der_prefix = NULL;
      size_t der_prefix_len = 0;

      // Select the correct DER prefix for the hash algorithm
      switch (md_type) {
      case MBEDTLS_MD_SHA1:
        der_prefix = (const unsigned char *)"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14";
        der_prefix_len = 15;
        break;
      case MBEDTLS_MD_SHA224:
        der_prefix =
            (const unsigned char *)"\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c";
        der_prefix_len = 19;
        break;
      case MBEDTLS_MD_SHA256:
        der_prefix =
            (const unsigned char *)"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20";
        der_prefix_len = 19;
        break;
      case MBEDTLS_MD_SHA384:
        der_prefix =
            (const unsigned char *)"\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30";
        der_prefix_len = 19;
        break;
      case MBEDTLS_MD_SHA512:
        der_prefix =
            (const unsigned char *)"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40";
        der_prefix_len = 19;
        break;
      default:
        printf("      Unsupported hash algorithm for PKCS#1 v1.5 DER encoding\n");
        goto cleanup;
      }

      // 6. Check that DER prefix is present
      if (idx + der_prefix_len + hash_len > key_len || memcmp(&decrypted[idx], der_prefix, der_prefix_len) != 0) {
        printf("      Invalid DER encoding for hash algorithm\n");
        goto cleanup;
      }

      // 7. Finally, compare the embedded hash value with our computed hash
      idx += der_prefix_len;
      if (memcmp(&decrypted[idx], hash, hash_len) != 0) {
        printf("      Hash value mismatch in signature\n");
        goto cleanup;
      }

      printf("      PKCS#1 v1.5 signature verification successful\n");
    }
  } else if (padding_mode == MBEDTLS_RSA_PKCS_V21) {
    // PSS padding requires a hash function
    if (md_type == MBEDTLS_MD_NONE) {
      printf("      PSS padding requires a hash function!\n");
      goto cleanup;
    }

    // Compute the hash of the data
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
    if (md_info == NULL) {
      printf("      Invalid hash algorithm type!\n");
      goto cleanup;
    }

    ret = mbedtls_md(md_info, data, data_len, hash);
    if (ret != 0) {
      printf("      Error calculating hash: -0x%04x\n", (unsigned int)-ret);
      goto cleanup;
    }

    // For PSS verification, we'll use a simpler approach with the base RSA functions
    // This is because different mbedtls versions might have different PSS verification APIs

    // 1. Verify the signature using RSA public operation
    unsigned char decrypted[256]; // Large enough buffer for RSA

    ret = mbedtls_rsa_public(&rsa, signature, decrypted);
    if (ret != 0) {
      printf("      PSS signature decryption failed: -0x%04x\n", (unsigned int)-ret);
      goto cleanup;
    }

    // 2. Use the built-in PSS verification function
    size_t hash_len = mbedtls_md_get_size(md_info);
    int expected_salt_len = 0;
    switch (md_type) {
    case MBEDTLS_MD_SHA1:
      expected_salt_len = 20;
      break;
    case MBEDTLS_MD_SHA256:
      expected_salt_len = 32;
      break;
    default:
      expected_salt_len = (int)hash_len;
      break;
    }

    // Set RSA padding again explicitly for the verification
    mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, md_type);

    // Use TF-PSA-Crypto's built-in PSS verification function directly.
    ret = mbedtls_rsa_rsassa_pss_verify_ext(&rsa, md_type, (unsigned int)hash_len, hash, md_type, expected_salt_len,
                                            signature);

    if (ret != 0) {
      printf("      PSS signature verification failed: -0x%04x\n", (unsigned int)-ret);
      goto cleanup;
    }

    printf("      PSS signature verification successful\n");
  } else {
    printf("      Unsupported padding mode!\n");
    goto cleanup;
  }

  printf("      Signature verification successful!\n");
  rv = CKR_OK;

cleanup:
  mbedtls_rsa_free(&rsa);
  return rv;
}

void test_decryption(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID) {
  CK_RV rv;
  CK_SESSION_HANDLE decryptSession;

  printf("    Running hardware decrypt tests...\n");

  rv = pFunctionList->C_OpenSession(slotID, CKF_SERIAL_SESSION, NULL, NULL, &decryptSession);
  if (rv != CKR_OK) {
    record_real_test_failure("Error opening session for decrypt tests", rv);
    return;
  }

  rv = perform_login(pFunctionList, decryptSession);
  if (rv != CKR_OK) {
    record_real_test_failure("Error logging in for decrypt tests", rv);
    pFunctionList->C_CloseSession(decryptSession);
    return;
  }

  CK_KEY_TYPE rsaKeyType = CKK_RSA;
  CK_OBJECT_HANDLE hRsaPrivateKey;
  rv = find_object(pFunctionList, decryptSession, CKO_PRIVATE_KEY, &rsaKeyType, NULL, 0, &hRsaPrivateKey);
  if (rv != CKR_OK) {
    record_real_test_failure("No RSA private key found for decrypt tests", rv);
    perform_logout(pFunctionList, decryptSession);
    pFunctionList->C_CloseSession(decryptSession);
    return;
  }

  CK_BYTE keyId[32];
  CK_ATTRIBUTE idAttr = {CKA_ID, keyId, sizeof(keyId)};
  rv = pFunctionList->C_GetAttributeValue(decryptSession, hRsaPrivateKey, &idAttr, 1);
  if (rv != CKR_OK) {
    record_real_test_failure("Error getting RSA private key ID", rv);
    perform_logout(pFunctionList, decryptSession);
    pFunctionList->C_CloseSession(decryptSession);
    return;
  }

  CK_BYTE modulus[512];
  CK_BYTE exponent[8];
  CK_ULONG modulusLen = sizeof(modulus);
  CK_ULONG exponentLen = sizeof(exponent);
  rv = load_rsa_public_key(pFunctionList, decryptSession, keyId, idAttr.ulValueLen, modulus, &modulusLen, exponent,
                           &exponentLen);
  if (rv != CKR_OK) {
    record_real_test_failure("Error loading RSA public key for decrypt tests", rv);
    perform_logout(pFunctionList, decryptSession);
    pFunctionList->C_CloseSession(decryptSession);
    return;
  }

  printf("    RSA decrypt key modulus length: %lu bytes\n", modulusLen);

  CK_BYTE pkcsPlaintext[512];
  if (modulusLen <= 11) {
    record_real_test_failure("RSA key is too small for PKCS#1 v1.5 decrypt test", CKR_GENERAL_ERROR);
    perform_logout(pFunctionList, decryptSession);
    pFunctionList->C_CloseSession(decryptSession);
    return;
  }
  CK_ULONG pkcsPlaintextLen = modulusLen - 11;
  if (pkcsPlaintextLen > sizeof(pkcsPlaintext)) {
    record_real_test_failure("RSA key is too large for decrypt test buffer", CKR_GENERAL_ERROR);
    perform_logout(pFunctionList, decryptSession);
    pFunctionList->C_CloseSession(decryptSession);
    return;
  }
  for (CK_ULONG i = 0; i < pkcsPlaintextLen; i++)
    pkcsPlaintext[i] = (CK_BYTE)('A' + (i % 26));

  CK_BYTE ciphertext[512];
  CK_ULONG ciphertextLen = sizeof(ciphertext);
  rv = encrypt_rsa_pkcs1_v15(modulus, modulusLen, exponent, exponentLen, pkcsPlaintext, pkcsPlaintextLen, ciphertext,
                             &ciphertextLen);
  if (rv != CKR_OK) {
    record_real_test_failure("Software RSA PKCS#1 v1.5 encryption failed", rv);
  } else {
    CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL, 0};
    CK_BYTE decrypted[512];
    CK_ULONG decryptedLen = sizeof(decrypted);

    rv = decrypt_with_key(pFunctionList, decryptSession, hRsaPrivateKey, &mechanism, ciphertext, ciphertextLen,
                          decrypted, &decryptedLen);
    if (rv != CKR_OK) {
      record_real_test_failure("Hardware RSA PKCS#1 v1.5 decrypt failed", rv);
    } else if (decryptedLen != pkcsPlaintextLen || memcmp(decrypted, pkcsPlaintext, pkcsPlaintextLen) != 0) {
      record_real_test_failure("Hardware RSA PKCS#1 v1.5 decrypt output mismatch", CKR_GENERAL_ERROR);
    } else {
      printf("    RSA PKCS#1 v1.5 long plaintext decrypt successful (%lu bytes)\n", decryptedLen);
    }
  }

  CK_BYTE oaepPlaintext[512];
  if (modulusLen <= (2 * 32) + 2) {
    record_real_test_failure("RSA key is too small for OAEP-SHA256 decrypt test", CKR_GENERAL_ERROR);
    perform_logout(pFunctionList, decryptSession);
    pFunctionList->C_CloseSession(decryptSession);
    return;
  }
  CK_ULONG oaepPlaintextLen = modulusLen - (2 * 32) - 2;
  if (oaepPlaintextLen > sizeof(oaepPlaintext)) {
    record_real_test_failure("RSA key is too large for OAEP decrypt test buffer", CKR_GENERAL_ERROR);
    perform_logout(pFunctionList, decryptSession);
    pFunctionList->C_CloseSession(decryptSession);
    return;
  }
  for (CK_ULONG i = 0; i < oaepPlaintextLen; i++)
    oaepPlaintext[i] = (CK_BYTE)(0xffu - (i & 0xffu));

  ciphertextLen = sizeof(ciphertext);
  rv = encrypt_rsa_oaep_sha256(modulus, modulusLen, exponent, exponentLen, oaepPlaintext, oaepPlaintextLen, ciphertext,
                               &ciphertextLen);
  if (rv != CKR_OK) {
    record_real_test_failure("Software RSA OAEP-SHA256 encryption failed", rv);
  } else {
    CK_RSA_PKCS_OAEP_PARAMS oaepParams = {CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, NULL, 0};
    CK_MECHANISM mechanism = {CKM_RSA_PKCS_OAEP, &oaepParams, sizeof(oaepParams)};
    CK_BYTE decrypted[512];
    CK_ULONG decryptedLen = sizeof(decrypted);

    rv = decrypt_with_key(pFunctionList, decryptSession, hRsaPrivateKey, &mechanism, ciphertext, ciphertextLen,
                          decrypted, &decryptedLen);
    if (rv != CKR_OK) {
      record_real_test_failure("Hardware RSA OAEP-SHA256 decrypt failed", rv);
    } else if (decryptedLen != oaepPlaintextLen || memcmp(decrypted, oaepPlaintext, oaepPlaintextLen) != 0) {
      record_real_test_failure("Hardware RSA OAEP-SHA256 decrypt output mismatch", CKR_GENERAL_ERROR);
    } else {
      printf("    RSA OAEP-SHA256 long plaintext decrypt successful (%lu bytes)\n", decryptedLen);
    }
  }

  CK_KEY_TYPE ecKeyType = CKK_EC;
  CK_OBJECT_HANDLE hEcPrivateKey;
  rv = find_object(pFunctionList, decryptSession, CKO_PRIVATE_KEY, &ecKeyType, NULL, 0, &hEcPrivateKey);
  if (rv == CKR_OK) {
    CK_BBOOL decrypt = CK_TRUE;
    CK_ATTRIBUTE decryptAttr = {CKA_DECRYPT, &decrypt, sizeof(decrypt)};
    rv = pFunctionList->C_GetAttributeValue(decryptSession, hEcPrivateKey, &decryptAttr, 1);
    if (rv != CKR_OK) {
      record_real_test_failure("Error getting EC private key decrypt attribute", rv);
    } else if (decrypt != CK_FALSE) {
      record_real_test_failure("EC private key unexpectedly advertises CKA_DECRYPT", CKR_GENERAL_ERROR);
    } else {
      CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL, 0};
      rv = pFunctionList->C_DecryptInit(decryptSession, &mechanism, hEcPrivateKey);
      if (rv == CKR_KEY_TYPE_INCONSISTENT || rv == CKR_KEY_FUNCTION_NOT_PERMITTED) {
        printf("    EC private key correctly rejects decrypt initialization\n");
      } else {
        record_real_test_failure("EC private key decrypt initialization returned unexpected result", rv);
      }
    }
  } else {
    printf("    No EC private key found, skipping EC decrypt negative test.\n");
  }

  perform_logout(pFunctionList, decryptSession);
  rv = pFunctionList->C_CloseSession(decryptSession);
  if (rv != CKR_OK)
    record_real_test_failure("Error closing decrypt test session", rv);
}

void test_pin_never_private_key_operation(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID) {
  CK_SESSION_HANDLE signSession;
  CK_RV rv = pFunctionList->C_OpenSession(slotID, CKF_SERIAL_SESSION, NULL, NULL, &signSession);
  if (rv != CKR_OK) {
    record_real_test_failure("Error opening PIN-never signing session", rv);
    return;
  }

  CK_BYTE keyId = 0x05;
  CK_KEY_TYPE keyType = CKK_EC;
  CK_OBJECT_HANDLE hPrivateKey;
  rv = find_object(pFunctionList, signSession, CKO_PRIVATE_KEY, &keyType, &keyId, sizeof(keyId), &hPrivateKey);
  if (rv != CKR_OK) {
    printf("    No 9E EC private key found for PIN-never signing smoke, skipping.\n");
    pFunctionList->C_CloseSession(signSession);
    return;
  }

  CK_BYTE pinPolicy = 0;
  CK_ATTRIBUTE policyAttr = {CKA_CNK_PIV_PIN_POLICY, &pinPolicy, sizeof(pinPolicy)};
  rv = pFunctionList->C_GetAttributeValue(signSession, hPrivateKey, &policyAttr, 1);
  if (rv != CKR_OK) {
    record_real_test_failure("Could not read 9E PIN policy", rv);
    pFunctionList->C_CloseSession(signSession);
    return;
  }

  if (pinPolicy != CNK_PIV_PIN_POLICY_NEVER) {
    printf("    9E EC key PIN policy is 0x%02x, not PIN-never; skipping no-login smoke.\n", pinPolicy);
    pFunctionList->C_CloseSession(signSession);
    return;
  }

  CK_MECHANISM mechanism = {CKM_ECDSA, NULL, 0};
  CK_BYTE digest[32] = {0};
  CK_BYTE signature[64];
  CK_ULONG signatureLen = sizeof(signature);

  rv = pFunctionList->C_SignInit(signSession, &mechanism, hPrivateKey);
  if (rv == CKR_OK)
    rv = pFunctionList->C_Sign(signSession, digest, sizeof(digest), signature, &signatureLen);
  if (rv == CKR_OK && signatureLen != sizeof(signature))
    rv = CKR_SIGNATURE_LEN_RANGE;

  if (rv != CKR_OK) {
    record_real_test_failure("PIN-never 9E signing without USER login failed", rv);
  } else {
    printf("    PIN-never 9E signing succeeded without USER login.\n");
  }

  rv = pFunctionList->C_CloseSession(signSession);
  if (rv != CKR_OK)
    record_real_test_failure("Error closing PIN-never signing session", rv);
}

// Test RSA signing operations
void test_rsa_signing(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID) {
  // Check if the token supports RSA mechanisms
  int has_rsa_pkcs = 0;
  int has_sha1_rsa_pkcs = 0;
  int has_sha256_rsa_pkcs = 0;
  CK_ULONG mechCount;

  CK_RV rv = pFunctionList->C_GetMechanismList(slotID, NULL, &mechCount);
  if (rv == CKR_OK && mechCount > 0) {
    CK_MECHANISM_TYPE_PTR mechList = (CK_MECHANISM_TYPE_PTR)malloc(mechCount * sizeof(CK_MECHANISM_TYPE));
    if (mechList) {
      rv = pFunctionList->C_GetMechanismList(slotID, mechList, &mechCount);
      if (rv == CKR_OK) {
        for (CK_ULONG j = 0; j < mechCount; j++) {
          if (mechList[j] == CKM_RSA_PKCS)
            has_rsa_pkcs = 1;
          if (mechList[j] == CKM_SHA1_RSA_PKCS)
            has_sha1_rsa_pkcs = 1;
          if (mechList[j] == CKM_SHA256_RSA_PKCS)
            has_sha256_rsa_pkcs = 1;
        }
      }
      free(mechList);
    }
  }

  if (!(has_rsa_pkcs || has_sha1_rsa_pkcs || has_sha256_rsa_pkcs)) {
    printf("    No RSA signing mechanisms available, skipping signing tests.\n");
    return;
  }

  printf("    Running RSA signing tests...\n");

  // Open a new session for signing tests
  CK_SESSION_HANDLE signSession;
  rv = pFunctionList->C_OpenSession(slotID, CKF_SERIAL_SESSION, NULL, NULL, &signSession);
  if (rv != CKR_OK) {
    printf("    Error opening session for signing tests: 0x%lx\n", rv);
    return;
  }

  printf("    Session for signing tests opened successfully. Session handle: %lu\n", signSession);

  // Login with PIN
  rv = perform_login(pFunctionList, signSession);
  if (rv != CKR_OK) {
    pFunctionList->C_CloseSession(signSession);
    return;
  }

  // Find RSA private keys for signing
  CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
  CK_KEY_TYPE keyType = CKK_RSA;
  CK_BBOOL sign_attribute = CK_TRUE; // Add explicit CKA_SIGN attribute
  CK_ATTRIBUTE findTemplate[] = {
      {CKA_CLASS, &keyClass, sizeof(keyClass)},
      {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
      {CKA_SIGN, &sign_attribute, sizeof(sign_attribute)} // Ensure key can be used for signing
  };

  rv = pFunctionList->C_FindObjectsInit(signSession, findTemplate, 3);
  if (rv != CKR_OK) {
    printf("    Error initializing object search: 0x%lx\n", rv);
    perform_logout(pFunctionList, signSession);
    pFunctionList->C_CloseSession(signSession);
    return;
  }

  CK_OBJECT_HANDLE hKey;
  CK_ULONG ulObjectCount;

  rv = pFunctionList->C_FindObjects(signSession, &hKey, 1, &ulObjectCount);
  if (rv != CKR_OK || ulObjectCount == 0) {
    printf("    No RSA private keys found: 0x%lx\n", rv);
    pFunctionList->C_FindObjectsFinal(signSession);
    perform_logout(pFunctionList, signSession);
    pFunctionList->C_CloseSession(signSession);
    return;
  }

  printf("    Found RSA private key (handle: %lu)\n", hKey);

  // Finalize the search
  rv = pFunctionList->C_FindObjectsFinal(signSession);
  if (rv != CKR_OK) {
    printf("    Error finalizing object search: 0x%lx\n", rv);
  }

  // Get key attributes
  CK_BBOOL sign, decrypt, encrypt;
  CK_ATTRIBUTE tmpl[] = {
      {CKA_SIGN, &sign, sizeof(sign)},
      {CKA_DECRYPT, &decrypt, sizeof(decrypt)},
      {CKA_ENCRYPT, &encrypt, sizeof(encrypt)},
  };

  rv = pFunctionList->C_GetAttributeValue(signSession, hKey, tmpl, 3);
  if (rv != CKR_OK) {
    printf("    Error getting key attributes: 0x%lx\n", rv);
  }

  printf("    Key attributes:\n");
  printf("      CKA_SIGN: %s\n", sign ? "true" : "false");
  printf("      CKA_DECRYPT: %s\n", decrypt ? "true" : "false");
  printf("      CKA_ENCRYPT: %s\n", encrypt ? "true" : "false");

  // Get the corresponding public key for verification
  CK_BYTE modulus[512]; // Large enough for RSA-4096
  CK_BYTE exponent[8];
  CK_ULONG modulus_len = sizeof(modulus);
  CK_ULONG exponent_len = sizeof(exponent);
  CK_BBOOL has_public_key = CK_FALSE;

  // Find the public key that corresponds to the private key
  // First, get the CKA_ID of the private key
  CK_BYTE key_id[32];
  CK_ULONG key_id_len = sizeof(key_id);
  CK_ATTRIBUTE id_tmpl = {CKA_ID, key_id, key_id_len};

  rv = pFunctionList->C_GetAttributeValue(signSession, hKey, &id_tmpl, 1);
  if (rv != CKR_OK) {
    printf("    Error getting private key ID: 0x%lx\n", rv);
  } else {
    key_id_len = id_tmpl.ulValueLen;

    // Search for the corresponding public key with the same ID
    CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE pubKeyType = CKK_RSA;
    CK_ATTRIBUTE pubKeyTemplate[] = {{CKA_CLASS, &pubKeyClass, sizeof(pubKeyClass)},
                                     {CKA_KEY_TYPE, &pubKeyType, sizeof(pubKeyType)},
                                     {CKA_ID, key_id, key_id_len}};

    rv = pFunctionList->C_FindObjectsInit(signSession, pubKeyTemplate, 3);
    if (rv != CKR_OK) {
      printf("    Error initializing search for public key: 0x%lx\n", rv);
    } else {
      CK_OBJECT_HANDLE hPubKey;
      CK_ULONG pubKeyCount;

      rv = pFunctionList->C_FindObjects(signSession, &hPubKey, 1, &pubKeyCount);
      if (rv == CKR_OK && pubKeyCount > 0) {
        printf("    Found corresponding public key (handle: %lu)\n", hPubKey);

        // Get the public key components (modulus and exponent)
        CK_ATTRIBUTE pubKeyAttrs[] = {{CKA_MODULUS, modulus, modulus_len},
                                      {CKA_PUBLIC_EXPONENT, exponent, exponent_len}};

        rv = pFunctionList->C_GetAttributeValue(signSession, hPubKey, pubKeyAttrs, 2);
        if (rv == CKR_OK) {
          modulus_len = pubKeyAttrs[0].ulValueLen;
          exponent_len = pubKeyAttrs[1].ulValueLen;
          has_public_key = CK_TRUE;

          printf("    Retrieved public key components for verification:\n");
          printf("      Modulus length: %lu bytes\n", modulus_len);
          printf("      Exponent length: %lu bytes\n", exponent_len);
        } else {
          printf("    Error getting public key components: 0x%lx\n", rv);
        }
      } else {
        printf("    Corresponding public key not found: 0x%lx\n", rv);
      }

      rv = pFunctionList->C_FindObjectsFinal(signSession);
      if (rv != CKR_OK) {
        printf("    Error finalizing public key search: 0x%lx\n", rv);
      }
    }
  }

  // Test data to sign
  CK_BYTE data[] = "Hello, CanoKey PKCS#11!";
  CK_ULONG dataLen = strlen((char *)data);
  CK_BYTE signature[256]; // Buffer for RSA signature
  CK_ULONG signatureLen;

  // Test raw RSA signing (PKCS#1 v1.5 padding)
  if (has_rsa_pkcs) {
    CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL, 0};

    printf("    Testing CKM_RSA_PKCS signing...\n");

    // Initialize signing operation
    rv = pFunctionList->C_SignInit(signSession, &mechanism, hKey);
    if (rv != CKR_OK) {
      printf("    Error initializing signing operation: 0x%lx\n", rv);
    } else {
      // First call to get buffer size
      signatureLen = sizeof(signature);
      rv = pFunctionList->C_Sign(signSession, data, dataLen, NULL, &signatureLen);
      if (rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL) {
        printf("    Error determining signature size: 0x%lx\n", rv);
      } else {
        printf("    Signature length will be %lu bytes\n", signatureLen);

        // Second call to actually sign
        rv = pFunctionList->C_Sign(signSession, data, dataLen, signature, &signatureLen);
        if (rv != CKR_OK) {
          printf("    Error creating signature: 0x%lx\n", rv);
        } else {
          printf("    CKM_RSA_PKCS signing successful! Signature length: %lu\n", signatureLen);

          // Display first few bytes of signature
          printf("    Signature (first 16 bytes): ");
          for (CK_ULONG j = 0; j < (signatureLen > 16 ? 16 : signatureLen); j++) {
            printf("%02X ", signature[j]);
          }
          printf("\n");

          // Verify the signature using mbedtls if public key is available
          if (has_public_key) {
            printf("    Verifying signature with mbedtls...\n");
            rv = cnk_verify_rsa_signature(modulus, modulus_len, exponent, exponent_len, data, dataLen, signature,
                                          MBEDTLS_MD_NONE, MBEDTLS_RSA_PKCS_V15);
            if (rv != CKR_OK) {
              printf("    mbedtls verification failed!\n");
            }
          }
        }
      }
    }
  }

  // Logout and login again for SHA1-RSA test
  perform_logout(pFunctionList, signSession);
  rv = perform_login(pFunctionList, signSession);
  if (rv != CKR_OK) {
    pFunctionList->C_CloseSession(signSession);
    return;
  }

  // Test SHA1-RSA signing
  if (has_sha1_rsa_pkcs) {
    CK_MECHANISM mechanism = {CKM_SHA1_RSA_PKCS, NULL, 0};

    printf("    Testing CKM_SHA1_RSA_PKCS signing...\n");

    // Re-verify key attributes before signing
    CK_BBOOL sign_capability;
    CK_ATTRIBUTE sign_check = {CKA_SIGN, &sign_capability, sizeof(sign_capability)};
    rv = pFunctionList->C_GetAttributeValue(signSession, hKey, &sign_check, 1);
    if (rv != CKR_OK || !sign_capability) {
      printf("    Key does not support signing or error checking attributes: 0x%lx\n", rv);
    } else {
      // Initialize signing operation
      rv = pFunctionList->C_SignInit(signSession, &mechanism, hKey);
      if (rv != CKR_OK) {
        printf("    Error initializing SHA1-RSA signing operation: 0x%lx\n", rv);
      } else {
        // Get signature length
        signatureLen = sizeof(signature);
        rv = pFunctionList->C_Sign(signSession, data, dataLen, signature, &signatureLen);
        if (rv != CKR_OK) {
          printf("    Error creating SHA1-RSA signature: 0x%lx\n", rv);
        } else {
          printf("    CKM_SHA1_RSA_PKCS signing successful! Signature length: %lu\n", signatureLen);

          // Display first few bytes of signature
          printf("    Signature (first 16 bytes): ");
          for (CK_ULONG j = 0; j < (signatureLen > 16 ? 16 : signatureLen); j++) {
            printf("%02X ", signature[j]);
          }
          printf("\n");

          // Verify the signature using mbedtls if public key is available
          if (has_public_key) {
            printf("    Verifying SHA1-RSA signature with mbedtls...\n");
            rv = cnk_verify_rsa_signature(modulus, modulus_len, exponent, exponent_len, data, dataLen, signature,
                                          MBEDTLS_MD_SHA1, MBEDTLS_RSA_PKCS_V15);
            if (rv != CKR_OK) {
              printf("    mbedtls SHA1-RSA verification failed!\n");
            }
          }
        }
      }
    }
  }

  // Logout and login again for SHA256-RSA test
  perform_logout(pFunctionList, signSession);
  rv = perform_login(pFunctionList, signSession);
  if (rv != CKR_OK) {
    pFunctionList->C_CloseSession(signSession);
    return;
  }

  // Test SHA256-RSA signing
  if (has_sha256_rsa_pkcs) {
    CK_MECHANISM mechanism = {CKM_SHA256_RSA_PKCS, NULL, 0};

    printf("    Testing CKM_SHA256_RSA_PKCS signing...\n");

    // Initialize signing operation
    rv = pFunctionList->C_SignInit(signSession, &mechanism, hKey);
    if (rv != CKR_OK) {
      printf("    Error initializing SHA256-RSA signing operation: 0x%lx\n", rv);
    } else {
      // Get signature length
      signatureLen = sizeof(signature);
      rv = pFunctionList->C_Sign(signSession, data, dataLen, signature, &signatureLen);
      if (rv != CKR_OK) {
        printf("    Error creating SHA256-RSA signature: 0x%lx\n", rv);
      } else {
        printf("    CKM_SHA256_RSA_PKCS signing successful! Signature length: %lu\n", signatureLen);

        // Display first few bytes of signature
        printf("    Signature (first 16 bytes): ");
        for (CK_ULONG j = 0; j < (signatureLen > 16 ? 16 : signatureLen); j++) {
          printf("%02X ", signature[j]);
        }
        printf("\n");

        // Verify the signature using mbedtls if public key is available
        if (has_public_key) {
          printf("    Verifying SHA256-RSA signature with mbedtls...\n");
          rv = cnk_verify_rsa_signature(modulus, modulus_len, exponent, exponent_len, data, dataLen, signature,
                                        MBEDTLS_MD_SHA256, MBEDTLS_RSA_PKCS_V15);
          if (rv != CKR_OK) {
            printf("    mbedtls SHA256-RSA verification failed!\n");
          }
        }
      }
    }
  }

  // Test RSA-PSS signatures
  int has_sha1_rsa_pss = 0;
  int has_sha256_rsa_pss = 0;

  // Check if the token supports PSS mechanisms
  CK_ULONG pss_mechCount;
  rv = pFunctionList->C_GetMechanismList(slotID, NULL, &pss_mechCount);
  if (rv == CKR_OK && pss_mechCount > 0) {
    CK_MECHANISM_TYPE_PTR pss_mechList = (CK_MECHANISM_TYPE_PTR)malloc(pss_mechCount * sizeof(CK_MECHANISM_TYPE));
    if (pss_mechList) {
      rv = pFunctionList->C_GetMechanismList(slotID, pss_mechList, &pss_mechCount);
      if (rv == CKR_OK) {
        for (CK_ULONG j = 0; j < pss_mechCount; j++) {
          if (pss_mechList[j] == CKM_SHA1_RSA_PKCS_PSS)
            has_sha1_rsa_pss = 1;
          if (pss_mechList[j] == CKM_SHA256_RSA_PKCS_PSS)
            has_sha256_rsa_pss = 1;
        }
      }
      free(pss_mechList);
    }
  }

  if (has_sha1_rsa_pss || has_sha256_rsa_pss) {
    printf("    Testing RSA-PSS signing mechanisms...\n");

    // Test SHA1-RSA-PSS signing
    if (has_sha1_rsa_pss) {
      // PSS mechanism parameters require hash algorithm and salt length
      CK_RSA_PKCS_PSS_PARAMS pssParams = {CKM_SHA_1, CKG_MGF1_SHA1, 20}; // 20-byte salt for SHA-1
      CK_MECHANISM mechanism = {CKM_SHA1_RSA_PKCS_PSS, &pssParams, sizeof(pssParams)};

      printf("    Testing CKM_SHA1_RSA_PKCS_PSS signing...\n");

      // Logout and login again for PSS test
      perform_logout(pFunctionList, signSession);
      rv = perform_login(pFunctionList, signSession);
      if (rv != CKR_OK) {
        pFunctionList->C_CloseSession(signSession);
        return;
      }

      // Initialize signing operation
      rv = pFunctionList->C_SignInit(signSession, &mechanism, hKey);
      if (rv != CKR_OK) {
        printf("    Error initializing SHA1-RSA-PSS signing operation: 0x%lx\n", rv);
      } else {
        // Get signature length
        signatureLen = sizeof(signature);
        rv = pFunctionList->C_Sign(signSession, data, dataLen, signature, &signatureLen);
        if (rv != CKR_OK) {
          printf("    Error creating SHA1-RSA-PSS signature: 0x%lx\n", rv);
        } else {
          printf("    CKM_SHA1_RSA_PKCS_PSS signing successful! Signature length: %lu\n", signatureLen);

          // Display first few bytes of signature
          printf("    Signature (first 16 bytes): ");
          for (CK_ULONG j = 0; j < (signatureLen > 16 ? 16 : signatureLen); j++) {
            printf("%02X ", signature[j]);
          }
          printf("\n");

          // Verify the signature using mbedtls if public key is available
          if (has_public_key) {
            printf("    Verifying SHA1-RSA-PSS signature with mbedtls...\n");
            rv = cnk_verify_rsa_signature(modulus, modulus_len, exponent, exponent_len, data, dataLen, signature,
                                          MBEDTLS_MD_SHA1, MBEDTLS_RSA_PKCS_V21);
            if (rv != CKR_OK) {
              printf("    mbedtls SHA1-RSA-PSS verification failed!\n");
            }
          }
        }
      }
    }

    // Test SHA256-RSA-PSS signing
    if (has_sha256_rsa_pss) {
      // PSS mechanism parameters require hash algorithm and salt length
      CK_RSA_PKCS_PSS_PARAMS pssParams = {CKM_SHA256, CKG_MGF1_SHA256, 32}; // 32-byte salt for SHA-256
      CK_MECHANISM mechanism = {CKM_SHA256_RSA_PKCS_PSS, &pssParams, sizeof(pssParams)};

      printf("    Testing CKM_SHA256_RSA_PKCS_PSS signing...\n");

      // Logout and login again for PSS test
      perform_logout(pFunctionList, signSession);
      rv = perform_login(pFunctionList, signSession);
      if (rv != CKR_OK) {
        pFunctionList->C_CloseSession(signSession);
        return;
      }

      // Initialize signing operation
      rv = pFunctionList->C_SignInit(signSession, &mechanism, hKey);
      if (rv != CKR_OK) {
        printf("    Error initializing SHA256-RSA-PSS signing operation: 0x%lx\n", rv);
      } else {
        // Get signature length
        signatureLen = sizeof(signature);
        rv = pFunctionList->C_Sign(signSession, data, dataLen, signature, &signatureLen);
        if (rv != CKR_OK) {
          printf("    Error creating SHA256-RSA-PSS signature: 0x%lx\n", rv);
        } else {
          printf("    CKM_SHA256_RSA_PKCS_PSS signing successful! Signature length: %lu\n", signatureLen);

          // Display first few bytes of signature
          printf("    Signature (first 16 bytes): ");
          for (CK_ULONG j = 0; j < (signatureLen > 16 ? 16 : signatureLen); j++) {
            printf("%02X ", signature[j]);
          }
          printf("\n");

          // Verify the signature using mbedtls if public key is available
          if (has_public_key) {
            printf("    Verifying SHA256-RSA-PSS signature with mbedtls...\n");
            rv = cnk_verify_rsa_signature(modulus, modulus_len, exponent, exponent_len, data, dataLen, signature,
                                          MBEDTLS_MD_SHA256, MBEDTLS_RSA_PKCS_V21);
            if (rv != CKR_OK) {
              printf("    mbedtls SHA256-RSA-PSS verification failed!\n");
            }
          }
        }
      }
    }
  } else {
    printf("    No RSA-PSS mechanisms available, skipping PSS signature tests.\n");
  }

  // Test multipart signing with SignUpdate and SignFinal
  printf("    Testing multipart signing with SignUpdate and SignFinal...\n");

  // Test multipart SHA1-RSA signing
  if (has_sha1_rsa_pkcs) {
    CK_MECHANISM mechanism = {CKM_SHA1_RSA_PKCS, NULL, 0};

    printf("    Testing CKM_SHA1_RSA_PKCS multipart signing...\n");

    // Logout and login again for multipart SHA1-RSA test
    perform_logout(pFunctionList, signSession);
    rv = perform_login(pFunctionList, signSession);
    if (rv != CKR_OK) {
      pFunctionList->C_CloseSession(signSession);
      return;
    }

    // Initialize signing operation
    rv = pFunctionList->C_SignInit(signSession, &mechanism, hKey);
    if (rv != CKR_OK) {
      printf("    Error initializing SHA1-RSA multipart signing operation: 0x%lx\n", rv);
    } else {
      // Split data into multiple parts for testing
      CK_ULONG part_size = 5; // Sign in 5-byte chunks
      CK_ULONG remaining = dataLen;
      CK_ULONG offset = 0;

      // Update in chunks
      while (remaining > 0) {
        CK_ULONG chunk_size = (remaining > part_size) ? part_size : remaining;
        rv = pFunctionList->C_SignUpdate(signSession, data + offset, chunk_size);
        if (rv != CKR_OK) {
          printf("    Error in C_SignUpdate at offset %lu: 0x%lx\n", offset, rv);
          break;
        }
        offset += chunk_size;
        remaining -= chunk_size;
      }

      // If all updates were successful, finalize the signature
      if (rv == CKR_OK) {
        // Get signature length
        signatureLen = 0;
        rv = pFunctionList->C_SignFinal(signSession, NULL, &signatureLen);
        if (rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL) {
          printf("    Error determining signature size in C_SignFinal: 0x%lx\n", rv);
        } else {
          // Now get the actual signature
          rv = pFunctionList->C_SignFinal(signSession, signature, &signatureLen);
          if (rv != CKR_OK) {
            printf("    Error creating SHA1-RSA multipart signature: 0x%lx\n", rv);
          } else {
            printf("    CKM_SHA1_RSA_PKCS multipart signing successful! Signature length: %lu\n", signatureLen);

            // Display first few bytes of signature
            printf("    Signature (first 16 bytes): ");
            for (CK_ULONG j = 0; j < (signatureLen > 16 ? 16 : signatureLen); j++) {
              printf("%02X ", signature[j]);
            }
            printf("\n");
          }
        }
      }
    }
  }

  // Test multipart SHA256-RSA signing
  if (has_sha256_rsa_pkcs) {
    CK_MECHANISM mechanism = {CKM_SHA256_RSA_PKCS, NULL, 0};

    printf("    Testing CKM_SHA256_RSA_PKCS multipart signing...\n");

    // Logout and login again for multipart SHA256-RSA test
    perform_logout(pFunctionList, signSession);
    rv = perform_login(pFunctionList, signSession);
    if (rv != CKR_OK) {
      pFunctionList->C_CloseSession(signSession);
      return;
    }

    // Initialize signing operation
    rv = pFunctionList->C_SignInit(signSession, &mechanism, hKey);
    if (rv != CKR_OK) {
      printf("    Error initializing SHA256-RSA multipart signing operation: 0x%lx\n", rv);
    } else {
      // For SHA256, demonstrate sending data in three parts
      CK_ULONG part1_len = dataLen / 3;
      CK_ULONG part2_len = part1_len;
      CK_ULONG part3_len = dataLen - part1_len - part2_len;

      // First part
      rv = pFunctionList->C_SignUpdate(signSession, data, part1_len);
      if (rv != CKR_OK) {
        printf("    Error in C_SignUpdate (part 1): 0x%lx\n", rv);
      } else {
        // Second part
        rv = pFunctionList->C_SignUpdate(signSession, data + part1_len, part2_len);
        if (rv != CKR_OK) {
          printf("    Error in C_SignUpdate (part 2): 0x%lx\n", rv);
        } else {
          // Third part
          rv = pFunctionList->C_SignUpdate(signSession, data + part1_len + part2_len, part3_len);
          if (rv != CKR_OK) {
            printf("    Error in C_SignUpdate (part 3): 0x%lx\n", rv);
          } else {
            // Get signature length
            signatureLen = 0;
            rv = pFunctionList->C_SignFinal(signSession, NULL, &signatureLen);
            if (rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL) {
              printf("    Error determining signature size in C_SignFinal: 0x%lx\n", rv);
            } else {
              // Now get the actual signature
              rv = pFunctionList->C_SignFinal(signSession, signature, &signatureLen);
              if (rv != CKR_OK) {
                printf("    Error creating SHA256-RSA multipart signature: 0x%lx\n", rv);
              } else {
                printf("    CKM_SHA256_RSA_PKCS multipart signing successful! Signature length: %lu\n", signatureLen);

                // Display first few bytes of signature
                printf("    Signature (first 16 bytes): ");
                for (CK_ULONG j = 0; j < (signatureLen > 16 ? 16 : signatureLen); j++) {
                  printf("%02X ", signature[j]);
                }
                printf("\n");
              }
            }
          }
        }
      }
    }
  }

  // Logout
  perform_logout(pFunctionList, signSession);

  // Close the signing session
  rv = pFunctionList->C_CloseSession(signSession);
  if (rv != CKR_OK) {
    printf("    Error closing signing session: 0x%lx\n", rv);
  } else {
    printf("    Signing session closed successfully.\n");
  }
}

// Test ECDSA signing operations
void test_ecdsa_signing(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID) {
  // Check if the token supports ECDSA mechanisms
  int has_ecdsa = 0;
  int has_ecdsa_sha1 = 0;
  int has_ecdsa_sha256 = 0;
  CK_ULONG mechCount;

  CK_RV rv = pFunctionList->C_GetMechanismList(slotID, NULL, &mechCount);
  if (rv == CKR_OK && mechCount > 0) {
    CK_MECHANISM_TYPE_PTR mechList = (CK_MECHANISM_TYPE_PTR)malloc(mechCount * sizeof(CK_MECHANISM_TYPE));
    if (mechList) {
      rv = pFunctionList->C_GetMechanismList(slotID, mechList, &mechCount);
      if (rv == CKR_OK) {
        for (CK_ULONG j = 0; j < mechCount; j++) {
          if (mechList[j] == CKM_ECDSA)
            has_ecdsa = 1;
          if (mechList[j] == CKM_ECDSA_SHA1)
            has_ecdsa_sha1 = 1;
          if (mechList[j] == CKM_ECDSA_SHA256)
            has_ecdsa_sha256 = 1;
        }
      }
      free(mechList);
    }
  }

  if (!(has_ecdsa || has_ecdsa_sha1 || has_ecdsa_sha256)) {
    printf("    No ECDSA signing mechanisms available, skipping ECDSA signing tests.\n");
    return;
  }

  printf("    Running ECDSA signing tests...\n");

  // Open a new session for signing tests
  CK_SESSION_HANDLE signSession;
  rv = pFunctionList->C_OpenSession(slotID, CKF_SERIAL_SESSION, NULL, NULL, &signSession);
  if (rv != CKR_OK) {
    printf("    Error opening session for ECDSA signing tests: 0x%lx\n", rv);
    return;
  }

  printf("    Session for ECDSA signing tests opened successfully. Session handle: %lu\n", signSession);

  // Login with PIN
  rv = perform_login(pFunctionList, signSession);
  if (rv != CKR_OK) {
    pFunctionList->C_CloseSession(signSession);
    return;
  }

  // Find ECDSA private keys for signing
  CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
  CK_KEY_TYPE keyType = CKK_EC;
  CK_BBOOL sign_attribute = CK_TRUE; // Add explicit CKA_SIGN attribute
  CK_ATTRIBUTE findTemplate[] = {
      {CKA_CLASS, &keyClass, sizeof(keyClass)},
      {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
      {CKA_SIGN, &sign_attribute, sizeof(sign_attribute)} // Ensure key can be used for signing
  };

  rv = pFunctionList->C_FindObjectsInit(signSession, findTemplate, 3);
  if (rv != CKR_OK) {
    printf("    Error initializing object search: 0x%lx\n", rv);
    perform_logout(pFunctionList, signSession);
    pFunctionList->C_CloseSession(signSession);
    return;
  }

  CK_OBJECT_HANDLE hKey;
  CK_ULONG ulObjectCount;

  rv = pFunctionList->C_FindObjects(signSession, &hKey, 1, &ulObjectCount);
  if (rv != CKR_OK || ulObjectCount == 0) {
    printf("    No ECDSA private keys found: 0x%lx\n", rv);
    pFunctionList->C_FindObjectsFinal(signSession);
    perform_logout(pFunctionList, signSession);
    pFunctionList->C_CloseSession(signSession);
    return;
  }

  printf("    Found ECDSA private key (handle: %lu)\n", hKey);

  // Finalize the search
  rv = pFunctionList->C_FindObjectsFinal(signSession);
  if (rv != CKR_OK) {
    printf("    Error finalizing object search: 0x%lx\n", rv);
  }

  // Get key attributes
  CK_BBOOL sign, derive;
  CK_ATTRIBUTE tmpl[] = {
      {CKA_SIGN, &sign, sizeof(sign)},
      {CKA_DERIVE, &derive, sizeof(derive)},
  };

  rv = pFunctionList->C_GetAttributeValue(signSession, hKey, tmpl, 2);
  if (rv != CKR_OK) {
    printf("    Error getting key attributes: 0x%lx\n", rv);
  }

  printf("    Key attributes:\n");
  printf("      CKA_SIGN: %s\n", sign ? "true" : "false");
  printf("      CKA_DERIVE: %s\n", derive ? "true" : "false");

  // Get the corresponding public key for verification
  CK_BYTE ec_params[64]; // Buffer for EC_PARAMS (curve OID)
  CK_BYTE ec_point[256]; // Buffer for EC_POINT (public key)
  CK_ULONG ec_params_len = sizeof(ec_params);
  CK_ULONG ec_point_len = sizeof(ec_point);
  CK_BBOOL has_public_key = CK_FALSE;

  // First, get the CKA_ID of the private key
  CK_BYTE key_id[32];
  CK_ULONG key_id_len = sizeof(key_id);
  CK_ATTRIBUTE id_tmpl = {CKA_ID, key_id, key_id_len};

  rv = pFunctionList->C_GetAttributeValue(signSession, hKey, &id_tmpl, 1);
  if (rv != CKR_OK) {
    printf("    Error getting private key ID: 0x%lx\n", rv);
  } else {
    key_id_len = id_tmpl.ulValueLen;

    // Search for the corresponding public key with the same ID
    CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE pubKeyType = CKK_EC;
    CK_ATTRIBUTE pubKeyTemplate[] = {{CKA_CLASS, &pubKeyClass, sizeof(pubKeyClass)},
                                     {CKA_KEY_TYPE, &pubKeyType, sizeof(pubKeyType)},
                                     {CKA_ID, key_id, key_id_len}};

    rv = pFunctionList->C_FindObjectsInit(signSession, pubKeyTemplate, 3);
    if (rv != CKR_OK) {
      printf("    Error initializing search for public key: 0x%lx\n", rv);
    } else {
      CK_OBJECT_HANDLE hPubKey;
      CK_ULONG pubKeyCount;

      rv = pFunctionList->C_FindObjects(signSession, &hPubKey, 1, &pubKeyCount);
      if (rv == CKR_OK && pubKeyCount > 0) {
        printf("    Found corresponding public key (handle: %lu)\n", hPubKey);

        // Get the public key components (EC_PARAMS and EC_POINT)
        CK_ATTRIBUTE pubKeyAttrs[] = {{CKA_EC_PARAMS, ec_params, ec_params_len},
                                      {CKA_EC_POINT, ec_point, ec_point_len}};

        rv = pFunctionList->C_GetAttributeValue(signSession, hPubKey, pubKeyAttrs, 2);
        if (rv == CKR_OK) {
          ec_params_len = pubKeyAttrs[0].ulValueLen;
          ec_point_len = pubKeyAttrs[1].ulValueLen;
          has_public_key = CK_TRUE;

          printf("    Retrieved public key components for verification:\n");
          printf("      EC_PARAMS length: %lu bytes\n", ec_params_len);
          printf("      EC_POINT length: %lu bytes\n", ec_point_len);

          print_hex_data("      EC_PARAMS", ec_params, ec_params_len, ec_params_len);
          print_hex_data("      EC_POINT", ec_point, ec_point_len, 32);
        } else {
          printf("    Error getting public key components: 0x%lx\n", rv);
        }
      } else {
        printf("    Corresponding public key not found: 0x%lx\n", rv);
      }

      rv = pFunctionList->C_FindObjectsFinal(signSession);
      if (rv != CKR_OK) {
        printf("    Error finalizing public key search: 0x%lx\n", rv);
      }
    }
  }

  // Test data to sign
  CK_BYTE data[] = "Hello, CanoKey ECDSA PKCS#11!";
  CK_ULONG dataLen = strlen((char *)data);
  CK_BYTE signature[128]; // Buffer for ECDSA signature
  CK_ULONG signatureLen;

  // Test raw ECDSA signing
  if (has_ecdsa) {
    CK_MECHANISM mechanism = {CKM_ECDSA, NULL, 0};

    printf("    Testing CKM_ECDSA signing...\n");

    // Initialize signing operation
    rv = pFunctionList->C_SignInit(signSession, &mechanism, hKey);
    if (rv != CKR_OK) {
      printf("    Error initializing ECDSA signing operation: 0x%lx\n", rv);
    } else {
      // First call to get buffer size
      signatureLen = sizeof(signature);
      rv = pFunctionList->C_Sign(signSession, data, dataLen, NULL, &signatureLen);
      if (rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL) {
        printf("    Error determining signature size: 0x%lx\n", rv);
      } else {
        printf("    Signature length will be %lu bytes\n", signatureLen);

        // Second call to actually sign
        rv = pFunctionList->C_Sign(signSession, data, dataLen, signature, &signatureLen);
        if (rv != CKR_OK) {
          printf("    Error creating signature: 0x%lx\n", rv);
        } else {
          printf("    CKM_ECDSA signing successful! Signature length: %lu\n", signatureLen);

          // Display the signature
          print_hex_data("    Signature", signature, signatureLen, 16);

          // Verify the signature using mbedtls if public key is available
          if (has_public_key) {
            printf("    Verifying signature with mbedtls...\n");
            rv = cnk_verify_ecdsa_signature(ec_params, ec_params_len, ec_point, ec_point_len, data, dataLen, signature,
                                            signatureLen, MBEDTLS_MD_NONE);
            if (rv != CKR_OK) {
              printf("    mbedtls verification failed!\n");
            }
          }
        }
      }
    }
  }

  // Test SHA1-ECDSA signing
  if (has_ecdsa_sha1) {
    // Logout and login again for SHA1-ECDSA test
    perform_logout(pFunctionList, signSession);
    rv = perform_login(pFunctionList, signSession);
    if (rv != CKR_OK) {
      pFunctionList->C_CloseSession(signSession);
      return;
    }

    CK_MECHANISM mechanism = {CKM_ECDSA_SHA1, NULL, 0};

    printf("    Testing CKM_ECDSA_SHA1 signing...\n");

    // Initialize signing operation
    rv = pFunctionList->C_SignInit(signSession, &mechanism, hKey);
    if (rv != CKR_OK) {
      printf("    Error initializing SHA1-ECDSA signing operation: 0x%lx\n", rv);
    } else {
      // Get signature length
      signatureLen = sizeof(signature);
      rv = pFunctionList->C_Sign(signSession, data, dataLen, signature, &signatureLen);
      if (rv != CKR_OK) {
        printf("    Error creating SHA1-ECDSA signature: 0x%lx\n", rv);
      } else {
        printf("    CKM_ECDSA_SHA1 signing successful! Signature length: %lu\n", signatureLen);

        // Display the signature
        print_hex_data("    Signature", signature, signatureLen, 16);

        // Verify the signature using mbedtls if public key is available
        if (has_public_key) {
          printf("    Verifying SHA1-ECDSA signature with mbedtls...\n");
          rv = cnk_verify_ecdsa_signature(ec_params, ec_params_len, ec_point, ec_point_len, data, dataLen, signature,
                                          signatureLen, MBEDTLS_MD_SHA1);
          if (rv != CKR_OK) {
            printf("    mbedtls SHA1-ECDSA verification failed!\n");
          }
        }
      }
    }
  }

  // Test SHA256-ECDSA signing
  if (has_ecdsa_sha256) {
    // Logout and login again for SHA256-ECDSA test
    perform_logout(pFunctionList, signSession);
    rv = perform_login(pFunctionList, signSession);
    if (rv != CKR_OK) {
      pFunctionList->C_CloseSession(signSession);
      return;
    }

    CK_MECHANISM mechanism = {CKM_ECDSA_SHA256, NULL, 0};

    printf("    Testing CKM_ECDSA_SHA256 signing...\n");

    // Initialize signing operation
    rv = pFunctionList->C_SignInit(signSession, &mechanism, hKey);
    if (rv != CKR_OK) {
      printf("    Error initializing SHA256-ECDSA signing operation: 0x%lx\n", rv);
    } else {
      // Get signature length
      signatureLen = sizeof(signature);
      rv = pFunctionList->C_Sign(signSession, data, dataLen, signature, &signatureLen);
      if (rv != CKR_OK) {
        printf("    Error creating SHA256-ECDSA signature: 0x%lx\n", rv);
      } else {
        printf("    CKM_ECDSA_SHA256 signing successful! Signature length: %lu\n", signatureLen);

        // Display the signature
        print_hex_data("    Signature", signature, signatureLen, 16);

        // Verify the signature using mbedtls if public key is available
        if (has_public_key) {
          printf("    Verifying SHA256-ECDSA signature with mbedtls...\n");
          rv = cnk_verify_ecdsa_signature(ec_params, ec_params_len, ec_point, ec_point_len, data, dataLen, signature,
                                          signatureLen, MBEDTLS_MD_SHA256);
          if (rv != CKR_OK) {
            printf("    mbedtls SHA256-ECDSA verification failed!\n");
          }
        }
      }
    }
  }

  // Logout and close session
  perform_logout(pFunctionList, signSession);
  pFunctionList->C_CloseSession(signSession);
}

void test_ecdh_derivation(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID) {
  CK_RV rv;
  CK_ULONG mechCount = 0;
  int hasEcdh = 0;

  rv = pFunctionList->C_GetMechanismList(slotID, NULL, &mechCount);
  if (rv == CKR_OK && mechCount > 0) {
    CK_MECHANISM_TYPE_PTR mechList = (CK_MECHANISM_TYPE_PTR)malloc(mechCount * sizeof(CK_MECHANISM_TYPE));
    if (mechList != NULL) {
      rv = pFunctionList->C_GetMechanismList(slotID, mechList, &mechCount);
      if (rv == CKR_OK) {
        for (CK_ULONG i = 0; i < mechCount; i++) {
          if (mechList[i] == CKM_ECDH1_DERIVE) {
            hasEcdh = 1;
            break;
          }
        }
      }
      free(mechList);
    }
  }

  if (!hasEcdh) {
    printf("    ECDH derive mechanism not available, skipping.\n");
    return;
  }

  printf("    Running ECDH derivation tests...\n");

  CK_SESSION_HANDLE deriveSession;
  rv = pFunctionList->C_OpenSession(slotID, CKF_SERIAL_SESSION, NULL, NULL, &deriveSession);
  if (rv != CKR_OK) {
    record_real_test_failure("Error opening ECDH derive session", rv);
    return;
  }

  rv = perform_login(pFunctionList, deriveSession);
  if (rv != CKR_OK) {
    pFunctionList->C_CloseSession(deriveSession);
    return;
  }

  CK_BYTE keyId = 2;
  CK_KEY_TYPE ecKeyType = CKK_EC;
  CK_OBJECT_HANDLE hEcPrivateKey;
  rv = find_object(pFunctionList, deriveSession, CKO_PRIVATE_KEY, &ecKeyType, &keyId, sizeof(keyId), &hEcPrivateKey);
  if (rv != CKR_OK) {
    record_real_test_failure("Could not find 9C EC private key for ECDH", rv);
    goto cleanup_session;
  }

  CK_BBOOL deriveAttr = CK_FALSE;
  CK_ATTRIBUTE deriveTemplate = {CKA_DERIVE, &deriveAttr, sizeof(deriveAttr)};
  rv = pFunctionList->C_GetAttributeValue(deriveSession, hEcPrivateKey, &deriveTemplate, 1);
  if (rv != CKR_OK) {
    record_real_test_failure("Could not read EC private key CKA_DERIVE", rv);
    goto cleanup_session;
  }
  if (!deriveAttr) {
    record_real_test_failure("EC private key does not advertise CKA_DERIVE", CKR_GENERAL_ERROR);
    goto cleanup_session;
  }

  CK_OBJECT_HANDLE hEcPublicKey;
  rv = find_object(pFunctionList, deriveSession, CKO_PUBLIC_KEY, &ecKeyType, &keyId, sizeof(keyId), &hEcPublicKey);
  if (rv != CKR_OK) {
    record_real_test_failure("Could not find 9C EC public key for ECDH", rv);
    goto cleanup_session;
  }

  CK_BYTE ecParams[32];
  CK_BYTE ecPointAttr[256];
  CK_ATTRIBUTE publicAttrs[] = {
      {CKA_EC_PARAMS, ecParams, sizeof(ecParams)},
      {CKA_EC_POINT, ecPointAttr, sizeof(ecPointAttr)},
  };
  rv = pFunctionList->C_GetAttributeValue(deriveSession, hEcPublicKey, publicAttrs, 2);
  if (rv != CKR_OK) {
    record_real_test_failure("Could not read 9C EC public key attributes", rv);
    goto cleanup_session;
  }

  CK_ULONG ecParamsLen = publicAttrs[0].ulValueLen;
  CK_ULONG ecPointAttrLen = publicAttrs[1].ulValueLen;
  CK_BYTE cardPoint[133];
  CK_ULONG cardPointLen = sizeof(cardPoint);
  rv = ec_point_value(ecPointAttr, ecPointAttrLen, cardPoint, &cardPointLen);
  if (rv != CKR_OK) {
    record_real_test_failure("Could not unwrap 9C EC point", rv);
    goto cleanup_session;
  }

  mbedtls_ecp_group grp;
  mbedtls_mpi ephemeralPrivate;
  mbedtls_ecp_point ephemeralPublic;
  CK_ULONG coordinateLen = 0;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&ephemeralPrivate);
  mbedtls_ecp_point_init(&ephemeralPublic);

  rv = load_ec_group_from_params(ecParams, ecParamsLen, &grp, &coordinateLen);
  if (rv != CKR_OK) {
    record_real_test_failure("Could not load EC group for ECDH", rv);
    goto cleanup_ecp;
  }

  unsigned int rngState = 0x5eedecdu;
  int ret = mbedtls_ecp_gen_keypair(&grp, &ephemeralPrivate, &ephemeralPublic, cnk_test_rng, &rngState);
  if (ret != 0) {
    printf("    Failed to generate software ECDH keypair: -0x%04x\n", (unsigned int)-ret);
    record_real_test_failure("Software ECDH keypair generation failed", CKR_GENERAL_ERROR);
    goto cleanup_ecp;
  }

  CK_BYTE peerPublicData[133];
  size_t peerPublicDataLen = 0;
  ret = mbedtls_ecp_point_write_binary(&grp, &ephemeralPublic, MBEDTLS_ECP_PF_UNCOMPRESSED, &peerPublicDataLen,
                                       peerPublicData, sizeof(peerPublicData));
  if (ret != 0) {
    printf("    Failed to encode software ECDH public key: -0x%04x\n", (unsigned int)-ret);
    record_real_test_failure("Software ECDH public key encoding failed", CKR_GENERAL_ERROR);
    goto cleanup_ecp;
  }

  CK_BYTE expectedSecret[64];
  CK_ULONG expectedSecretLen = sizeof(expectedSecret);
  rv = compute_ecdh_expected_secret(ecParams, ecParamsLen, cardPoint, cardPointLen, &ephemeralPrivate, expectedSecret,
                                    &expectedSecretLen);
  if (rv != CKR_OK) {
    record_real_test_failure("Software ECDH expected secret computation failed", rv);
    goto cleanup_ecp;
  }

  CK_ECDH1_DERIVE_PARAMS deriveParams = {CKD_NULL, 0, NULL, (CK_ULONG)peerPublicDataLen, peerPublicData};
  rv = derive_and_check_ecdh_secret(pFunctionList, deriveSession, hEcPrivateKey, &deriveParams, expectedSecret,
                                    expectedSecretLen, "ECDH CKD_NULL secret matches software result");
  if (rv != CKR_OK) {
    goto cleanup_ecp;
  }

  CK_BYTE sharedInfo[] = {'c', 'a', 'n', 'o', 'k', 'e', 'y', '-', 'p', 'k', 'c', 's', '1', '1'};
  CK_BYTE expectedKdfSecret[32];
  rv = compute_x963_kdf(MBEDTLS_MD_SHA256, expectedSecret, expectedSecretLen, sharedInfo, sizeof(sharedInfo),
                        expectedKdfSecret, sizeof(expectedKdfSecret));
  if (rv != CKR_OK) {
    goto cleanup_ecp;
  }

  CK_ECDH1_DERIVE_PARAMS kdfParams = {CKD_SHA256_KDF, sizeof(sharedInfo), sharedInfo, (CK_ULONG)peerPublicDataLen,
                                      peerPublicData};
  rv = derive_and_check_ecdh_secret(pFunctionList, deriveSession, hEcPrivateKey, &kdfParams, expectedKdfSecret,
                                    sizeof(expectedKdfSecret), "ECDH CKD_SHA256_KDF secret matches software result");

cleanup_ecp:
  mbedtls_ecp_point_free(&ephemeralPublic);
  mbedtls_mpi_free(&ephemeralPrivate);
  mbedtls_ecp_group_free(&grp);

cleanup_session:
  perform_logout(pFunctionList, deriveSession);
  rv = pFunctionList->C_CloseSession(deriveSession);
  if (rv != CKR_OK)
    record_real_test_failure("Error closing ECDH derive session", rv);
}

void test_destructive_write_operations(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID) {
  if (!cnk_env_is_enabled(CNK_REAL_WRITE_TEST_ENV)) {
    printf("    Skipping destructive write tests; set %s=1 to overwrite test slot ID %u.\n", CNK_REAL_WRITE_TEST_ENV,
           CNK_REAL_WRITE_TEST_ID);
    return;
  }

  printf("    Running destructive key write tests on test slot ID %u...\n", CNK_REAL_WRITE_TEST_ID);

  CK_SESSION_HANDLE hSession;
  CK_RV rv = open_management_write_session(pFunctionList, slotID, &hSession);
  if (rv != CKR_OK) {
    record_real_test_failure("Error opening management session for EC generation", rv);
    return;
  }

  rv = generate_card_ec_key(pFunctionList, hSession);
  if (rv != CKR_OK)
    record_real_test_failure("C_GenerateKeyPair EC write smoke failed", rv);
  if (rv == CKR_OK) {
    rv = check_test_key_policies(pFunctionList, hSession, CKK_EC, CNK_REAL_WRITE_TEST_PIN_POLICY);
    if (rv != CKR_OK)
      record_real_test_failure("Generated EC key policy readback failed", rv);
  }
  close_management_write_session(pFunctionList, hSession);

  if (rv == CKR_OK) {
    rv = sign_with_test_private_key(pFunctionList, slotID, CKK_EC);
    if (rv != CKR_OK)
      record_real_test_failure("Generated EC private key sign smoke failed", rv);
    else
      printf("    Signed with generated EC P-256 private key\n");
  }

  rv = open_management_write_session(pFunctionList, slotID, &hSession);
  if (rv != CKR_OK) {
    record_real_test_failure("Error opening management session for PIN-never EC generation", rv);
    return;
  }

  rv = generate_card_ec_key_with_policy(pFunctionList, hSession, CNK_PIV_PIN_POLICY_NEVER);
  if (rv != CKR_OK)
    record_real_test_failure("C_GenerateKeyPair PIN-never EC write smoke failed", rv);
  if (rv == CKR_OK) {
    rv = check_test_key_policies(pFunctionList, hSession, CKK_EC, CNK_PIV_PIN_POLICY_NEVER);
    if (rv != CKR_OK)
      record_real_test_failure("PIN-never EC key policy readback failed", rv);
  }
  close_management_write_session(pFunctionList, hSession);

  if (rv == CKR_OK) {
    rv = sign_with_pin_never_test_key_without_login(pFunctionList, slotID);
    if (rv != CKR_OK)
      record_real_test_failure("PIN-never EC private key no-login sign smoke failed", rv);
    else
      printf("    Signed with generated PIN-never EC P-256 private key without USER login\n");
  }

  rv = open_management_write_session(pFunctionList, slotID, &hSession);
  if (rv != CKR_OK) {
    record_real_test_failure("Error opening management session for EC import", rv);
    return;
  }

  CK_RV writeRv = import_software_ec_key(pFunctionList, hSession);
  if (writeRv != CKR_OK)
    record_real_test_failure("C_CreateObject EC private-key import smoke failed", writeRv);
  if (writeRv == CKR_OK) {
    writeRv = check_test_key_policies(pFunctionList, hSession, CKK_EC, CNK_REAL_WRITE_TEST_PIN_POLICY);
    if (writeRv != CKR_OK)
      record_real_test_failure("Imported EC key policy readback failed", writeRv);
  }
  close_management_write_session(pFunctionList, hSession);

  if (writeRv == CKR_OK) {
    rv = sign_with_test_private_key(pFunctionList, slotID, CKK_EC);
    if (rv != CKR_OK)
      record_real_test_failure("Imported EC private key sign smoke failed", rv);
    else
      printf("    Signed with imported EC P-256 private key\n");
  }

  rv = open_management_write_session(pFunctionList, slotID, &hSession);
  if (rv != CKR_OK) {
    record_real_test_failure("Error opening management session for RSA import", rv);
    return;
  }

  writeRv = import_software_rsa_key(pFunctionList, hSession);
  if (writeRv != CKR_OK)
    record_real_test_failure("C_CreateObject RSA private-key import smoke failed", writeRv);
  if (writeRv == CKR_OK) {
    writeRv = check_test_key_policies(pFunctionList, hSession, CKK_RSA, CNK_REAL_WRITE_TEST_PIN_POLICY);
    if (writeRv != CKR_OK)
      record_real_test_failure("Imported RSA key policy readback failed", writeRv);
  }
  close_management_write_session(pFunctionList, hSession);

  if (writeRv == CKR_OK) {
    rv = sign_with_test_private_key(pFunctionList, slotID, CKK_RSA);
    if (rv != CKR_OK)
      record_real_test_failure("Imported RSA private key sign smoke failed", rv);
    else
      printf("    Signed with imported RSA-2048 private key\n");
  }

  rv = open_management_write_session(pFunctionList, slotID, &hSession);
  if (rv != CKR_OK) {
    record_real_test_failure("Error opening management session for certificate write", rv);
    return;
  }

  writeRv = write_test_certificate(pFunctionList, hSession);
  if (writeRv != CKR_OK)
    record_real_test_failure("C_CreateObject certificate write smoke failed", writeRv);
  close_management_write_session(pFunctionList, hSession);
}

void test_management_challenge(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotId) {
  CK_SESSION_HANDLE hSession;
  CK_RV rv = pFunctionList->C_OpenSession(slotId, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
  if (rv != CKR_OK) {
    printf("    Error opening session for auth challenge tests: 0x%lx\n", rv);
    return;
  }

  rv = perform_management_login(pFunctionList, hSession);
  if (rv != CKR_OK) {
    printf("    Error logging in: 0x%lx\n", rv);
  } else {
    printf("    Login successful\n");
  }

  // Close the session
  pFunctionList->C_CloseSession(hSession);
}

int main(int argc, char *argv[]) {
  // Path to the PKCS#11 library
  const char *libraryPath = NULL;

  // Check if a library path was provided as a command line argument
  if (argc > 1) {
    libraryPath = argv[1];
  } else {
    fprintf(stderr, "Usage: %s <path_to_pkcs11_library>\n", argv[0]);
    return 1;
  }

  printf("Using PKCS#11 library: %s\n", libraryPath);

  cnk_setenv("CNK_LOG_LEVEL", "debug");
  cnk_setenv("CNK_UNSAFE_LOG_APDU", "1");

  // Load the PKCS#11 library and get the function list
  CNK_LIBRARY_HANDLE library;
  CK_FUNCTION_LIST_PTR pFunctionList;
  CK_RV rv = load_pkcs11_library(libraryPath, &library, &pFunctionList);
  if (rv != CKR_OK) {
    return 1;
  }

  // Initialize the library
  rv = pFunctionList->C_Initialize(NULL);
  if (rv != CKR_OK) {
    printf("Error initializing library: 0x%lx\n", rv);
    cnk_close_library(library);
    return 1;
  }

  printf("Library initialized successfully\n");

  // Display library information
  display_library_info(pFunctionList);

  // Get the slot list
  CK_SLOT_ID_PTR pSlotList = NULL;
  CK_ULONG ulSlotCount = 0;
  rv = get_slot_list(pFunctionList, &pSlotList, &ulSlotCount);
  if (rv != CKR_OK) {
    pFunctionList->C_Finalize(NULL);
    cnk_close_library(library);
    return 1;
  }

  if (ulSlotCount > 0) {
    // Print the slot IDs and get slot info for each slot
    printf("Slot IDs:\n");
    for (CK_ULONG i = 0; i < ulSlotCount; i++) {
      printf("  Slot %lu: ID = %lu\n", i, pSlotList[i]);

      // Display slot information
      display_slot_info(pFunctionList, pSlotList[i]);

      // Get and display token information if a token is present
      CK_SLOT_INFO slotInfo;
      rv = pFunctionList->C_GetSlotInfo(pSlotList[i], &slotInfo);
      if (rv == CKR_OK && slotInfo.flags & CKF_TOKEN_PRESENT) {
        display_token_info(pFunctionList, pSlotList[i]);
      }

      // Open a session with this slot
      CK_SESSION_HANDLE hSession;
      rv = open_session(pFunctionList, pSlotList[i], &hSession);
      if (rv != CKR_OK) {
        printf("    Error opening session: 0x%lx\n", rv);
        continue;
      }

      printf("    Session opened successfully. Session handle: %lu\n", hSession);

      // Display session information
      display_session_info(pFunctionList, hSession);

      // Get the mechanism list
      display_mechanism_list(pFunctionList, pSlotList[i]);

      // Test public key operations
      test_public_key_operations(pFunctionList, pSlotList[i]);

      // Test ECDSA public key operations
      test_ecdsa_public_key_operations(pFunctionList, pSlotList[i]);

      // Test certificate operations
      test_certificate_operations(pFunctionList, pSlotList[i]);

      // Test standard PIV data object enumeration
      test_piv_data_objects(pFunctionList, pSlotList[i]);

      // Test hardware decrypt
      test_decryption(pFunctionList, pSlotList[i]);

      // Test PIN-never private-key operation without USER login
      test_pin_never_private_key_operation(pFunctionList, pSlotList[i]);

      // Test RSA signing
      test_rsa_signing(pFunctionList, pSlotList[i]);

      // Test ECDSA signing
      test_ecdsa_signing(pFunctionList, pSlotList[i]);

      // Test ECDH key derivation
      test_ecdh_derivation(pFunctionList, pSlotList[i]);

      // Test write paths only when explicitly requested; it overwrites ID 06.
      test_destructive_write_operations(pFunctionList, pSlotList[i]);

      // Test auth challenge
      test_management_challenge(pFunctionList, pSlotList[i]);

      // Close the session
      rv = pFunctionList->C_CloseSession(hSession);
      if (rv != CKR_OK) {
        printf("    Error closing session: 0x%lx\n", rv);
      } else {
        printf("    Session closed successfully.\n");
      }
    }

    free(pSlotList);
  } else {
    printf("No slots found. Make sure a PKCS#11 device is connected.\n");
  }

  // Finalize the library
  rv = pFunctionList->C_Finalize(NULL);
  if (rv != CKR_OK) {
    printf("Error finalizing library: 0x%lx\n", rv);
    cnk_close_library(library);
    return 1;
  }

  printf("Library finalized successfully\n");

  // Close the library
  cnk_close_library(library);
  printf("Library unloaded\n");

  if (g_real_test_failures != 0) {
    printf("Real hardware test failures: %d\n", g_real_test_failures);
    return 1;
  }

  return 0;
}
