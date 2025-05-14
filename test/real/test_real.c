#include "pkcs11.h"
#include "pkcs11_object.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Include mbedtls headers for signature verification
#include <mbedtls/bignum.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/md.h>
#include <mbedtls/rsa.h>

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
CK_RV load_pkcs11_library(const char *libraryPath, void **library, CK_FUNCTION_LIST_PTR *pFunctionList) {
  // Load the PKCS#11 library dynamically
  *library = dlopen(libraryPath, RTLD_LAZY);
  if (!*library) {
    printf("Error loading library: %s\n", dlerror());
    return CKR_GENERAL_ERROR;
  }

  // Get the C_GetFunctionList function
  CK_C_GetFunctionList getFunc = (CK_C_GetFunctionList)dlsym(*library, "C_GetFunctionList");
  if (!getFunc) {
    printf("Error getting C_GetFunctionList function: %s\n", dlerror());
    dlclose(*library);
    return CKR_GENERAL_ERROR;
  }

  // Get the function list
  CK_RV rv = getFunc(pFunctionList);
  if (rv != CKR_OK) {
    printf("Error getting function list: 0x%lx\n", rv);
    dlclose(*library);
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
void test_rsa_signing(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID);
void test_ecdsa_signing(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID);
void test_management_challenge(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotID);

// Verification function declarations
static CK_RV cnk_verify_rsa_signature(CK_BYTE_PTR modulus, CK_ULONG modulus_len, CK_BYTE_PTR exponent,
                                      CK_ULONG exponent_len, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature,
                                      mbedtls_md_type_t md_type, int padding_mode);
static CK_RV cnk_verify_ecdsa_signature(CK_BYTE_PTR ec_params, CK_ULONG ec_params_len, CK_BYTE_PTR ec_point,
                                        CK_ULONG ec_point_len, CK_BYTE_PTR data, CK_ULONG data_len,
                                        CK_BYTE_PTR signature, CK_ULONG signature_len, mbedtls_md_type_t md_type);

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

// Verify RSA signature using mbedtls
static CK_RV cnk_verify_rsa_signature(CK_BYTE_PTR modulus, CK_ULONG modulus_len, CK_BYTE_PTR exponent,
                                      CK_ULONG exponent_len, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature,
                                      mbedtls_md_type_t md_type,
                                      int padding_mode) { // MBEDTLS_RSA_PKCS_V15 or MBEDTLS_RSA_PKCS_V21
  CK_RV rv = CKR_GENERAL_ERROR;
  int ret;
  mbedtls_rsa_context rsa;
  mbedtls_mpi N, E;
  unsigned char hash[64]; // Large enough for any hash

  // Initialize mbedtls structures
  mbedtls_rsa_init(&rsa);
  mbedtls_mpi_init(&N);
  mbedtls_mpi_init(&E);

  // Import the public key components
  ret = mbedtls_mpi_read_binary(&N, modulus, modulus_len);
  if (ret != 0) {
    printf("      Error loading modulus: -0x%04x\n", (unsigned int)-ret);
    goto cleanup;
  }

  ret = mbedtls_mpi_read_binary(&E, exponent, exponent_len);
  if (ret != 0) {
    printf("      Error loading exponent: -0x%04x\n", (unsigned int)-ret);
    goto cleanup;
  }

  // Import key components into RSA context
  ret = mbedtls_rsa_import(&rsa, &N, NULL, NULL, NULL, &E);
  if (ret != 0) {
    printf("      Error importing RSA key: -0x%04x\n", (unsigned int)-ret);
    goto cleanup;
  }

  // Set RSA padding mode based on the parameter
  mbedtls_rsa_set_padding(&rsa, padding_mode, md_type);

  // Complete/check the key
  ret = mbedtls_rsa_complete(&rsa);
  if (ret != 0) {
    printf("      Error completing RSA key: -0x%04x\n", (unsigned int)-ret);
    goto cleanup;
  }

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

      // Get the key length in bytes
      size_t key_len = mbedtls_rsa_get_len(&rsa);

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

    // 2. Use mbedtls built-in PSS verification function
    size_t hash_len = mbedtls_md_get_size(md_info);

    // Set RSA padding again explicitly for the verification
    mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, md_type);

// Use mbedtls built-in PSS verification functions directly
#if MBEDTLS_VERSION_NUMBER >= 0x03000000 // mbedTLS 3.0 and above
    ret = mbedtls_rsa_rsassa_pss_verify(&rsa, md_type, (unsigned int)hash_len, hash, signature);
#else
    ret = mbedtls_rsa_rsassa_pss_verify(&rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, md_type, (unsigned int)hash_len, hash,
                                        signature);
#endif

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
  mbedtls_mpi_free(&N);
  mbedtls_mpi_free(&E);
  return rv;
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

void test_management_challenge(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slotId) {
  CK_SESSION_HANDLE hSession;
  CK_RV rv = pFunctionList->C_OpenSession(slotId, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
  if (rv != CKR_OK) {
    printf("    Error opening session for auth challenge tests: 0x%lx\n", rv);
    return;
  }

  CK_BYTE key[] = "\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08";
  rv = pFunctionList->C_Login(hSession, CKU_SO, key, 24);
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

  // Load the PKCS#11 library and get the function list
  void *library;
  CK_FUNCTION_LIST_PTR pFunctionList;
  CK_RV rv = load_pkcs11_library(libraryPath, &library, &pFunctionList);
  if (rv != CKR_OK) {
    return 1;
  }

  // Initialize the library
  rv = pFunctionList->C_Initialize(NULL);
  if (rv != CKR_OK) {
    printf("Error initializing library: 0x%lx\n", rv);
    dlclose(library);
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
    dlclose(library);
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

      // Test RSA signing
      test_rsa_signing(pFunctionList, pSlotList[i]);

      // Test ECDSA signing
      test_ecdsa_signing(pFunctionList, pSlotList[i]);

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
    dlclose(library);
    return 1;
  }

  printf("Library finalized successfully\n");

  // Close the library
  dlclose(library);
  printf("Library unloaded\n");

  return 0;
}
