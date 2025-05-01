#include "pkcs11.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

  // // Test public key operations
  // keyClass = CKO_PUBLIC_KEY;
  // rv = pFunctionList->C_FindObjectsInit(certSession, findTemplate, 2);
  // if (rv != CKR_OK) {
  //   printf("    Error initializing object search: 0x%lx\n", rv);
  // } else {
  //   CK_OBJECT_HANDLE hKey;
  //   CK_ULONG ulObjectCount;
  //
  //   rv = pFunctionList->C_FindObjects(certSession, &hKey, 1, &ulObjectCount);
  //   if (rv != CKR_OK || ulObjectCount == 0) {
  //     printf("    No key found: 0x%lx\n", rv);
  //   } else {
  //     printf("    Found key (handle: %lu)\n", hKey);
  //
  //     // Finalize the search
  //     rv = pFunctionList->C_FindObjectsFinal(certSession);
  //     if (rv != CKR_OK) {
  //       printf("    Error finalizing object search: 0x%lx\n", rv);
  //     }
  //
  //     CK_BYTE modulus[4096], publicExponent[8];
  //     CK_ATTRIBUTE templates[] = {
  //         {CKA_MODULUS, modulus, sizeof(modulus)},
  //         {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)}};
  //
  //     rv = pFunctionList->C_GetAttributeValue(certSession, hKey, templates, 2);
  //     if (rv != CKR_OK) {
  //       printf("      Error getting key attributes: 0x%lx\n", rv);
  //     } else {
  //       print_hex_data("modulus value", modulus, templates[0].ulValueLen, 32);
  //       print_hex_data("public exponent value", publicExponent, templates[1].ulValueLen, 32);
  //     }
  //   }
  // }

  // Close the session
  pFunctionList->C_CloseSession(certSession);
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

      // Test certificate operations
      test_certificate_operations(pFunctionList, pSlotList[i]);

      // Test RSA signing
      test_rsa_signing(pFunctionList, pSlotList[i]);

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
