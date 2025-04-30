#include "pkcs11.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

  // Load the PKCS#11 library dynamically
  void *library = dlopen(libraryPath, RTLD_LAZY);
  if (!library) {
    printf("Error loading library: %s\n", dlerror());
    return 1;
  }

  // Get the C_GetFunctionList function
  CK_C_GetFunctionList getFunc = (CK_C_GetFunctionList)dlsym(library, "C_GetFunctionList");
  if (!getFunc) {
    printf("Error getting C_GetFunctionList function: %s\n", dlerror());
    dlclose(library);
    return 1;
  }

  // Get the function list
  CK_FUNCTION_LIST_PTR pFunctionList = NULL;
  CK_RV rv = getFunc(&pFunctionList);
  if (rv != CKR_OK) {
    printf("Error getting function list: 0x%lx\n", rv);
    dlclose(library);
    return 1;
  }

  printf("Successfully loaded PKCS#11 library\n");

  // Initialize the library
  rv = pFunctionList->C_Initialize(NULL);
  if (rv != CKR_OK) {
    printf("Error initializing library: 0x%lx\n", rv);
    dlclose(library);
    return 1;
  }

  printf("Library initialized successfully\n");

  // Get library information
  CK_INFO info;
  rv = pFunctionList->C_GetInfo(&info);
  if (rv != CKR_OK) {
    printf("Error getting library info: 0x%lx\n", rv);
  } else {
    // Convert fixed-length fields to null-terminated strings
    char manufacturerID[33] = {0};
    char libraryDescription[33] = {0};

    memcpy(manufacturerID, info.manufacturerID, sizeof(info.manufacturerID));
    memcpy(libraryDescription, info.libraryDescription, sizeof(info.libraryDescription));

    // Trim trailing spaces
    for (int i = sizeof(info.manufacturerID) - 1; i >= 0; i--) {
      if (manufacturerID[i] == ' ') {
        manufacturerID[i] = '\0';
      } else {
        break;
      }
    }

    for (int i = sizeof(info.libraryDescription) - 1; i >= 0; i--) {
      if (libraryDescription[i] == ' ') {
        libraryDescription[i] = '\0';
      } else {
        break;
      }
    }

    printf("PKCS#11 Library Information:\n");
    printf("  Cryptoki Version: %d.%d\n", info.cryptokiVersion.major, info.cryptokiVersion.minor);
    printf("  Manufacturer: %s\n", manufacturerID);
    printf("  Library Description: %s\n", libraryDescription);
    printf("  Library Version: %d.%d\n", info.libraryVersion.major, info.libraryVersion.minor);
  }

  // Get the number of slots
  CK_ULONG ulSlotCount = 0;
  rv = pFunctionList->C_GetSlotList(CK_FALSE, NULL, &ulSlotCount);
  if (rv != CKR_OK) {
    printf("Error getting slot count: 0x%lx\n", rv);
    pFunctionList->C_Finalize(NULL);
    dlclose(library);
    return 1;
  }

  printf("Number of slots: %lu\n", ulSlotCount);

  if (ulSlotCount > 0) {
    // Allocate memory for the slot list
    CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR)malloc(ulSlotCount * sizeof(CK_SLOT_ID));
    if (!pSlotList) {
      printf("Memory allocation failed\n");
      pFunctionList->C_Finalize(NULL);
      dlclose(library);
      return 1;
    }

    // Get the slot list
    rv = pFunctionList->C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
    if (rv != CKR_OK) {
      printf("Error getting slot list: 0x%lx\n", rv);
      free(pSlotList);
      pFunctionList->C_Finalize(NULL);
      dlclose(library);
      return 1;
    }

    // Print the slot IDs and get slot info for each slot
    printf("Slot IDs:\n");
    for (CK_ULONG i = 0; i < ulSlotCount; i++) {
      printf("  Slot %lu: ID = %lu\n", i, pSlotList[i]);

      // Get and display slot info
      CK_SLOT_INFO slotInfo;
      rv = pFunctionList->C_GetSlotInfo(pSlotList[i], &slotInfo);
      if (rv != CKR_OK) {
        printf("    Error getting slot info: 0x%lx\n", rv);
        continue;
      }

      // Convert the fixed-length fields to null-terminated strings for display
      char description[65] = {0};
      char manufacturer[33] = {0};

      memcpy(description, slotInfo.slotDescription, sizeof(slotInfo.slotDescription));
      description[sizeof(slotInfo.slotDescription)] = '\0';
      // Trim trailing spaces
      for (int j = sizeof(slotInfo.slotDescription) - 1; j >= 0; j--) {
        if (description[j] == ' ') {
          description[j] = '\0';
        } else {
          break;
        }
      }

      memcpy(manufacturer, slotInfo.manufacturerID, sizeof(slotInfo.manufacturerID));
      manufacturer[sizeof(slotInfo.manufacturerID)] = '\0';
      // Trim trailing spaces
      for (int j = sizeof(slotInfo.manufacturerID) - 1; j >= 0; j--) {
        if (manufacturer[j] == ' ') {
          manufacturer[j] = '\0';
        } else {
          break;
        }
      }

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

      // Get token info if a token is present
      if (slotInfo.flags & CKF_TOKEN_PRESENT) {
        CK_TOKEN_INFO tokenInfo;
        rv = pFunctionList->C_GetTokenInfo(pSlotList[i], &tokenInfo);
        if (rv != CKR_OK) {
          printf("    Error getting token info: 0x%lx\n", rv);
          continue;
        }

        // Convert fixed-length fields to null-terminated strings
        char tokenLabel[33] = {0};
        char tokenManufacturer[33] = {0};
        char tokenModel[17] = {0};
        char tokenSerialNumber[17] = {0};

        memcpy(tokenLabel, tokenInfo.label, sizeof(tokenInfo.label));
        memcpy(tokenManufacturer, tokenInfo.manufacturerID, sizeof(tokenInfo.manufacturerID));
        memcpy(tokenModel, tokenInfo.model, sizeof(tokenInfo.model));
        memcpy(tokenSerialNumber, tokenInfo.serialNumber, sizeof(tokenInfo.serialNumber));

        // Trim trailing spaces
        for (int j = sizeof(tokenInfo.label) - 1; j >= 0; j--) {
          if (tokenLabel[j] == ' ') {
            tokenLabel[j] = '\0';
          } else {
            break;
          }
        }

        for (int j = sizeof(tokenInfo.manufacturerID) - 1; j >= 0; j--) {
          if (tokenManufacturer[j] == ' ') {
            tokenManufacturer[j] = '\0';
          } else {
            break;
          }
        }

        for (int j = sizeof(tokenInfo.model) - 1; j >= 0; j--) {
          if (tokenModel[j] == ' ') {
            tokenModel[j] = '\0';
          } else {
            break;
          }
        }

        for (int j = sizeof(tokenInfo.serialNumber) - 1; j >= 0; j--) {
          if (tokenSerialNumber[j] == ' ') {
            tokenSerialNumber[j] = '\0';
          } else {
            break;
          }
        }

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

        // Try to open a session with this token
        CK_SESSION_HANDLE hSession;
        rv = pFunctionList->C_OpenSession(pSlotList[i], CKF_SERIAL_SESSION, NULL, NULL, &hSession);
        if (rv != CKR_OK) {
          printf("    Error opening session: 0x%lx\n", rv);
          continue;
        }

        printf("    Session opened successfully. Session handle: %lu\n", hSession);

        // Get session info
        CK_SESSION_INFO sessionInfo;
        rv = pFunctionList->C_GetSessionInfo(hSession, &sessionInfo);
        if (rv == CKR_OK) {
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
        } else {
          printf("    Error getting session info: 0x%lx\n", rv);
        }

        // Try to get the mechanism list
        CK_ULONG ulMechCount;
        rv = pFunctionList->C_GetMechanismList(pSlotList[i], NULL, &ulMechCount);
        if (rv == CKR_OK) {
          printf("    Supported mechanisms: %lu\n", ulMechCount);

          if (ulMechCount > 0) {
            CK_MECHANISM_TYPE_PTR pMechanismList =
                (CK_MECHANISM_TYPE_PTR)malloc(ulMechCount * sizeof(CK_MECHANISM_TYPE));
            if (pMechanismList) {
              rv = pFunctionList->C_GetMechanismList(pSlotList[i], pMechanismList, &ulMechCount);
              if (rv == CKR_OK) {
                printf("    Mechanism list:\n");
                for (CK_ULONG j = 0; j < ulMechCount; j++) {
                  printf("      %lu: 0x%lx", j, pMechanismList[j]);

                  // Print known mechanism names
                  switch (pMechanismList[j]) {
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
              } else {
                printf("    Error getting mechanism list: 0x%lx\n", rv);
              }

              free(pMechanismList);
            } else {
              printf("    Memory allocation failed for mechanism list\n");
            }
          }
        } else {
          printf("    Error getting mechanism count: 0x%lx\n", rv);
        }

        CK_SESSION_HANDLE certSession;
        rv = pFunctionList->C_OpenSession(pSlotList[i], CKF_SERIAL_SESSION, NULL, NULL, &certSession);
        if (rv != CKR_OK) {
          printf("    Error opening session for cert tests: 0x%lx\n", rv);
        } else {
          CK_OBJECT_CLASS keyClass = CKO_CERTIFICATE;
          CK_BYTE keyId = 2;
          CK_ATTRIBUTE findTemplate[] = {{CKA_CLASS, &keyClass, sizeof(keyClass)}, {CKA_ID, &keyId, sizeof(keyId)}};
          rv = pFunctionList->C_FindObjectsInit(certSession, findTemplate, 2);
          if (rv != CKR_OK) {
            printf("    Error initializing object search: 0x%lx\n", rv);
          } else {
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
                printf("      Cert value:\n");
                for (int j = 0; j < temp.ulValueLen; j++) {
                  printf("%02x", data[j]);
                  if (j % 32 == 31)
                    printf("\n");
                }
                printf("\n");
              }
            }
          }

          keyClass = CKO_PUBLIC_KEY;
          rv = pFunctionList->C_FindObjectsInit(certSession, findTemplate, 2);
          if (rv != CKR_OK) {
            printf("    Error initializing object search: 0x%lx\n", rv);
          } else {
            CK_OBJECT_HANDLE hKey;
            CK_ULONG ulObjectCount;

            rv = pFunctionList->C_FindObjects(certSession, &hKey, 1, &ulObjectCount);
            if (rv != CKR_OK || ulObjectCount == 0) {
              printf("    No key found: 0x%lx\n", rv);
            } else {
              printf("    Found key (handle: %lu)\n", hKey);

              // Finalize the search
              rv = pFunctionList->C_FindObjectsFinal(certSession);
              if (rv != CKR_OK) {
                printf("    Error finalizing object search: 0x%lx\n", rv);
              }

              CK_BYTE modulus[4096], publicExponent[8];
              CK_ATTRIBUTE templates[] = {{CKA_MODULUS, modulus, sizeof(modulus)}, {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)}};
              rv = pFunctionList->C_GetAttributeValue(certSession, hKey, templates, 2);
              if (rv != CKR_OK) {
                printf("      Error getting modulus value: 0x%lx\n", rv);
              } else {
                printf("      modulus value:\n");
                for (int j = 0; j < templates[0].ulValueLen; j++) {
                  printf("%02x", modulus[j]);
                  if (j % 32 == 31)
                    printf("\n");
                }
                printf("\n");
                printf("      public exponent value:\n");
                for (int j = 0; j < templates[1].ulValueLen; j++) {
                  printf("%02x", publicExponent[j]);
                  if (j % 32 == 31)
                    printf("\n");
                }
                printf("\n");
              }
            }
          }
        }

        // Test RSA signing if RSA mechanisms are available
        int has_rsa_pkcs = 0;
        int has_sha1_rsa_pkcs = 0;
        int has_sha256_rsa_pkcs = 0;

        // Check if the token supports RSA mechanisms
        CK_ULONG mechCount;
        rv = pFunctionList->C_GetMechanismList(pSlotList[i], NULL, &mechCount);
        if (rv == CKR_OK && mechCount > 0) {
          CK_MECHANISM_TYPE_PTR mechList = (CK_MECHANISM_TYPE_PTR)malloc(mechCount * sizeof(CK_MECHANISM_TYPE));
          if (mechList) {
            rv = pFunctionList->C_GetMechanismList(pSlotList[i], mechList, &mechCount);
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

        if (has_rsa_pkcs || has_sha1_rsa_pkcs || has_sha256_rsa_pkcs) {
          printf("    Running RSA signing tests...\n");

          // Open a new session for signing tests
          CK_SESSION_HANDLE signSession;
          rv = pFunctionList->C_OpenSession(pSlotList[i], CKF_SERIAL_SESSION, NULL, NULL, &signSession);
          if (rv != CKR_OK) {
            printf("    Error opening session for signing tests: 0x%lx\n", rv);
          } else {
            printf("    Session for signing tests opened successfully. Session handle: %lu\n", signSession);

            // Login with PIN 123456
            CK_UTF8CHAR pin[] = "123456";
            rv = pFunctionList->C_Login(signSession, CKU_USER, pin, strlen((char *)pin));
            if (rv != CKR_OK) {
              printf("    Error logging in: 0x%lx\n", rv);
            } else {
              printf("    Login successful\n");
            }

            // Find RSA private keys for signing
            CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
            CK_KEY_TYPE keyType = CKK_RSA;
            CK_ATTRIBUTE findTemplate[] = {{CKA_CLASS, &keyClass, sizeof(keyClass)},
                                           {CKA_KEY_TYPE, &keyType, sizeof(keyType)}};

            rv = pFunctionList->C_FindObjectsInit(signSession, findTemplate, 2);
            if (rv != CKR_OK) {
              printf("    Error initializing object search: 0x%lx\n", rv);
            } else {
              CK_OBJECT_HANDLE hKey;
              CK_ULONG ulObjectCount;

              rv = pFunctionList->C_FindObjects(signSession, &hKey, 1, &ulObjectCount);
              if (rv != CKR_OK || ulObjectCount == 0) {
                printf("    No RSA private keys found: 0x%lx\n", rv);
              } else {
                printf("    Found RSA private key (handle: %lu)\n", hKey);

                // Finalize the search
                rv = pFunctionList->C_FindObjectsFinal(signSession);
                if (rv != CKR_OK) {
                  printf("    Error finalizing object search: 0x%lx\n", rv);
                }

                CK_BBOOL sign, decrypt, encrypt;
                CK_ATTRIBUTE tmpl[] = {{CKA_SIGN, &sign, sizeof(sign)}, {CKA_DECRYPT, &decrypt, sizeof(decrypt)}, {CKA_ENCRYPT, &encrypt, sizeof(encrypt)}};

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
                CK_BYTE signature[256]; // Buffer for RSA signature (adjust size as needed)
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

                        // Optionally display first few bytes of signature
                        printf("    Signature (first 16 bytes): ");
                        for (CK_ULONG j = 0; j < (signatureLen > 16 ? 16 : signatureLen); j++) {
                          printf("%02X ", signature[j]);
                        }
                        printf("\n");
                      }
                    }
                  }
                }

                CK_UTF8CHAR pin[] = "123456";

                rv = pFunctionList->C_Logout(signSession);
                if (rv != CKR_OK) {
                  printf("    Error logging out: 0x%lx\n", rv);
                } else {
                  printf("    Logout successful\n");
                }

                // Login with PIN 123456
                rv = pFunctionList->C_Login(signSession, CKU_USER, pin, strlen((char *)pin));
                if (rv != CKR_OK) {
                  printf("    Error logging in: 0x%lx\n", rv);
                } else {
                  printf("    Login successful\n");
                }

                // Test SHA1-RSA signing
                if (has_sha1_rsa_pkcs) {
                  CK_MECHANISM mechanism = {CKM_SHA1_RSA_PKCS, NULL, 0};

                  printf("    Testing CKM_SHA1_RSA_PKCS signing...\n");

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

                      // Optionally display first few bytes of signature
                      printf("    Signature (first 16 bytes): ");
                      for (CK_ULONG j = 0; j < (signatureLen > 16 ? 16 : signatureLen); j++) {
                        printf("%02X ", signature[j]);
                      }
                      printf("\n");
                    }
                  }
                }

                rv = pFunctionList->C_Logout(signSession);
                if (rv != CKR_OK) {
                  printf("    Error logging out: 0x%lx\n", rv);
                } else {
                  printf("    Logout successful\n");
                }

                // Login with PIN 123456
                rv = pFunctionList->C_Login(signSession, CKU_USER, pin, strlen((char *)pin));
                if (rv != CKR_OK) {
                  printf("    Error logging in: 0x%lx\n", rv);
                } else {
                  printf("    Login successful\n");
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

                      // Optionally display first few bytes of signature
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

            // Logout
            rv = pFunctionList->C_Logout(signSession);
            if (rv != CKR_OK) {
              printf("    Error logging out: 0x%lx\n", rv);
            } else {
              printf("    Logout successful\n");
            }

            // Close the signing session
            rv = pFunctionList->C_CloseSession(signSession);
            if (rv != CKR_OK) {
              printf("    Error closing signing session: 0x%lx\n", rv);
            } else {
              printf("    Signing session closed successfully.\n");
            }
          }
        } else {
          printf("    No RSA signing mechanisms available, skipping signing tests.\n");
        }

        // Close the session
        rv = pFunctionList->C_CloseSession(hSession);
        if (rv != CKR_OK) {
          printf("    Error closing session: 0x%lx\n", rv);
        } else {
          printf("    Session closed successfully.\n");
        }
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
