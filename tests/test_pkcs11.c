#include "pkcs11.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
  CK_FUNCTION_LIST_PTR pFunctionList = NULL;
  CK_RV rv;
  CK_SLOT_ID_PTR pSlotList = NULL;
  CK_ULONG ulSlotCount = 0;

  // Load the PKCS#11 library dynamically
  // Note: In a real application, you would use dlopen/LoadLibrary to load the library
  // For this test, we'll assume the library is statically linked

  // Get the function list
  rv = C_GetFunctionList(&pFunctionList);
  if (rv != CKR_OK) {
    printf("Error getting function list: 0x%lx\n", rv);
    return 1;
  }

  // Initialize the library
  rv = pFunctionList->C_Initialize(NULL);
  if (rv != CKR_OK) {
    printf("Error initializing library: 0x%lx\n", rv);
    return 1;
  }

  // Get the number of slots
  rv = pFunctionList->C_GetSlotList(CK_FALSE, NULL, &ulSlotCount);
  if (rv != CKR_OK) {
    printf("Error getting slot count: 0x%lx\n", rv);
    pFunctionList->C_Finalize(NULL);
    return 1;
  }

  printf("Number of slots: %lu\n", ulSlotCount);

  if (ulSlotCount > 0) {
    // Allocate memory for the slot list
    pSlotList = (CK_SLOT_ID_PTR)malloc(ulSlotCount * sizeof(CK_SLOT_ID));
    if (!pSlotList) {
      printf("Memory allocation failed\n");
      pFunctionList->C_Finalize(NULL);
      return 1;
    }

    // Get the slot list
    rv = pFunctionList->C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
    if (rv != CKR_OK) {
      printf("Error getting slot list: 0x%lx\n", rv);
      free(pSlotList);
      pFunctionList->C_Finalize(NULL);
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
    }

    // Open a session with the first slot
    if (ulSlotCount > 0) {
      CK_SESSION_HANDLE hSession;
      CK_FLAGS flags = CKF_SERIAL_SESSION; // Read-only session

      printf("\nOpening session with slot %lu...\n", pSlotList[0]);
      rv = pFunctionList->C_OpenSession(pSlotList[0], flags, NULL, NULL, &hSession);
      if (rv != CKR_OK) {
        printf("Error opening session: 0x%lx\n", rv);
      } else {
        printf("Session opened successfully. Session handle: %lu\n", hSession);

        // Test C_Login with PIN "123456"
        CK_UTF8CHAR pin[] = {"123456"};
        CK_ULONG pinLen = strlen((char *)pin);

        printf("Logging in with PIN: %s\n", pin);
        rv = pFunctionList->C_Login(hSession, CKU_USER, pin, pinLen);
        if (rv == CKR_OK) {
          printf("Login successful!\n");

          // Test object finding functions
          printf("\nTesting object finding functions...\n");

          // Test finding all certificates
          CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
          CK_ATTRIBUTE certTemplate[] = {{CKA_CLASS, &certClass, sizeof(certClass)}};

          printf("Finding all certificates...\n");
          rv = pFunctionList->C_FindObjectsInit(hSession, certTemplate, 1);
          if (rv != CKR_OK) {
            printf("Error initializing find operation for certificates: 0x%lx\n", rv);
          } else {
            CK_OBJECT_HANDLE certObjects[10];
            CK_ULONG certCount;

            rv = pFunctionList->C_FindObjects(hSession, certObjects, 10, &certCount);
            if (rv != CKR_OK) {
              printf("Error finding certificate objects: 0x%lx\n", rv);
            } else {
              printf("Found %lu certificate objects:\n", certCount);
              for (CK_ULONG i = 0; i < certCount; i++) {
                printf("  Certificate object handle: %lu\n", certObjects[i]);
                // Extract and display the slot ID and object ID from the handle
                CK_SLOT_ID slotId = (certObjects[i] >> 16) & 0xFFFF;
                CK_BYTE objectId = certObjects[i] & 0xFF;
                printf("    Slot ID: %lu, Object ID: %u\n", slotId, objectId);
              }
            }

            rv = pFunctionList->C_FindObjectsFinal(hSession);
            if (rv != CKR_OK) {
              printf("Error finalizing certificate find operation: 0x%lx\n", rv);
            }
          }

          // Test finding all private keys
          CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
          CK_ATTRIBUTE privKeyTemplate[] = {{CKA_CLASS, &privKeyClass, sizeof(privKeyClass)}};

          printf("\nFinding all private keys...\n");
          rv = pFunctionList->C_FindObjectsInit(hSession, privKeyTemplate, 1);
          if (rv != CKR_OK) {
            printf("Error initializing find operation for private keys: 0x%lx\n", rv);
          } else {
            CK_OBJECT_HANDLE privKeyObjects[10];
            CK_ULONG privKeyCount;

            rv = pFunctionList->C_FindObjects(hSession, privKeyObjects, 10, &privKeyCount);
            if (rv != CKR_OK) {
              printf("Error finding private key objects: 0x%lx\n", rv);
            } else {
              printf("Found %lu private key objects:\n", privKeyCount);
              for (CK_ULONG i = 0; i < privKeyCount; i++) {
                printf("  Private key object handle: %lu\n", privKeyObjects[i]);
                // Extract and display the slot ID and object ID from the handle
                CK_SLOT_ID slotId = (privKeyObjects[i] >> 16) & 0xFFFF;
                CK_BYTE objectId = privKeyObjects[i] & 0xFF;
                printf("    Slot ID: %lu, Object ID: %u\n", slotId, objectId);
              }
            }

            rv = pFunctionList->C_FindObjectsFinal(hSession);
            if (rv != CKR_OK) {
              printf("Error finalizing private key find operation: 0x%lx\n", rv);
            }
          }

          // Test finding a specific object by ID
          CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
          CK_BYTE objectId = 1; // PIV_SLOT_9A
          CK_ATTRIBUTE specificTemplate[] = {{CKA_CLASS, &pubKeyClass, sizeof(pubKeyClass)},
                                             {CKA_ID, &objectId, sizeof(objectId)}};

          printf("\nFinding public key with ID 1 (PIV_SLOT_9A)...\n");
          rv = pFunctionList->C_FindObjectsInit(hSession, specificTemplate, 2);
          if (rv != CKR_OK) {
            printf("Error initializing find operation for specific object: 0x%lx\n", rv);
          } else {
            CK_OBJECT_HANDLE specificObjects[1];
            CK_ULONG specificCount;

            rv = pFunctionList->C_FindObjects(hSession, specificObjects, 1, &specificCount);
            if (rv != CKR_OK) {
              printf("Error finding specific object: 0x%lx\n", rv);
            } else {
              printf("Found %lu specific objects:\n", specificCount);
              for (CK_ULONG i = 0; i < specificCount; i++) {
                printf("  Object handle: %lu\n", specificObjects[i]);
                // Extract and display the slot ID and object ID from the handle
                CK_SLOT_ID slotId = (specificObjects[i] >> 16) & 0xFFFF;
                CK_BYTE objId = specificObjects[i] & 0xFF;
                printf("    Slot ID: %lu, Object ID: %u\n", slotId, objId);
              }
            }

            rv = pFunctionList->C_FindObjectsFinal(hSession);
            if (rv != CKR_OK) {
              printf("Error finalizing specific find operation: 0x%lx\n", rv);
            }
          }

          // Test logout
          rv = pFunctionList->C_Logout(hSession);
          if (rv == CKR_OK) {
            printf("Logout successful!\n");
          } else {
            printf("Error logging out: 0x%lx\n", rv);
          }
        } else {
          printf("Login failed: 0x%lx\n", rv);
          if (rv == CKR_PIN_INCORRECT) {
            printf("PIN is incorrect.\n");
          } else if (rv == CKR_PIN_LOCKED) {
            printf("PIN is locked.\n");
          }
        }

        // Close the session
        rv = pFunctionList->C_CloseSession(hSession);
        if (rv != CKR_OK) {
          printf("Error closing session: 0x%lx\n", rv);
        } else {
          printf("Session closed successfully.\n");
        }
      }
    }

    free(pSlotList);
  } else {
    printf("No slots found. Make sure a CanoKey device is connected.\n");
  }

  // Finalize the library
  rv = pFunctionList->C_Finalize(NULL);
  if (rv != CKR_OK) {
    printf("Error finalizing library: 0x%lx\n", rv);
    return 1;
  }

  return 0;
}
