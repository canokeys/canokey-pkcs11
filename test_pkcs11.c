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
