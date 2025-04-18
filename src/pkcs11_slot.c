#include "logging.h"
#include "pcsc_backend.h"
#include "pkcs11.h"
#include "pkcs11_macros.h"
#include "pkcs11_mutex.h"
#include "utils.h"

#include <string.h>

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
  CNK_LOG_FUNC(": tokenPresent: %d, pSlotList: %p, pulCount: %p", tokenPresent, pSlotList, pulCount);

  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pulCount);

  // List readers
  CNK_ENSURE_OK(cnk_list_readers());

  cnk_mutex_lock(&g_cnk_readers_mutex);

  // If pSlotList is NULL, just return the number of slots
  if (!pSlotList) {
    *pulCount = g_cnk_num_readers;
    cnk_mutex_unlock(&g_cnk_readers_mutex);
    CNK_RET_OK;
  }

  // Check if the provided buffer is large enough
  if (*pulCount < (CK_ULONG)g_cnk_num_readers) {
    *pulCount = g_cnk_num_readers;
    cnk_mutex_unlock(&g_cnk_readers_mutex);
    CNK_RETURN(CKR_BUFFER_TOO_SMALL, "pulCount too small");
  }

  // Fill the slot list with the stored slot IDs
  for (CK_LONG i = 0; i < g_cnk_num_readers; i++) {
    pSlotList[i] = g_cnk_readers[i].slot_id;
  }

  *pulCount = g_cnk_num_readers;

  cnk_mutex_unlock(&g_cnk_readers_mutex);

  CNK_DEBUG("C_GetSlotList: %lu slots", g_cnk_num_readers);

  CNK_RET_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
  CNK_LOG_FUNC(": slotID: %lu, pInfo: %p", slotID, pInfo);

  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pInfo);

  // Get firmware version and hardware name
  CK_BYTE fw_major, fw_minor;
  char hw_name[64] = {0}; // Buffer for hardware name
  CNK_ENSURE_OK(cnk_get_version(slotID, &fw_major, &fw_minor, hw_name, sizeof(hw_name)));

  // Fill in the slot info structure
  memset(pInfo, 0, sizeof(CK_SLOT_INFO));

  // Set the slot description to hardware name
  memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
  size_t name_len = strlen(hw_name);
  if (name_len > sizeof(pInfo->slotDescription)) {
    name_len = sizeof(pInfo->slotDescription);
  }
  memcpy(pInfo->slotDescription, hw_name, name_len);

  // Set the manufacturer ID
  memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
  const char *manufacturer = "canokeys.org";
  memcpy(pInfo->manufacturerID, manufacturer,
         strlen(manufacturer) > sizeof(pInfo->manufacturerID) ? sizeof(pInfo->manufacturerID) : strlen(manufacturer));

  // Set flags
  pInfo->flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT | CKF_TOKEN_PRESENT;

  // Always set hardware version to 1.0
  pInfo->hardwareVersion.major = 1;
  pInfo->hardwareVersion.minor = 0;

  // Set firmware version
  pInfo->firmwareVersion.major = fw_major;
  pInfo->firmwareVersion.minor = fw_minor;

  CNK_DEBUG("C_GetSlotInfo: Hardware name: %s, FW version: %d.%d", hw_name, fw_major, fw_minor);

  CNK_RET_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
  CNK_LOG_FUNC(": slotID: %lu", slotID);

  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pInfo);

  cnk_mutex_lock(&g_cnk_readers_mutex);

  // Check if the slot ID is valid
  if (slotID >= (CK_SLOT_ID)g_cnk_num_readers) {
    cnk_mutex_unlock(&g_cnk_readers_mutex);
    CNK_RETURN(CKR_SLOT_ID_INVALID, "invalid slot");
  }

  // Get the serial number
  CK_ULONG serial_number;
  CK_RV ret = cnk_get_serial_number(slotID, &serial_number);
  if (ret != CKR_OK) {
    cnk_mutex_unlock(&g_cnk_readers_mutex);
    CNK_RETURN(ret, "failed to get serial number");
  }

  // Clear the structure
  memset(pInfo, 0, sizeof(CK_TOKEN_INFO));

  // Create the token label with serial number
  char label[32];
  snprintf(label, sizeof(label), "CanoKey PIV #%lu", serial_number);

  // Set the token label (padded with spaces)
  memset(pInfo->label, ' ', sizeof(pInfo->label));
  size_t label_len = strlen(label);
  if (label_len > sizeof(pInfo->label)) {
    label_len = sizeof(pInfo->label);
  }
  memcpy(pInfo->label, label, label_len);

  // Set the manufacturer ID (padded with spaces)
  memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
  const char *manufacturer = "canokeys.org";
  size_t manufacturer_len = strlen(manufacturer);
  if (manufacturer_len > sizeof(pInfo->manufacturerID)) {
    manufacturer_len = sizeof(pInfo->manufacturerID);
  }
  memcpy(pInfo->manufacturerID, manufacturer, manufacturer_len);

  // Set the serial number (padded with spaces)
  memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
  char serial_str[16];
  snprintf(serial_str, sizeof(serial_str), "%lu", serial_number);
  size_t serial_len = strlen(serial_str);
  if (serial_len > sizeof(pInfo->serialNumber)) {
    serial_len = sizeof(pInfo->serialNumber);
  }
  memcpy(pInfo->serialNumber, serial_str, serial_len);

  // Set the flags as requested
  pInfo->flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;

  // Set session counts
  pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
  pInfo->ulSessionCount = 0; // Will be updated if we implement session tracking
  pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
  pInfo->ulRwSessionCount = 0; // Will be updated if we implement session tracking

  // Set PIN constraints
  pInfo->ulMaxPinLen = 8; // PIV PIN is 8 digits max
  pInfo->ulMinPinLen = 6; // PIV PIN is 6 digits min

  // Memory info - not applicable for a smart card, set to effectively infinite
  pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;

  // Get firmware version
  CK_BYTE fw_major, fw_minor;
  CK_RV rv = cnk_get_version(slotID, &fw_major, &fw_minor, (char *)pInfo->model, sizeof(pInfo->model));
  if (rv != CKR_OK) {
    // If we can't get the version, default to 1.0
    CNK_WARN("Failed to get firmware version, defaulting to 1.0");
    fw_major = 1;
    fw_minor = 0;
  }

  // Set hardware and firmware versions
  pInfo->hardwareVersion.major = 1;
  pInfo->hardwareVersion.minor = 0;
  pInfo->firmwareVersion.major = fw_major;
  pInfo->firmwareVersion.minor = fw_minor;

  // UTC time - not supported
  memset(pInfo->utcTime, 0, sizeof(pInfo->utcTime));

  CNK_DEBUG("Serial number: %lu, Label: %s", serial_number, label);

  cnk_mutex_unlock(&g_cnk_readers_mutex);

  CNK_RET_OK;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved) {
  CNK_LOG_FUNC(": flags: %lu, pSlot: %p, pReserved: %p", flags, pSlot, pReserved);
  CNK_RET_UNIMPL;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount) {
  CNK_LOG_FUNC(": slotID: %lu", slotID);

  // Validate common parameters
  PKCS11_VALIDATE(pulCount, slotID);

  // Define the supported mechanisms
  static const CK_MECHANISM_TYPE supported_mechanisms[] = {
      CKM_RSA_PKCS_KEY_PAIR_GEN, // RSA key pair generation
      CKM_RSA_PKCS,              // RSA PKCS #1 v1.5
      CKM_RSA_X_509,             // Raw RSA
      CKM_RSA_PKCS_OAEP,         // RSA OAEP
      CKM_RSA_PKCS_PSS,          // RSA PSS
      CKM_SHA1_RSA_PKCS,         // RSA PKCS #1 v1.5 with SHA-1
      CKM_SHA1_RSA_PKCS_PSS,     // RSA PKCS #1 v1.5 with SHA-1 and PSS
      CKM_SHA256_RSA_PKCS,       // RSA PKCS #1 v1.5 with SHA-256
      CKM_SHA256_RSA_PKCS_PSS,   // RSA PKCS #1 v1.5 with SHA-256 and PSS
      CKM_SHA384_RSA_PKCS,       // RSA PKCS #1 v1.5 with SHA-384
      CKM_SHA384_RSA_PKCS_PSS,   // RSA PKCS #1 v1.5 with SHA-384 and PSS
      CKM_SHA512_RSA_PKCS,       // RSA PKCS #1 v1.5 with SHA-512
      CKM_SHA512_RSA_PKCS_PSS,   // RSA PKCS #1 v1.5 with SHA-512 and PSS
      CKM_SHA224_RSA_PKCS,       // RSA PKCS #1 v1.5 with SHA-224
      CKM_SHA224_RSA_PKCS_PSS,   // RSA PKCS #1 v1.5 with SHA-224 and PSS
      CKM_SHA3_256_RSA_PKCS,     // RSA PKCS #1 v1.5 with SHA3-256
      CKM_SHA3_384_RSA_PKCS,     // RSA PKCS #1 v1.5 with SHA3-384
      CKM_SHA3_512_RSA_PKCS,     // RSA PKCS #1 v1.5 with SHA3-512

      CKM_ECDSA_KEY_PAIR_GEN, // ECDSA key pair generation
      CKM_ECDSA               // ECDSA
  };

  const CK_ULONG num_mechanisms = sizeof(supported_mechanisms) / sizeof(supported_mechanisms[0]);

  // If pMechanismList is NULL, just return the number of mechanisms
  if (pMechanismList == NULL) {
    *pulCount = num_mechanisms;
    CNK_RET_OK;
  }

  // Check if the provided buffer is large enough
  if (*pulCount < num_mechanisms) {
    *pulCount = num_mechanisms;
    CNK_RETURN(CKR_BUFFER_TOO_SMALL, "pulCount too small");
  }

  // Copy the mechanism list to the provided buffer
  memcpy(pMechanismList, supported_mechanisms, sizeof(supported_mechanisms));
  *pulCount = num_mechanisms;

  CNK_DEBUG("Returned %lu mechanisms", num_mechanisms);
  CNK_RET_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
  CNK_LOG_FUNC(": slotID: %lu, type: %lu, pInfo: %p", slotID, type, pInfo);

  // Validate common parameters
  PKCS11_VALIDATE(pInfo, slotID);

  // Clear the mechanism info structure
  memset(pInfo, 0, sizeof(CK_MECHANISM_INFO));

  // Set mechanism info based on type
  switch (type) {
  case CKM_RSA_PKCS_KEY_PAIR_GEN:
    pInfo->flags = CKF_GENERATE_KEY_PAIR;
    pInfo->ulMinKeySize = 2048;
    pInfo->ulMaxKeySize = 4096;
    break;

  case CKM_RSA_X_509:
  case CKM_RSA_PKCS:
    pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY;
    pInfo->ulMinKeySize = 2048;
    pInfo->ulMaxKeySize = 4096;
    break;

  case CKM_RSA_PKCS_OAEP:
    pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
    pInfo->ulMinKeySize = 2048;
    pInfo->ulMaxKeySize = 4096;
    break;

  case CKM_RSA_PKCS_PSS:
  case CKM_SHA1_RSA_PKCS:
  case CKM_SHA1_RSA_PKCS_PSS:
  case CKM_SHA256_RSA_PKCS:
  case CKM_SHA256_RSA_PKCS_PSS:
  case CKM_SHA384_RSA_PKCS:
  case CKM_SHA384_RSA_PKCS_PSS:
  case CKM_SHA512_RSA_PKCS:
  case CKM_SHA512_RSA_PKCS_PSS:
  case CKM_SHA224_RSA_PKCS:
  case CKM_SHA224_RSA_PKCS_PSS:
  case CKM_SHA3_256_RSA_PKCS:
  case CKM_SHA3_384_RSA_PKCS:
  case CKM_SHA3_512_RSA_PKCS:
    pInfo->flags = CKF_SIGN | CKF_VERIFY;
    pInfo->ulMinKeySize = 2048;
    pInfo->ulMaxKeySize = 4096;
    break;

    // TODO: add ECDSA

  default:
    CNK_RETURN(CKR_MECHANISM_INVALID, "invalid mechanism");
  }

  CNK_DEBUG("C_GetMechanismInfo: Mechanism %lu, flags = 0x%lx, min key size = %lu, max key size = %lu", type,
            pInfo->flags, pInfo->ulMinKeySize, pInfo->ulMaxKeySize);
  CNK_RET_OK;
}

CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel) {
  CNK_LOG_FUNC(": slotID: %lu, pPin: %p, ulPinLen: %lu, pLabel: %p", slotID, pPin, ulPinLen, pLabel);
  CNK_RET_UNIMPL;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  CNK_LOG_FUNC(": hSession: %lu, pPin: %p, ulPinLen: %lu", hSession, pPin, ulPinLen);
  CNK_RET_UNIMPL;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin,
               CK_ULONG ulNewLen) {
  CNK_LOG_FUNC(": hSession: %lu, pOldPin: %p, ulOldLen: %lu, pNewPin: %p, ulNewLen: %lu", hSession, pOldPin, ulOldLen,
               pNewPin, ulNewLen);
  CNK_RET_UNIMPL;
}
