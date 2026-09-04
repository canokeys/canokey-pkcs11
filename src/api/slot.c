#include "api/session.h"
#include "backend/pcsc.h"
#include "internal/logging.h"
#include "internal/macros.h"
#include "internal/mutex.h"
#include "internal/util.h"
#include "pkcs11.h"
#include "pkcs11_canokey.h"

#include <string.h>

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
  CNK_LOG_FUNC(": tokenPresent: %d, pSlotList: %p, pulCount: %p", tokenPresent, pSlotList, pulCount);

  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pulCount);

  // Managed mode is bound to one caller-owned card handle and exposes only
  // the canonical slot 0. Listing the host PC/SC readers here would expose
  // unrelated readers and make C_OpenSession's slot contract inconsistent.
  if (g_cnk_is_managed_mode) {
    if (pSlotList == NULL) {
      *pulCount = 1;
      return CKR_OK;
    }
    if (*pulCount < 1) {
      *pulCount = 1;
      return CKR_BUFFER_TOO_SMALL;
    }
    pSlotList[0] = 0;
    *pulCount = 1;
    return CKR_OK;
  }

  // List readers
  CNK_ENSURE_OK(cnk_list_readers());

  CNK_ENSURE_OK(cnk_mutex_lock(&g_cnk_readers_mutex));
  CK_ULONG readerCount = (CK_ULONG)g_cnk_num_readers;
  CK_SLOT_ID *slotIds = readerCount == 0 ? NULL : ck_malloc(readerCount * sizeof(*slotIds));
  if (readerCount != 0 && slotIds == NULL) {
    cnk_mutex_unlock(&g_cnk_readers_mutex);
    return CKR_HOST_MEMORY;
  }
  for (CK_ULONG i = 0; i < readerCount; i++)
    slotIds[i] = g_cnk_readers[i].slot_id;
  cnk_mutex_unlock(&g_cnk_readers_mutex);

  // PC/SC lists readers even when no card is inserted. Filter only the
  // tokenPresent form, using the backend's synchronized connection helper
  // after releasing the reader lock.
  CK_ULONG presentCount = 0;
  for (CK_ULONG i = 0; i < readerCount; i++) {
    CK_BBOOL present = CK_TRUE;
    if (tokenPresent) {
      SCARDHANDLE hCard = 0;
      CK_RV probeRv = cnk_begin_card_transaction(slotIds[i], &hCard);
      if (probeRv == CKR_OK) {
        present = CK_TRUE;
        cnk_disconnect_card(hCard);
      } else if (probeRv == CKR_DEVICE_ERROR) {
        present = CK_FALSE;
      } else {
        ck_free(slotIds);
        return probeRv;
      }
    }
    if (present) {
      if (pSlotList != NULL && presentCount < *pulCount)
        pSlotList[presentCount] = slotIds[i];
      presentCount++;
    }
  }
  ck_free(slotIds);

  if (pSlotList == NULL) {
    *pulCount = presentCount;
    CNK_RET_OK;
  }
  if (*pulCount < presentCount) {
    *pulCount = presentCount;
    CNK_RETURN(CKR_BUFFER_TOO_SMALL, "pulCount too small");
  }
  *pulCount = presentCount;

  CNK_DEBUG("C_GetSlotList: %lu slots", presentCount);

  CNK_RET_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
  CNK_LOG_FUNC(": slotID: %lu, pInfo: %p", slotID, pInfo);

  PKCS11_VALIDATE(pInfo, slotID);

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

  PKCS11_VALIDATE(pInfo, slotID);

  // Read token-wide counters before the reader lock. C_OpenSession acquires
  // session_mutex first, so taking the locks in the reverse order can deadlock.
  CK_ULONG openSessions = 0;
  CK_ULONG readOnlySessions = 0;
  CNK_ENSURE_OK(cnk_token_get_session_counts(slotID, &openSessions, &readOnlySessions));

  // Get the serial number
  CK_ULONG serial_number;
  CK_RV ret = cnk_get_serial_number(slotID, &serial_number);
  if (ret != CKR_OK)
    CNK_RETURN(ret, "failed to get serial number");

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

  pInfo->flags = CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;
  CK_BBOOL randomSupported = CK_FALSE;
  if (cnk_piv_random_supported(slotID, &randomSupported) == CKR_OK && randomSupported)
    pInfo->flags |= CKF_RNG;

  // Session counts are token-wide, not tied to the caller's session.
  pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
  pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
  pInfo->ulSessionCount = openSessions;
  pInfo->ulRwSessionCount = openSessions >= readOnlySessions ? openSessions - readOnlySessions : 0;

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
  char model[sizeof(pInfo->model) + 1] = {0};
  CK_RV rv = cnk_get_version(slotID, &fw_major, &fw_minor, model, sizeof(model));
  if (rv != CKR_OK) {
    // If we can't get the version, default to 1.0
    CNK_WARN("Failed to get firmware version, defaulting to 1.0");
    fw_major = 1;
    fw_minor = 0;
  }
  memset(pInfo->model, ' ', sizeof(pInfo->model));
  size_t modelLen = strlen(model);
  if (modelLen > sizeof(pInfo->model))
    modelLen = sizeof(pInfo->model);
  memcpy(pInfo->model, model, modelLen);

  // Set hardware and firmware versions
  pInfo->hardwareVersion.major = 1;
  pInfo->hardwareVersion.minor = 0;
  pInfo->firmwareVersion.major = fw_major;
  pInfo->firmwareVersion.minor = fw_minor;

  // UTC time - not supported
  memset(pInfo->utcTime, 0, sizeof(pInfo->utcTime));

  CNK_DEBUG("Serial number: %lu, Label: %s", serial_number, label);

  CNK_RET_OK;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved) {
  CNK_LOG_FUNC(": flags: %lu, pSlot: %p, pReserved: %p", flags, pSlot, pReserved);
  CNK_ENSURE_INITIALIZED();
  CNK_ENSURE_NONNULL(pSlot);
  CNK_ENSURE_NULL(pReserved);
  if ((flags & ~CKF_DONT_BLOCK) != 0)
    return CKR_ARGUMENTS_BAD;
  CK_RV beginRv = cnk_pcsc_operation_begin();
  if (beginRv != CKR_OK)
    return beginRv;
  CK_RV rv = cnk_wait_for_slot_event(flags, pSlot);
  cnk_pcsc_operation_end();
  return rv;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount) {
  CNK_LOG_FUNC(": slotID: %lu", slotID);

  // Validate common parameters
  PKCS11_VALIDATE(pulCount, slotID);

  // Define the supported mechanisms
  static const CK_MECHANISM_TYPE baseMechanisms[] = {
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
      CKM_SHA3_224_RSA_PKCS,
      CKM_SHA3_224_RSA_PKCS_PSS,
      CKM_SHA3_256_RSA_PKCS_PSS,
      CKM_SHA3_384_RSA_PKCS_PSS,
      CKM_SHA3_512_RSA_PKCS_PSS,
      CKM_ECDSA_KEY_PAIR_GEN, // ECDSA key pair generation
      CKM_ECDSA,              // ECDSA
      CKM_ECDSA_SHA1,         // ECDSA with SHA-1
      CKM_ECDSA_SHA224,       // ECDSA with SHA-224
      CKM_ECDSA_SHA256,       // ECDSA with SHA-256
      CKM_ECDSA_SHA384,       // ECDSA with SHA-384
      CKM_ECDSA_SHA512,       // ECDSA with SHA-512
      CKM_ECDSA_SHA3_224,     // ECDSA with SHA3-224
      CKM_ECDSA_SHA3_256,     // ECDSA with SHA3-256
      CKM_ECDSA_SHA3_384,     // ECDSA with SHA3-384
      CKM_ECDSA_SHA3_512,     // ECDSA with SHA3-512
      CKM_ECDH1_DERIVE,       // ECDH key agreement
      CKM_SHA_1,
      CKM_SHA224,
      CKM_SHA256,
      CKM_SHA384,
      CKM_SHA512,
      CKM_SHA3_224,
      CKM_SHA3_256,
      CKM_SHA3_384,
      CKM_SHA3_512,
      CKM_GENERIC_SECRET_KEY_GEN,
      CKM_AES_KEY_GEN,
  };

  CK_MECHANISM_TYPE supportedMechanisms[sizeof(baseMechanisms) / sizeof(baseMechanisms[0]) + 7];
  CK_ULONG numMechanisms = sizeof(baseMechanisms) / sizeof(baseMechanisms[0]);
  memcpy(supportedMechanisms, baseMechanisms, sizeof(baseMechanisms));

  CNK_PIV_ALGORITHM_EXTENSION_CONFIG algorithmConfig = {0};
  CK_BBOOL extensionsSupported =
      cnk_get_piv_algorithm_extension(slotID, &algorithmConfig) == CKR_OK && algorithmConfig.enabled;
  if (extensionsSupported && algorithmConfig.ed25519 != 0) {
    supportedMechanisms[numMechanisms++] = CKM_EC_EDWARDS_KEY_PAIR_GEN;
    supportedMechanisms[numMechanisms++] = CKM_EDDSA;
  }
  if (extensionsSupported && algorithmConfig.x25519 != 0)
    supportedMechanisms[numMechanisms++] = CKM_EC_MONTGOMERY_KEY_PAIR_GEN;
  if (extensionsSupported && algorithmConfig.mldsa65 != 0) {
    supportedMechanisms[numMechanisms++] = CKM_ML_DSA_KEY_PAIR_GEN;
    supportedMechanisms[numMechanisms++] = CKM_ML_DSA;
  }
  if (extensionsSupported && algorithmConfig.mlkem768 != 0) {
    supportedMechanisms[numMechanisms++] = CKM_ML_KEM_KEY_PAIR_GEN;
    supportedMechanisms[numMechanisms++] = CKM_ML_KEM;
  }

  // If pMechanismList is NULL, just return the number of mechanisms
  if (pMechanismList == NULL) {
    *pulCount = numMechanisms;
    CNK_RET_OK;
  }

  // Check if the provided buffer is large enough
  if (*pulCount < numMechanisms) {
    *pulCount = numMechanisms;
    CNK_RETURN(CKR_BUFFER_TOO_SMALL, "pulCount too small");
  }

  // Copy the mechanism list to the provided buffer
  memcpy(pMechanismList, supportedMechanisms, numMechanisms * sizeof(*supportedMechanisms));
  *pulCount = numMechanisms;

  CNK_DEBUG("Returned %lu mechanisms", numMechanisms);
  CNK_RET_OK;
}

static CK_ULONG piv_rsa_max_bits(const CNK_PIV_ALGORITHM_EXTENSION_CONFIG *config, CK_BBOOL enabled) {
  CK_ULONG maxBits = 2048;
  if (enabled) {
    if (config->rsa3072 != 0)
      maxBits = 3072;
    if (config->rsa4096 != 0)
      maxBits = 4096;
  }
  return maxBits;
}

static CK_BBOOL mechanism_uses_algorithm_extension(CK_MECHANISM_TYPE type) {
  switch (type) {
  case CKM_RSA_PKCS_KEY_PAIR_GEN:
  case CKM_RSA_X_509:
  case CKM_RSA_PKCS:
  case CKM_RSA_PKCS_OAEP:
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
  case CKM_SHA3_224_RSA_PKCS:
  case CKM_SHA3_224_RSA_PKCS_PSS:
  case CKM_SHA3_256_RSA_PKCS_PSS:
  case CKM_SHA3_384_RSA_PKCS_PSS:
  case CKM_SHA3_512_RSA_PKCS_PSS:
  case CKM_ECDSA_KEY_PAIR_GEN:
  case CKM_ECDSA:
  case CKM_ECDSA_SHA1:
  case CKM_ECDSA_SHA224:
  case CKM_ECDSA_SHA256:
  case CKM_ECDSA_SHA384:
  case CKM_ECDSA_SHA512:
  case CKM_ECDSA_SHA3_224:
  case CKM_ECDSA_SHA3_256:
  case CKM_ECDSA_SHA3_384:
  case CKM_ECDSA_SHA3_512:
  case CKM_ECDH1_DERIVE:
  case CKM_EC_EDWARDS_KEY_PAIR_GEN:
  case CKM_EDDSA:
  case CKM_EC_MONTGOMERY_KEY_PAIR_GEN:
  case CKM_ML_DSA_KEY_PAIR_GEN:
  case CKM_ML_DSA:
  case CKM_ML_KEM_KEY_PAIR_GEN:
  case CKM_ML_KEM:
    return CK_TRUE;
  default:
    return CK_FALSE;
  }
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
  CNK_LOG_FUNC(": slotID: %lu, type: %lu, pInfo: %p", slotID, type, pInfo);

  // Validate common parameters
  PKCS11_VALIDATE(pInfo, slotID);

  // Clear the mechanism info structure
  memset(pInfo, 0, sizeof(CK_MECHANISM_INFO));

  CNK_PIV_ALGORITHM_EXTENSION_CONFIG config = {0};
  CK_BBOOL extensionEnabled = CK_FALSE;
  if (mechanism_uses_algorithm_extension(type))
    extensionEnabled = cnk_get_piv_algorithm_extension(slotID, &config) == CKR_OK && config.enabled;

  if (type == CKM_ML_DSA_KEY_PAIR_GEN || type == CKM_ML_DSA || type == CKM_ML_KEM_KEY_PAIR_GEN || type == CKM_ML_KEM) {
    if (!extensionEnabled ||
        ((type == CKM_ML_DSA_KEY_PAIR_GEN || type == CKM_ML_DSA) ? config.mldsa65 == 0 : config.mlkem768 == 0))
      return CKR_MECHANISM_INVALID;
  }
  if (type == CKM_EC_EDWARDS_KEY_PAIR_GEN || type == CKM_EDDSA || type == CKM_EC_MONTGOMERY_KEY_PAIR_GEN) {
    if (!extensionEnabled)
      return CKR_MECHANISM_INVALID;
    if ((type == CKM_EC_EDWARDS_KEY_PAIR_GEN || type == CKM_EDDSA) && config.ed25519 == 0)
      return CKR_MECHANISM_INVALID;
    if (type == CKM_EC_MONTGOMERY_KEY_PAIR_GEN && config.x25519 == 0)
      return CKR_MECHANISM_INVALID;
  }

  // Set mechanism info based on type
  switch (type) {
  case CKM_RSA_PKCS_KEY_PAIR_GEN:
    pInfo->flags = CKF_HW | CKF_GENERATE_KEY_PAIR;
    pInfo->ulMinKeySize = 2048;
    pInfo->ulMaxKeySize = piv_rsa_max_bits(&config, extensionEnabled);
    break;

  case CKM_RSA_X_509:
  case CKM_RSA_PKCS:
    // Sign/decrypt use the card, while verify/encrypt use the host. CKF_HW
    // would incorrectly claim every advertised operation is hardware-backed.
    pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY;
    pInfo->ulMinKeySize = 2048;
    pInfo->ulMaxKeySize = piv_rsa_max_bits(&config, extensionEnabled);
    break;

  case CKM_RSA_PKCS_OAEP:
    pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
    pInfo->ulMinKeySize = 2048;
    pInfo->ulMaxKeySize = piv_rsa_max_bits(&config, extensionEnabled);
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
  case CKM_SHA3_224_RSA_PKCS:
  case CKM_SHA3_224_RSA_PKCS_PSS:
  case CKM_SHA3_256_RSA_PKCS_PSS:
  case CKM_SHA3_384_RSA_PKCS_PSS:
  case CKM_SHA3_512_RSA_PKCS_PSS:
    pInfo->flags = CKF_SIGN | CKF_VERIFY;
    pInfo->ulMinKeySize = 2048;
    pInfo->ulMaxKeySize = piv_rsa_max_bits(&config, extensionEnabled);
    break;

  case CKM_ECDSA_KEY_PAIR_GEN:
    pInfo->flags = CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_NAMEDCURVE;
    pInfo->ulMinKeySize = 256;
    pInfo->ulMaxKeySize = 384;
    if (extensionEnabled && config.secp521r1 != 0)
      pInfo->ulMaxKeySize = 521;
    break;

  case CKM_EC_EDWARDS_KEY_PAIR_GEN:
    pInfo->flags = CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_NAMEDCURVE;
    pInfo->ulMinKeySize = 255;
    pInfo->ulMaxKeySize = 255;
    break;

  case CKM_EDDSA:
    // Signing is card-side. Host verification is not advertised until the
    // bundled crypto provider has a compatible pure-Ed25519 primitive.
    pInfo->flags = CKF_HW | CKF_SIGN | CKF_EC_NAMEDCURVE;
    pInfo->ulMinKeySize = 255;
    pInfo->ulMaxKeySize = 255;
    break;

  case CKM_EC_MONTGOMERY_KEY_PAIR_GEN:
    pInfo->flags = CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_NAMEDCURVE;
    pInfo->ulMinKeySize = 255;
    pInfo->ulMaxKeySize = 255;
    break;

  case CKM_ECDSA:
  case CKM_ECDSA_SHA1:
  case CKM_ECDSA_SHA224:
  case CKM_ECDSA_SHA256:
  case CKM_ECDSA_SHA384:
  case CKM_ECDSA_SHA512:
  case CKM_ECDSA_SHA3_224:
  case CKM_ECDSA_SHA3_256:
  case CKM_ECDSA_SHA3_384:
  case CKM_ECDSA_SHA3_512:
    pInfo->flags = CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE;
    pInfo->ulMinKeySize = 256;
    pInfo->ulMaxKeySize = 384;
    if (extensionEnabled && config.secp521r1 != 0)
      pInfo->ulMaxKeySize = 521;
    break;

  case CKM_ECDH1_DERIVE:
    pInfo->flags = CKF_HW | CKF_DERIVE | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS;
    pInfo->ulMinKeySize = extensionEnabled && config.x25519 != 0 ? 255 : 256;
    pInfo->ulMaxKeySize = 384;
    if (extensionEnabled && config.secp521r1 != 0)
      pInfo->ulMaxKeySize = 521;
    break;

  case CKM_GENERIC_SECRET_KEY_GEN:
    pInfo->flags = CKF_GENERATE;
    pInfo->ulMinKeySize = 8;
    pInfo->ulMaxKeySize = 1024;
    break;

  case CKM_AES_KEY_GEN:
    pInfo->flags = CKF_GENERATE;
    pInfo->ulMinKeySize = 128;
    pInfo->ulMaxKeySize = 256;
    break;

  case CKM_ML_DSA_KEY_PAIR_GEN:
    pInfo->flags = CKF_HW | CKF_GENERATE_KEY_PAIR;
    pInfo->ulMinKeySize = 1952;
    pInfo->ulMaxKeySize = 1952;
    break;

  case CKM_ML_DSA:
    pInfo->flags = CKF_SIGN | CKF_VERIFY;
    pInfo->ulMinKeySize = 1952;
    pInfo->ulMaxKeySize = 1952;
    break;

  case CKM_ML_KEM_KEY_PAIR_GEN:
    pInfo->flags = CKF_HW | CKF_GENERATE_KEY_PAIR;
    pInfo->ulMinKeySize = 1184;
    pInfo->ulMaxKeySize = 1184;
    break;

  case CKM_ML_KEM:
    pInfo->flags = CKF_ENCAPSULATE | CKF_DECAPSULATE;
    pInfo->ulMinKeySize = 1184;
    pInfo->ulMaxKeySize = 1184;
    break;

  case CKM_SHA_1:
  case CKM_SHA224:
  case CKM_SHA256:
  case CKM_SHA384:
  case CKM_SHA512:
  case CKM_SHA3_224:
  case CKM_SHA3_256:
  case CKM_SHA3_384:
  case CKM_SHA3_512:
    pInfo->flags = CKF_DIGEST;
    break;

  default:
    CNK_RETURN(CKR_MECHANISM_INVALID, "invalid mechanism");
  }

  CNK_DEBUG("C_GetMechanismInfo: Mechanism %lu, flags = 0x%lx, min key size = %lu, max key size = %lu", type,
            pInfo->flags, pInfo->ulMinKeySize, pInfo->ulMaxKeySize);
  CNK_RET_OK;
}

CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel) {
  CNK_LOG_FUNC(": slotID: %lu, pPin: %p, ulPinLen: %lu, pLabel: %p", slotID, pPin, ulPinLen, pLabel);
  CNK_ENSURE_INITIALIZED();
  CNK_RET_NOT_IMPLEMENTED;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  CNK_LOG_FUNC(": hSession: %lu, pPin: %p, ulPinLen: %lu", hSession, pPin, ulPinLen);
  CNK_ENSURE_INITIALIZED();
  CNK_RET_NOT_IMPLEMENTED;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin,
               CK_ULONG ulNewLen) {
  CNK_LOG_FUNC(": hSession: %lu, pOldPin: %p, ulOldLen: %lu, pNewPin: %p, ulNewLen: %lu", hSession, pOldPin, ulOldLen,
               pNewPin, ulNewLen);
  return C_CNK_SetPIN(hSession, CNK_PIV_PIN_TYPE_PIN, pOldPin, ulOldLen, pNewPin, ulNewLen, NULL);
}
