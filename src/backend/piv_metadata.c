#include "backend/pcsc.h"

#include "internal/logging.h"
#include "internal/macros.h"
#include "internal/util.h"

#include <mbedtls/platform_util.h>
#include <string.h>

#define CNK_PIV_MAX_PUBLIC_KEY_RESPONSE 4096

static CK_RV readPivVersionOnCard(SCARDHANDLE hCard, CK_BYTE version[3]) {
  CK_BYTE apdu[] = {0x00, 0xFD, 0x00, 0x00, 0x00};
  CK_BYTE response[5];
  DWORD responseLen = sizeof(response);
  LONG pcscRv = cnk_transceive_apdu(hCard, apdu, sizeof(apdu), response, &responseLen, CK_FALSE);
  if (pcscRv != SCARD_S_SUCCESS || responseLen < 2)
    return CKR_DEVICE_ERROR;
  if (response[responseLen - 2] != 0x90 || response[responseLen - 1] != 0x00)
    return CKR_FUNCTION_NOT_SUPPORTED;
  if (responseLen != sizeof(response))
    return CKR_DEVICE_ERROR;
  memcpy(version, response, 3);
  return CKR_OK;
}

static CK_RV connectPiv(CK_SLOT_ID slotId, SCARDHANDLE *card) {
  CK_RV rv = cnk_connect_and_select_canokey(slotId, card);
  if (rv != CKR_OK)
    return rv;
  rv = cnk_select_piv_application(*card);
  if (rv != CKR_OK)
    cnk_disconnect_card(*card);
  return rv;
}

CK_RV cnk_get_metadata(CK_SLOT_ID slotID, CK_BYTE pivTag, CK_BYTE_PTR algorithmType, CK_BYTE_PTR publicKey,
                       CK_ULONG_PTR publicKeyLen, CK_BYTE_PTR pinPolicy, CK_BYTE_PTR touchPolicy) {
  CNK_ENSURE_NONNULL(algorithmType);
  if (publicKey != NULL && publicKeyLen == NULL)
    return CKR_ARGUMENTS_BAD;

  SCARDHANDLE card = 0;
  CK_RV rv = connectPiv(slotID, &card);
  if (rv != CKR_OK)
    return rv;

  CK_BYTE apdu[] = {0x00, 0xF7, 0x00, pivTag, 0x00};
  CK_BYTE response[CNK_PIV_MAX_PUBLIC_KEY_RESPONSE];
  DWORD responseLen = sizeof(response);
  LONG pcscRv = cnk_transceive_apdu(card, apdu, sizeof(apdu), response, &responseLen, CK_TRUE);
  if (pcscRv != SCARD_S_SUCCESS || responseLen < 2) {
    rv = CKR_DEVICE_ERROR;
    goto cleanup;
  }
  CK_BYTE sw1 = response[responseLen - 2];
  CK_BYTE sw2 = response[responseLen - 1];
  if (sw1 != 0x90 || sw2 != 0x00) {
    rv = sw1 == 0x6A && (sw2 == 0x82 || sw2 == 0x88) ? CKR_DATA_INVALID : CKR_DEVICE_ERROR;
    goto cleanup;
  }

  CK_ULONG dataLen = responseLen - 2;
  CK_ULONG offset = 0;
  CK_BBOOL sawAlgorithm = CK_FALSE;
  CK_ULONG publicKeyCapacity = publicKeyLen == NULL ? 0 : *publicKeyLen;
  while (offset < dataLen) {
    CK_BYTE tag = response[offset++];
    CK_LONG fail = 0;
    CK_ULONG lengthSize = 0;
    CK_ULONG length = tlvGetLengthSafe(response + offset, dataLen - offset, &fail, &lengthSize);
    if (fail) {
      rv = CKR_DEVICE_ERROR;
      goto cleanup;
    }
    offset += lengthSize;
    const CK_BYTE *value = response + offset;

    switch (tag) {
    case 0x01:
      if (length != 1) {
        rv = CKR_DEVICE_ERROR;
        goto cleanup;
      }
      *algorithmType = value[0];
      sawAlgorithm = CK_TRUE;
      break;
    case 0x02:
      if (length < 2) {
        rv = CKR_DEVICE_ERROR;
        goto cleanup;
      }
      if (pinPolicy != NULL)
        *pinPolicy = value[0];
      if (touchPolicy != NULL)
        *touchPolicy = value[1];
      break;
    case 0x04:
      if (publicKeyLen != NULL)
        *publicKeyLen = length;
      if (publicKey != NULL) {
        if (publicKeyCapacity < length) {
          rv = CKR_BUFFER_TOO_SMALL;
          goto cleanup;
        }
        memcpy(publicKey, value, length);
      }
      break;
    default:
      break;
    }
    offset += length;
  }
  rv = sawAlgorithm ? CKR_OK : CKR_DEVICE_ERROR;

cleanup:
  cnk_disconnect_card(card);
  return rv;
}

CK_RV cnk_get_piv_metadata_directory(CK_SLOT_ID slotID, CNK_PIV_METADATA_DIRECTORY_ENTRY *entries,
                                     CK_ULONG_PTR entryCount) {
  CNK_ENSURE_NONNULL(entryCount);
  if (entries == NULL && *entryCount != 0)
    return CKR_ARGUMENTS_BAD;

  SCARDHANDLE card = 0;
  CK_RV rv = connectPiv(slotID, &card);
  if (rv != CKR_OK)
    return rv;
  CK_BYTE version[3];
  rv = readPivVersionOnCard(card, version);
  if (rv != CKR_OK)
    goto cleanup;
  if (version[0] < 5 || (version[0] == 5 && version[1] < 7)) {
    rv = CKR_FUNCTION_NOT_SUPPORTED;
    goto cleanup;
  }

  CK_BYTE apdu[] = {0x00, 0xF7, 0x01, 0x00, 0x00};
  CK_BYTE response[5 + CNK_PIV_METADATA_DIRECTORY_MAX_ENTRIES * 6 + 2];
  DWORD responseLen = sizeof(response);
  LONG pcscRv = cnk_transceive_apdu(card, apdu, sizeof(apdu), response, &responseLen, CK_TRUE);
  if (pcscRv != SCARD_S_SUCCESS || responseLen < 2) {
    rv = CKR_DEVICE_ERROR;
    goto cleanup;
  }
  CK_BYTE sw1 = response[responseLen - 2];
  CK_BYTE sw2 = response[responseLen - 1];
  if (sw1 != 0x90 || sw2 != 0x00) {
    rv = sw1 == 0x6D || (sw1 == 0x6A && (sw2 == 0x81 || sw2 == 0x86)) ? CKR_FUNCTION_NOT_SUPPORTED : CKR_DEVICE_ERROR;
    goto cleanup;
  }

  CK_ULONG dataLen = responseLen - 2;
  if (dataLen < 5 || response[0] != 0x01 || response[1] != 0x01 || response[2] != 0x01 || response[3] != 0x02 ||
      response[4] != dataLen - 5 || response[4] % 6 != 0) {
    rv = CKR_DEVICE_ERROR;
    goto cleanup;
  }
  CK_ULONG required = response[4] / 6;
  CK_ULONG capacity = *entryCount;
  *entryCount = required;
  if (entries == NULL) {
    rv = CKR_OK;
    goto cleanup;
  }
  if (capacity < required) {
    rv = CKR_BUFFER_TOO_SMALL;
    goto cleanup;
  }
  for (CK_ULONG i = 0; i < required; i++) {
    const CK_BYTE *encoded = response + 5 + i * 6;
    entries[i] =
        (CNK_PIV_METADATA_DIRECTORY_ENTRY){encoded[0], encoded[1], encoded[2], encoded[3], encoded[4], encoded[5]};
  }
  rv = CKR_OK;

cleanup:
  cnk_disconnect_card(card);
  return rv;
}

CK_RV cnk_get_piv_algorithm_extension(CK_SLOT_ID slotID, CNK_PIV_ALGORITHM_EXTENSION_CONFIG *config) {
  CNK_ENSURE_NONNULL(config);
  SCARDHANDLE card = 0;
  CK_RV rv = connectPiv(slotID, &card);
  if (rv != CKR_OK)
    return rv;

  CK_BYTE apdu[] = {0x00, 0xEE, 0x01, 0x00, 0x00};
  CK_BYTE response[sizeof(*config) + 2];
  DWORD responseLen = sizeof(response);
  LONG pcscRv = cnk_transceive_apdu(card, apdu, sizeof(apdu), response, &responseLen, CK_FALSE);
  cnk_disconnect_card(card);
  if (pcscRv != SCARD_S_SUCCESS || responseLen != sizeof(response) || response[responseLen - 2] != 0x90 ||
      response[responseLen - 1] != 0x00)
    return CKR_FUNCTION_NOT_SUPPORTED;
  memcpy(config, response, sizeof(*config));
  return CKR_OK;
}

static CK_RV pivRandomSupportedOnCard(SCARDHANDLE card, CK_BBOOL *supported) {
  CNK_ENSURE_NONNULL(supported);
  CK_BYTE version[3];
  CK_RV rv = readPivVersionOnCard(card, version);
  if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
    *supported = CK_FALSE;
    return CKR_OK;
  }
  if (rv != CKR_OK)
    return rv;
  *supported = version[0] >= 6 ? CK_TRUE : CK_FALSE;
  return CKR_OK;
}

CK_RV cnk_piv_random_supported(CK_SLOT_ID slotID, CK_BBOOL *supported) {
  CNK_ENSURE_NONNULL(supported);
  SCARDHANDLE card = 0;
  CK_RV rv = connectPiv(slotID, &card);
  if (rv != CKR_OK)
    return rv;
  rv = pivRandomSupportedOnCard(card, supported);
  cnk_disconnect_card(card);
  return rv;
}

CK_RV cnk_piv_generate_random(CK_SLOT_ID slotID, CK_BYTE_PTR output, CK_ULONG outputLen) {
  if (output == NULL && outputLen > 0)
    return CKR_ARGUMENTS_BAD;
  SCARDHANDLE card = 0;
  CK_RV rv = connectPiv(slotID, &card);
  if (rv != CKR_OK)
    return rv;

  CK_BBOOL supported = CK_FALSE;
  rv = pivRandomSupportedOnCard(card, &supported);
  if (rv != CKR_OK || !supported) {
    cnk_disconnect_card(card);
    return rv == CKR_OK ? CKR_RANDOM_NO_RNG : rv;
  }

  CK_ULONG offset = 0;
  while (offset < outputLen) {
    CK_ULONG chunkLen = outputLen - offset;
    if (chunkLen > 256)
      chunkLen = 256;
    CK_BYTE apdu[] = {0x00, 0x84, 0x00, 0x00, chunkLen == 256 ? 0 : (CK_BYTE)chunkLen};
    CK_BYTE response[258];
    DWORD responseLen = sizeof(response);
    LONG pcscRv = cnk_transceive_apdu(card, apdu, sizeof(apdu), response, &responseLen, CK_FALSE);
    if (pcscRv != SCARD_S_SUCCESS || responseLen != chunkLen + 2 || response[responseLen - 2] != 0x90 ||
        response[responseLen - 1] != 0x00) {
      rv = CKR_DEVICE_ERROR;
      break;
    }
    memcpy(output + offset, response, chunkLen);
    offset += chunkLen;
  }
  cnk_disconnect_card(card);
  if (rv != CKR_OK && outputLen > 0)
    mbedtls_platform_zeroize(output, outputLen);
  return rv;
}
