#include "backend/pcsc.h"

#include "api/session.h"
#include "internal/logging.h"
#include "internal/macros.h"
#include "internal/util.h"

#include <mbedtls/platform_util.h>
#include <psa/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#define CNK_PIV_MAX_PUBLIC_KEY_RESPONSE 4096
#define CNK_PIV_PUBLIC_CACHE_TTL_MS 60000
#define CNK_PIV_EXTENSION_CACHE_SLOTS 64

typedef struct {
  CK_BBOOL valid;
  CK_SLOT_ID slotId;
  uint64_t refreshedAtMs;
  CNK_PIV_ALGORITHM_EXTENSION_CONFIG config;
} CNK_PIV_EXTENSION_CACHE_ENTRY;

static CNK_PIV_EXTENSION_CACHE_ENTRY g_piv_extension_cache[CNK_PIV_EXTENSION_CACHE_SLOTS];

static uint64_t cnk_public_cache_now_ms(void) {
#if defined(_WIN32)
  return (uint64_t)GetTickCount64();
#else
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
    return 0;
  return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
#endif
}

static CK_BBOOL cnk_public_cache_fresh(uint64_t refreshedAtMs, uint64_t nowMs) {
  return refreshedAtMs != 0 && nowMs >= refreshedAtMs && nowMs - refreshedAtMs < CNK_PIV_PUBLIC_CACHE_TTL_MS;
}

static CK_LONG cnk_public_cache_index(CK_BYTE pivTag) {
  switch (pivTag) {
  case 0x9A:
  case 0x05:
    return 0;
  case 0x9C:
  case 0x0A:
    return 1;
  case 0x9D:
  case 0x0B:
    return 2;
  case 0x9E:
  case 0x01:
    return 3;
  case 0x82:
  case 0x0D:
    return 4;
  case 0x83:
  case 0x0E:
    return 5;
  default:
    if (pivTag >= 0x84 && pivTag <= 0x95)
      return 4 + (CK_LONG)(pivTag - 0x82);
    if (pivTag >= 0x0F && pivTag <= 0x20)
      return 6 + (CK_LONG)(pivTag - 0x0F);
    return -1;
  }
}

static CK_RV cnk_copy_cached_metadata(const CNK_PIV_PUBLIC_CACHE_ENTRY *entry, CK_BYTE_PTR algorithmType,
                                      CK_BYTE_PTR publicKey, CK_ULONG_PTR publicKeyLen, CK_BYTE_PTR pinPolicy,
                                      CK_BYTE_PTR touchPolicy) {
  CNK_ENSURE_NONNULL(entry, algorithmType);
  *algorithmType = entry->algorithmType;
  if (pinPolicy != NULL)
    *pinPolicy = entry->pinPolicy;
  if (touchPolicy != NULL)
    *touchPolicy = entry->touchPolicy;
  if (publicKeyLen == NULL)
    return CKR_OK;

  CK_ULONG capacity = *publicKeyLen;
  *publicKeyLen = entry->publicKeyLen;
  if (publicKey == NULL)
    return CKR_OK;
  if (capacity < entry->publicKeyLen)
    return CKR_BUFFER_TOO_SMALL;
  memcpy(publicKey, entry->publicKey, entry->publicKeyLen);
  return CKR_OK;
}

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

static CK_RV connectPiv(CK_SLOT_ID slotId, SCARDHANDLE *card) { return cnk_begin_piv_transaction(slotId, card); }

static CK_RV readPivPinRetriesOnCard(SCARDHANDLE card, CK_BYTE pinReference, CK_BYTE_PTR pinTries) {
  CNK_ENSURE_NONNULL(pinTries);
  if (pinReference != CNK_PIV_PIN_TYPE_PIN && pinReference != CNK_PIV_PIN_TYPE_PUK)
    return CKR_ARGUMENTS_BAD;

  CK_BYTE apdu[] = {0x00, 0xF7, 0x00, pinReference, 0x00};
  CK_BYTE response[32];
  DWORD responseLen = sizeof(response);
  LONG pcscRv = cnk_transceive_apdu(card, apdu, sizeof(apdu), response, &responseLen, CK_FALSE);
  if (pcscRv != SCARD_S_SUCCESS || responseLen < 2)
    return CKR_DEVICE_ERROR;
  CK_BYTE sw1 = response[responseLen - 2];
  CK_BYTE sw2 = response[responseLen - 1];
  if (sw1 != 0x90 || sw2 != 0x00)
    return sw1 == 0x6D || (sw1 == 0x6A && (sw2 == 0x81 || sw2 == 0x86)) ? CKR_FUNCTION_NOT_SUPPORTED : CKR_DEVICE_ERROR;

  CK_ULONG offset = 0;
  CK_ULONG dataLen = responseLen - 2;
  while (offset < dataLen) {
    CK_BYTE tag = response[offset++];
    CK_LONG fail = 0;
    CK_ULONG lengthSize = 0;
    CK_ULONG length = tlvGetLengthSafe(response + offset, dataLen - offset, &fail, &lengthSize);
    if (fail || lengthSize > dataLen - offset)
      return CKR_DEVICE_ERROR;
    offset += lengthSize;
    if (length > dataLen - offset)
      return CKR_DEVICE_ERROR;
    if (tag == 0x06) {
      if (length != 2)
        return CKR_DEVICE_ERROR;
      *pinTries = response[offset + 1];
      return CKR_OK;
    }
    offset += length;
  }
  return CKR_DEVICE_ERROR;
}

CK_RV cnk_get_piv_pin_retries(CK_SLOT_ID slotID, CK_BYTE pinReference, CK_BYTE_PTR pinTries) {
  CNK_ENSURE_NONNULL(pinTries);
  SCARDHANDLE card = 0;
  CK_RV rv = connectPiv(slotID, &card);
  if (rv != CKR_OK)
    return rv;
  rv = readPivPinRetriesOnCard(card, pinReference, pinTries);
  cnk_disconnect_card(card);
  return rv;
}

CK_RV cnk_block_piv_puk(CK_SLOT_ID slotID) {
  SCARDHANDLE card = 0;
  CK_RV rv = connectPiv(slotID, &card);
  if (rv != CKR_OK)
    return rv;

  CK_BYTE knownPuk[8] = {0};
  CK_BBOOL pukKnown = CK_FALSE;
  CK_BYTE replacementPuk[8];
  CK_BYTE randomPuk[8];
  if (psa_generate_random(randomPuk, sizeof(randomPuk)) != PSA_SUCCESS) {
    rv = CKR_RANDOM_NO_RNG;
    goto cleanup;
  }
  for (CK_ULONG i = 0; i < sizeof(replacementPuk); i++)
    replacementPuk[i] = (CK_BYTE)('0' + randomPuk[i] % 10);
  mbedtls_platform_zeroize(randomPuk, sizeof(randomPuk));
  CK_BYTE pinTries = 0;
  rv = readPivPinRetriesOnCard(card, CNK_PIV_PIN_TYPE_PUK, &pinTries);
  if (rv != CKR_OK || pinTries == 0)
    goto cleanup;

  // Firmware validates and decrements the PUK only through CHANGE REFERENCE
  // DATA. If a guess accidentally succeeds, remember the replacement value
  // and make every subsequent old-PUK field provably different from it.
  for (CK_ULONG attempt = 0; attempt < 32 && pinTries > 0; attempt++) {
    CK_BYTE oldPuk[8];
    if (pukKnown) {
      memcpy(oldPuk, knownPuk, sizeof(oldPuk));
      oldPuk[0] = oldPuk[0] == '9' ? '0' : (CK_BYTE)(oldPuk[0] + 1);
    } else {
      CK_ULONG value = attempt;
      for (CK_LONG i = (CK_LONG)sizeof(oldPuk) - 1; i >= 0; i--) {
        oldPuk[i] = (CK_BYTE)('0' + value % 10);
        value /= 10;
      }
    }
    CK_BYTE apdu[21] = {0x00, 0x24, 0x00, CNK_PIV_PIN_TYPE_PUK, 0x10};
    memcpy(apdu + 5, oldPuk, sizeof(oldPuk));
    memcpy(apdu + 5 + sizeof(oldPuk), replacementPuk, sizeof(replacementPuk));
    CK_BYTE response[16];
    DWORD responseLen = sizeof(response);
    LONG pcscRv = cnk_transceive_apdu(card, apdu, sizeof(apdu), response, &responseLen, CK_FALSE);
    if (pcscRv != SCARD_S_SUCCESS || responseLen < 2) {
      rv = CKR_DEVICE_ERROR;
      goto cleanup;
    }
    CK_BYTE sw1 = response[responseLen - 2];
    CK_BYTE sw2 = response[responseLen - 1];
    if (sw1 == 0x69 && sw2 == 0x83) {
      pinTries = 0;
      break;
    }
    if (sw1 == 0x63 && (sw2 & 0xF0) == 0xC0) {
      pinTries = sw2 & 0x0F;
      continue;
    }
    if (sw1 != 0x90 || sw2 != 0x00) {
      rv = CKR_DEVICE_ERROR;
      goto cleanup;
    }
    memcpy(knownPuk, replacementPuk, sizeof(knownPuk));
    pukKnown = CK_TRUE;
    // A successful change resets retries. Continue immediately with a known
    // wrong old value; the resulting retry status supplies the new count.
    pinTries = 0xFF;
  }

  rv = readPivPinRetriesOnCard(card, CNK_PIV_PIN_TYPE_PUK, &pinTries);
  if (rv == CKR_OK && pinTries != 0)
    rv = CKR_DEVICE_ERROR;

cleanup:
  mbedtls_platform_zeroize(knownPuk, sizeof(knownPuk));
  mbedtls_platform_zeroize(replacementPuk, sizeof(replacementPuk));
  mbedtls_platform_zeroize(randomPuk, sizeof(randomPuk));
  cnk_disconnect_card(card);
  return rv;
}

CK_RV cnk_get_metadata(CK_SLOT_ID slotID, CK_BYTE pivTag, CK_BYTE_PTR algorithmType, CK_BYTE_PTR publicKey,
                       CK_ULONG_PTR publicKeyLen, CK_BYTE_PTR pinPolicy, CK_BYTE_PTR touchPolicy) {
  CNK_DEBUG("Sending metadata command for PIV tag 0x%02X", pivTag);
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
  if (pcscRv != SCARD_S_SUCCESS) {
    CNK_ERROR("Failed to send metadata command: %ld", pcscRv);
    rv = CKR_DEVICE_ERROR;
    goto cleanup;
  }
  if (responseLen < 2) {
    CNK_ERROR("Response too short");
    rv = CKR_DEVICE_ERROR;
    goto cleanup;
  }
  CK_BYTE sw1 = response[responseLen - 2];
  CK_BYTE sw2 = response[responseLen - 1];
  if (sw1 != 0x90 || sw2 != 0x00) {
    CNK_ERROR("GET METADATA returned error status: %02X%02X", sw1, sw2);
    rv = sw1 == 0x6A && (sw2 == 0x82 || sw2 == 0x88) ? CKR_DATA_INVALID : CKR_DEVICE_ERROR;
    goto cleanup;
  }

  CK_ULONG dataLen = responseLen - 2;
  CK_ULONG offset = 0;
  CK_BBOOL sawAlgorithm = CK_FALSE;
  CK_ULONG publicKeyCapacity = publicKeyLen == NULL ? 0 : *publicKeyLen;
  CNK_DEBUG("Complete metadata response length: %lu bytes", dataLen);
  while (offset < dataLen) {
    CK_BYTE tag = response[offset++];
    CK_LONG fail = 0;
    CK_ULONG lengthSize = 0;
    CK_ULONG length = tlvGetLengthSafe(response + offset, dataLen - offset, &fail, &lengthSize);
    if (fail || lengthSize > dataLen - offset) {
      CNK_ERROR("Invalid length encoding in metadata response");
      rv = CKR_DEVICE_ERROR;
      goto cleanup;
    }
    offset += lengthSize;
    if (length > dataLen - offset) {
      CNK_ERROR("Incomplete TLV data in metadata response");
      rv = CKR_DEVICE_ERROR;
      goto cleanup;
    }
    const CK_BYTE *value = response + offset;

    switch (tag) {
    case 0x01:
      if (length != 1) {
        rv = CKR_DEVICE_ERROR;
        goto cleanup;
      }
      *algorithmType = value[0];
      sawAlgorithm = CK_TRUE;
      CNK_DEBUG("Algorithm type: 0x%02X", *algorithmType);
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
      CNK_DEBUG("Pin and touch policies: 0x%02X 0x%02X", value[0], value[1]);
      break;
    case 0x03:
      if (length >= 1)
        CNK_DEBUG("Key origin: 0x%02X", value[0]);
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
        CNK_DEBUG("Public key data present, length: %lu bytes", length);
      }
      break;
    default:
      CNK_DEBUG("Unhandled metadata tag: 0x%02X, length: %lu", tag, length);
      break;
    }
    offset += length;
  }
  rv = sawAlgorithm ? CKR_OK : CKR_DEVICE_ERROR;

cleanup:
  cnk_disconnect_card(card);
  return rv;
}

CK_RV cnk_get_metadata_cached(CNK_PKCS11_SESSION *session, CK_BYTE pivTag, CK_BYTE_PTR algorithmType,
                              CK_BYTE_PTR publicKey, CK_ULONG_PTR publicKeyLen, CK_BYTE_PTR pinPolicy,
                              CK_BYTE_PTR touchPolicy) {
  CNK_ENSURE_NONNULL(session, session->token, algorithmType);
  if (g_cnk_is_managed_mode || !atomic_load(&g_cnk_piv_metadata_cache_enabled)) {
    CNK_DEBUG("hardware metadata read (%s): PIV slot 0x%02X", g_cnk_is_managed_mode ? "managed mode" : "cache disabled",
              pivTag);
    return cnk_get_metadata(session->slotId, pivTag, algorithmType, publicKey, publicKeyLen, pinPolicy, touchPolicy);
  }

  CK_LONG index = cnk_public_cache_index(pivTag);
  if (index < 0)
    return cnk_get_metadata(session->slotId, pivTag, algorithmType, publicKey, publicKeyLen, pinPolicy, touchPolicy);

  uint64_t nowMs = cnk_public_cache_now_ms();
  CNK_PIV_PUBLIC_CACHE_ENTRY *entry = &session->token->pivPublicCache.slots[index];
  CNK_ENSURE_OK(cnk_mutex_lock(&session->token->lock));
  if (entry->metadataValid && cnk_public_cache_fresh(entry->metadataRefreshedAtMs, nowMs)) {
    CK_RV copyRv = cnk_copy_cached_metadata(entry, algorithmType, publicKey, publicKeyLen, pinPolicy, touchPolicy);
    cnk_mutex_unlock(&session->token->lock);
    CNK_DEBUG("cached metadata read: PIV slot 0x%02X", pivTag);
    return copyRv;
  }
  cnk_mutex_unlock(&session->token->lock);

  CK_BYTE cachedPublicKey[CNK_PIV_PUBLIC_CACHE_MAX_PUBLIC_KEY];
  CK_ULONG cachedPublicKeyLen = sizeof(cachedPublicKey);
  CK_BYTE cachedAlgorithmType = 0;
  CK_BYTE cachedPinPolicy = 0;
  CK_BYTE cachedTouchPolicy = 0;
  CNK_DEBUG("hardware metadata read: PIV slot 0x%02X", pivTag);
  CK_RV rv = cnk_get_metadata(session->slotId, pivTag, &cachedAlgorithmType, cachedPublicKey, &cachedPublicKeyLen,
                              &cachedPinPolicy, &cachedTouchPolicy);
  if (rv != CKR_OK)
    return rv;

  if (cachedPublicKeyLen > sizeof(entry->publicKey))
    return CKR_DATA_LEN_RANGE;
  CNK_ENSURE_OK(cnk_mutex_lock(&session->token->lock));
  entry->algorithmType = cachedAlgorithmType;
  entry->pinPolicy = cachedPinPolicy;
  entry->touchPolicy = cachedTouchPolicy;
  entry->publicKeyLen = cachedPublicKeyLen;
  memcpy(entry->publicKey, cachedPublicKey, cachedPublicKeyLen);
  entry->metadataRefreshedAtMs = cnk_public_cache_now_ms();
  entry->metadataValid = CK_TRUE;
  CK_RV copyRv = cnk_copy_cached_metadata(entry, algorithmType, publicKey, publicKeyLen, pinPolicy, touchPolicy);
  cnk_mutex_unlock(&session->token->lock);
  return copyRv;
}

CK_RV cnk_get_piv_metadata_directory(CK_SLOT_ID slotID, CNK_PIV_METADATA_DIRECTORY_ENTRY *entries,
                                     CK_ULONG_PTR entryCount) {
  CNK_ENSURE_NONNULL(entryCount);
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
  CK_ULONG capacity = entries == NULL ? 0 : *entryCount;
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

CK_RV cnk_get_piv_metadata_directory_cached(CNK_PKCS11_SESSION *session, CNK_PIV_METADATA_DIRECTORY_ENTRY *entries,
                                            CK_ULONG_PTR entryCount) {
  CNK_ENSURE_NONNULL(session, session->token, entryCount);
  if (g_cnk_is_managed_mode || !atomic_load(&g_cnk_piv_metadata_cache_enabled)) {
    CNK_DEBUG("hardware metadata-directory read (%s)", g_cnk_is_managed_mode ? "managed mode" : "cache disabled");
    return cnk_get_piv_metadata_directory(session->slotId, entries, entryCount);
  }

  uint64_t nowMs = cnk_public_cache_now_ms();
  CNK_PIV_PUBLIC_CACHE *cache = &session->token->pivPublicCache;
  CNK_ENSURE_OK(cnk_mutex_lock(&session->token->lock));
  if (cache->directoryValid && cnk_public_cache_fresh(cache->directoryRefreshedAtMs, nowMs)) {
    CK_ULONG required = cache->directoryCount;
    CK_ULONG capacity = entries == NULL ? 0 : *entryCount;
    *entryCount = required;
    if (entries != NULL && capacity < required) {
      cnk_mutex_unlock(&session->token->lock);
      return CKR_BUFFER_TOO_SMALL;
    }
    if (entries != NULL)
      for (CK_ULONG i = 0; i < required; i++)
        entries[i] =
            (CNK_PIV_METADATA_DIRECTORY_ENTRY){cache->directory[i][0], cache->directory[i][1], cache->directory[i][2],
                                               cache->directory[i][3], cache->directory[i][4], cache->directory[i][5]};
    cnk_mutex_unlock(&session->token->lock);
    CNK_DEBUG("cached metadata-directory read: %lu entries", required);
    return CKR_OK;
  }
  cnk_mutex_unlock(&session->token->lock);

  CNK_PIV_METADATA_DIRECTORY_ENTRY fetched[CNK_PIV_METADATA_DIRECTORY_MAX_ENTRIES];
  CK_ULONG fetchedCount = CNK_PIV_METADATA_DIRECTORY_MAX_ENTRIES;
  CNK_DEBUG("hardware metadata-directory read");
  CK_RV rv = cnk_get_piv_metadata_directory(session->slotId, fetched, &fetchedCount);
  if (rv != CKR_OK)
    return rv;

  CNK_ENSURE_OK(cnk_mutex_lock(&session->token->lock));
  cache->directoryCount = fetchedCount;
  for (CK_ULONG i = 0; i < fetchedCount; i++)
    memcpy(cache->directory[i], &fetched[i], sizeof(fetched[i]));
  cache->directoryRefreshedAtMs = cnk_public_cache_now_ms();
  cache->directoryValid = CK_TRUE;
  CK_ULONG capacity = entries == NULL ? 0 : *entryCount;
  *entryCount = fetchedCount;
  if (entries != NULL && capacity < fetchedCount) {
    cnk_mutex_unlock(&session->token->lock);
    return CKR_BUFFER_TOO_SMALL;
  }
  if (entries != NULL)
    memcpy(entries, fetched, fetchedCount * sizeof(*entries));
  cnk_mutex_unlock(&session->token->lock);
  return CKR_OK;
}

CK_RV cnk_get_piv_data_cached(CNK_PKCS11_SESSION *session, CK_BYTE pivTag, CK_BYTE_PTR data, CK_ULONG_PTR data_len,
                              CK_BBOOL fetch_data) {
  CNK_ENSURE_NONNULL(session, session->token);
  if (g_cnk_is_managed_mode || !atomic_load(&g_cnk_piv_metadata_cache_enabled)) {
    CNK_DEBUG("hardware certificate read (%s): PIV slot 0x%02X",
              g_cnk_is_managed_mode ? "managed mode" : "cache disabled", pivTag);
    return cnk_get_piv_data(session->slotId, pivTag, data, data_len, fetch_data);
  }

  CK_LONG index = cnk_public_cache_index(pivTag);
  if (index < 0)
    return cnk_get_piv_data(session->slotId, pivTag, data, data_len, fetch_data);
  CNK_PIV_PUBLIC_CACHE_ENTRY *entry = &session->token->pivPublicCache.slots[index];
  uint64_t nowMs = cnk_public_cache_now_ms();
  CNK_ENSURE_OK(cnk_mutex_lock(&session->token->lock));
  if (entry->certificateValid && cnk_public_cache_fresh(entry->certificateRefreshedAtMs, nowMs)) {
    CK_ULONG required = entry->certificateLen;
    if (!fetch_data) {
      cnk_mutex_unlock(&session->token->lock);
      CNK_DEBUG("cached certificate existence read: PIV slot 0x%02X", pivTag);
      return CKR_OK;
    }
    if (data_len == NULL) {
      cnk_mutex_unlock(&session->token->lock);
      return CKR_ARGUMENTS_BAD;
    }
    CK_ULONG capacity = *data_len;
    *data_len = required;
    if (data == NULL || capacity < required) {
      cnk_mutex_unlock(&session->token->lock);
      return data == NULL ? CKR_OK : CKR_BUFFER_TOO_SMALL;
    }
    memcpy(data, entry->certificate, required);
    cnk_mutex_unlock(&session->token->lock);
    CNK_DEBUG("cached certificate read: PIV slot 0x%02X", pivTag);
    return CKR_OK;
  }
  cnk_mutex_unlock(&session->token->lock);

  CK_BYTE fetched[CNK_PIV_PUBLIC_CACHE_MAX_CERTIFICATE];
  CK_ULONG fetchedLen = sizeof(fetched);
  CNK_DEBUG("hardware certificate read: PIV slot 0x%02X", pivTag);
  CK_RV rv = cnk_get_piv_data(session->slotId, pivTag, fetched, &fetchedLen, CK_TRUE);
  if (rv != CKR_OK)
    return rv;
  if (fetchedLen > sizeof(entry->certificate))
    return CKR_DATA_LEN_RANGE;

  CNK_ENSURE_OK(cnk_mutex_lock(&session->token->lock));
  entry->certificateLen = fetchedLen;
  memcpy(entry->certificate, fetched, fetchedLen);
  entry->certificateRefreshedAtMs = cnk_public_cache_now_ms();
  entry->certificateValid = CK_TRUE;
  if (!fetch_data) {
    cnk_mutex_unlock(&session->token->lock);
    return CKR_OK;
  }
  if (data_len == NULL) {
    cnk_mutex_unlock(&session->token->lock);
    return CKR_ARGUMENTS_BAD;
  }
  CK_ULONG capacity = *data_len;
  *data_len = fetchedLen;
  if (data == NULL) {
    cnk_mutex_unlock(&session->token->lock);
    return CKR_OK;
  }
  if (capacity < fetchedLen) {
    cnk_mutex_unlock(&session->token->lock);
    return CKR_BUFFER_TOO_SMALL;
  }
  memcpy(data, fetched, fetchedLen);
  cnk_mutex_unlock(&session->token->lock);
  return CKR_OK;
}

void cnk_piv_public_cache_invalidate(CNK_PKCS11_SESSION *session) {
  if (session == NULL || session->token == NULL)
    return;
  if (cnk_mutex_lock(&session->token->lock) != CKR_OK)
    return;
  memset(&session->token->pivPublicCache, 0, sizeof(session->token->pivPublicCache));
  cnk_mutex_unlock(&session->token->lock);
  CNK_DEBUG("invalidated public PIV snapshot cache");
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

CK_RV cnk_get_piv_algorithm_extension_cached(CK_SLOT_ID slotID, CNK_PIV_ALGORITHM_EXTENSION_CONFIG *config) {
  CNK_ENSURE_NONNULL(config);
  // Managed callers share a host-owned card handle and may observe external
  // key changes between callbacks; never reuse a standalone snapshot there.
  if (atomic_load(&g_cnk_is_managed_mode))
    return cnk_get_piv_algorithm_extension(slotID, config);
  CK_ULONG index = (CK_ULONG)slotID % CNK_PIV_EXTENSION_CACHE_SLOTS;
  uint64_t nowMs = cnk_public_cache_now_ms();
  CNK_ENSURE_OK(cnk_mutex_lock(&g_cnk_readers_mutex));
  CNK_PIV_EXTENSION_CACHE_ENTRY *entry = &g_piv_extension_cache[index];
  if (entry->valid && entry->slotId == slotID && cnk_public_cache_fresh(entry->refreshedAtMs, nowMs)) {
    *config = entry->config;
    cnk_mutex_unlock(&g_cnk_readers_mutex);
    return CKR_OK;
  }
  cnk_mutex_unlock(&g_cnk_readers_mutex);

  CK_RV rv = cnk_get_piv_algorithm_extension(slotID, config);
  if (rv != CKR_OK)
    return rv;
  CNK_ENSURE_OK(cnk_mutex_lock(&g_cnk_readers_mutex));
  entry->slotId = slotID;
  entry->config = *config;
  entry->refreshedAtMs = cnk_public_cache_now_ms();
  entry->valid = CK_TRUE;
  cnk_mutex_unlock(&g_cnk_readers_mutex);
  return CKR_OK;
}

void cnk_piv_algorithm_extension_cache_invalidate(void) {
  if (cnk_mutex_lock(&g_cnk_readers_mutex) != CKR_OK)
    return;
  memset(g_piv_extension_cache, 0, sizeof(g_piv_extension_cache));
  cnk_mutex_unlock(&g_cnk_readers_mutex);
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
