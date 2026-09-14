#include "backend/libcanokey.h"
#include "backend/pcsc.h"
#include "backend/piv_operation.h"

#include "api/session.h"
#include "internal/logging.h"
#include "internal/macros.h"
#include "internal/util.h"

#include <mbedtls/platform_util.h>
#include <psa/crypto.h>
#include <stdlib.h>
#include <string.h>

CK_RV cnk_ensure_libcanokey_profile(CNK_PKCS11_SESSION *session) {
  CNK_ENSURE_NONNULL(session, session->token);
  for (unsigned attempt = 0; attempt < 3; attempt++) {
    CK_ULONG epoch = atomic_load(&g_cnk_managed_binding_epoch);
    CNK_ENSURE_OK(cnk_mutex_lock(&session->token->lock));
    if (session->token->libcanokeyProfile != NULL && session->token->libcanokeyProfileEpoch == epoch) {
      cnk_mutex_unlock(&session->token->lock);
      return CKR_OK;
    }
    CNK_LIBCANO_PROFILE *old = session->token->libcanokeyProfile;
    session->token->libcanokeyProfile = NULL;
    session->token->libcanokeyProfileEpoch = 0;
    cnk_mutex_unlock(&session->token->lock);
    if (old != NULL)
      CNK_EXTERNAL_VOID(cnk_profile_free, old);

    void *candidate = NULL;
    CK_RV rv = cnk_probe_libcanokey_profile(session->slotId, &candidate);
    if (rv != CKR_OK)
      return rv;
    rv = cnk_mutex_lock(&session->token->lock);
    if (rv != CKR_OK) {
      CNK_EXTERNAL_VOID(cnk_profile_free, candidate);
      return rv;
    }
    CK_ULONG currentEpoch = atomic_load(&g_cnk_managed_binding_epoch);
    if (currentEpoch != epoch) {
      cnk_mutex_unlock(&session->token->lock);
      CNK_EXTERNAL_VOID(cnk_profile_free, candidate);
      continue;
    }
    if (session->token->libcanokeyProfile == NULL) {
      session->token->libcanokeyProfile = candidate;
      session->token->libcanokeyProfileEpoch = epoch;
      candidate = NULL;
    }
    cnk_mutex_unlock(&session->token->lock);
    if (candidate != NULL)
      CNK_EXTERNAL_VOID(cnk_profile_free, candidate);
    return CKR_OK;
  }
  return CKR_OPERATION_ACTIVE;
}

static CK_RV cnk_get_metadata_libcanokey(CNK_PKCS11_SESSION *session, CK_BYTE pivTag, CK_BYTE_PTR algorithmType,
                                         CNK_PIV_PUBLIC_KEY *publicKey, CK_BYTE_PTR pinPolicy,
                                         CK_BYTE_PTR touchPolicy) {
  CNK_ENSURE_NONNULL(session, session->token, algorithmType);
  CNK_ENSURE_OK(cnk_ensure_libcanokey_profile(session));
  SCARDHANDLE card = 0;
  CNK_ENSURE_OK(cnk_begin_piv_transaction(session->slotId, &card));
  CNK_LIBCANO_CONTEXT *context = NULL;
  CNK_LIBCANO_OPERATION *operation = NULL;
  CNK_LIBCANO_ERROR error = {.struct_size = sizeof(error)};
  CK_RV rv = cnk_piv_context_for_session(session, CNK_LIBCANO_CONTEXT_SELECTED, &context);
  if (rv != CKR_OK)
    goto cleanup;
  uint32_t status = CNK_EXTERNAL_CALL(cnk_piv_get_metadata_in_context_new, context, pivTag, NULL, &operation, &error);
  rv = cnk_piv_operation_status(status, &error, CKR_DATA_INVALID);
  if (rv != CKR_OK)
    goto cleanup;
  rv = cnk_run_piv_operation(card, operation, CKR_DATA_INVALID, NULL);
  if (rv != CKR_OK)
    goto cleanup;
  rv = CKR_DEVICE_ERROR;
  CNK_LIBCANO_METADATA metadata = {.struct_size = sizeof(metadata)};
  if (CNK_EXTERNAL_CALL(cnk_operation_metadata, operation, &metadata) != CNK_LIBCANO_OK ||
      (metadata.presence_flags & CNK_LIBCANO_METADATA_HAS_ALGORITHM) == 0)
    goto cleanup;
  rv = publicKey != NULL ? cnk_copy_piv_public_key(operation, publicKey) : CKR_OK;
  if (rv == CKR_OK) {
    *algorithmType = metadata.algorithm_id;
    if (pinPolicy != NULL && (metadata.presence_flags & CNK_LIBCANO_METADATA_HAS_POLICY) != 0)
      *pinPolicy = metadata.pin_policy;
    if (touchPolicy != NULL && (metadata.presence_flags & CNK_LIBCANO_METADATA_HAS_POLICY) != 0)
      *touchPolicy = metadata.touch_policy;
  }
cleanup:
  if (operation)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  if (context)
    CNK_EXTERNAL_VOID(cnk_piv_context_free, context);
  cnk_disconnect_card(card);
  return rv;
}

static CK_RV cnk_get_certificate_libcanokey(CNK_PKCS11_SESSION *session, CK_BYTE pivTag, CK_BYTE_PTR data,
                                            CK_ULONG_PTR dataLen, CK_BBOOL fetchData) {
  CNK_ENSURE_NONNULL(session, session->token);
  CNK_ENSURE_OK(cnk_ensure_libcanokey_profile(session));
  CK_BYTE slot = pivTag == 0x05 ? 0x9a : pivTag == 0x0a ? 0x9c : pivTag == 0x0b ? 0x9d : pivTag == 0x01 ? 0x9e : 0;
  if (slot == 0 && pivTag >= 0x0d && pivTag <= 0x20)
    slot = (CK_BYTE)(0x82 + pivTag - 0x0d);
  if (slot == 0)
    return CKR_ARGUMENTS_BAD;
  if (!fetchData)
    dataLen = NULL;
  else if (dataLen == NULL)
    return CKR_ARGUMENTS_BAD;
  SCARDHANDLE card = 0;
  CNK_ENSURE_OK(cnk_begin_piv_transaction(session->slotId, &card));
  CNK_LIBCANO_CONTEXT *context = NULL;
  CNK_LIBCANO_OPERATION *operation = NULL;
  CNK_LIBCANO_ERROR error = {.struct_size = sizeof(error)};
  CK_RV rv = cnk_piv_context_for_session(session, CNK_LIBCANO_CONTEXT_SELECTED, &context);
  if (rv != CKR_OK)
    goto cleanup;
  uint32_t status = CNK_EXTERNAL_CALL(cnk_piv_read_certificate_in_context_new, context, slot, NULL, &operation, &error);
  rv = cnk_piv_operation_status(status, &error, CKR_DATA_INVALID);
  if (rv != CKR_OK)
    goto cleanup;
  rv = cnk_run_piv_operation(card, operation, CKR_DATA_INVALID, NULL);
  if (rv != CKR_OK)
    goto cleanup;
  rv = CKR_DEVICE_ERROR;
  size_t required = 0;
  if (CNK_EXTERNAL_CALL(cnk_operation_result_copy_bytes, operation, NULL, &required) != CNK_LIBCANO_OK ||
      required > CNK_PIV_PUBLIC_CACHE_MAX_CERTIFICATE)
    goto cleanup;
  if (!fetchData) {
    rv = CKR_OK;
    goto cleanup;
  }
  CK_ULONG capacity = *dataLen;
  *dataLen = (CK_ULONG)required;
  if (data == NULL) {
    rv = CKR_OK;
    goto cleanup;
  }
  if (capacity < required) {
    rv = CKR_BUFFER_TOO_SMALL;
    goto cleanup;
  }
  if (CNK_EXTERNAL_CALL(cnk_operation_result_copy_bytes, operation, data, &required) != CNK_LIBCANO_OK)
    goto cleanup;
  rv = CKR_OK;
cleanup:
  if (operation)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  if (context)
    CNK_EXTERNAL_VOID(cnk_piv_context_free, context);
  cnk_disconnect_card(card);
  return rv;
}
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#define CNK_PIV_PUBLIC_CACHE_TTL_MS 60000
#define CNK_PIV_EXTENSION_CACHE_SLOTS 64

typedef struct {
  CK_BBOOL valid;
  CK_SLOT_ID slotId;
  uint64_t refreshedAtMs;
  CK_ULONG bindingEpoch;
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
                                      CNK_PIV_PUBLIC_KEY *publicKey, CK_BYTE_PTR pinPolicy, CK_BYTE_PTR touchPolicy) {
  CNK_ENSURE_NONNULL(entry, algorithmType);
  *algorithmType = entry->algorithmType;
  if (pinPolicy != NULL)
    *pinPolicy = entry->pinPolicy;
  if (touchPolicy != NULL)
    *touchPolicy = entry->touchPolicy;
  if (publicKey != NULL)
    *publicKey = entry->publicKey;
  return CKR_OK;
}

static CK_RV readPivVersionOnCard(SCARDHANDLE card, CK_BYTE version[3]) {
  CNK_LIBCANO_OPERATION *operation = NULL;
  CNK_LIBCANO_ERROR error = {.struct_size = sizeof(error)};
  uint32_t status = CNK_EXTERNAL_CALL(cnk_piv_read_version_selected_new, NULL, &operation, &error);
  CK_RV rv = cnk_piv_operation_status(status, &error, CKR_DEVICE_ERROR);
  if (rv == CKR_OK)
    rv = cnk_run_piv_operation(card, operation, CKR_DEVICE_ERROR, NULL);
  if (rv == CKR_OK) {
    size_t length = 3;
    status = CNK_EXTERNAL_CALL(cnk_operation_result_copy_bytes, operation, version, &length);
    rv = status == CNK_LIBCANO_OK && length == 3 ? CKR_OK : CKR_DEVICE_ERROR;
  }
  if (operation)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  return rv;
}

static CK_RV connectPiv(CK_SLOT_ID slotId, SCARDHANDLE *card) { return cnk_begin_piv_transaction(slotId, card); }

static CK_RV readPivPinRetriesOnCard(CNK_PKCS11_SESSION *session, SCARDHANDLE card, CK_BYTE pinReference,
                                     CK_BYTE_PTR pinTries) {
  CNK_ENSURE_NONNULL(pinTries);
  if (pinReference != CNK_PIV_PIN_TYPE_PIN && pinReference != CNK_PIV_PIN_TYPE_PUK)
    return CKR_ARGUMENTS_BAD;
  CNK_LIBCANO_METADATA metadata = {.struct_size = sizeof(metadata)};
  CK_RV rv = cnk_piv_read_metadata_fields(session, card, pinReference, &metadata, CKR_DEVICE_ERROR);
  if (rv != CKR_OK)
    return rv;
  if (!(metadata.presence_flags & CNK_LIBCANO_METADATA_HAS_RETRIES))
    return CKR_DEVICE_ERROR;
  *pinTries = metadata.retries_remaining;
  return CKR_OK;
}

CK_RV cnk_get_piv_pin_retries(CNK_PKCS11_SESSION *session, CK_BYTE pinReference, CK_BYTE_PTR pinTries) {
  CNK_ENSURE_NONNULL(session, pinTries);
  CNK_ENSURE_OK(cnk_ensure_libcanokey_profile(session));
  SCARDHANDLE card = 0;
  CK_RV rv = connectPiv(session->slotId, &card);
  if (rv != CKR_OK)
    return rv;
  rv = readPivPinRetriesOnCard(session, card, pinReference, pinTries);
  cnk_disconnect_card(card);
  return rv;
}

CK_RV cnk_block_piv_puk(CNK_PKCS11_SESSION *session) {
  CNK_ENSURE_NONNULL(session);
  CNK_ENSURE_OK(cnk_ensure_libcanokey_profile(session));
  SCARDHANDLE card = 0;
  CK_RV rv = connectPiv(session->slotId, &card);
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
  rv = readPivPinRetriesOnCard(session, card, CNK_PIV_PIN_TYPE_PUK, &pinTries);
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
    rv = cnk_piv_credential_on_card(session, card, CNK_LIBCANO_CREDENTIAL_CHANGE_PUK, oldPuk, sizeof(oldPuk),
                                    replacementPuk, sizeof(replacementPuk), &pinTries);
    mbedtls_platform_zeroize(oldPuk, sizeof(oldPuk));
    if (rv == CKR_PIN_LOCKED) {
      pinTries = 0;
      break;
    }
    if (rv == CKR_PIN_INCORRECT)
      continue;
    if (rv != CKR_OK)
      goto cleanup;
    memcpy(knownPuk, replacementPuk, sizeof(knownPuk));
    pukKnown = CK_TRUE;
    // A successful change resets retries. Continue immediately with a known
    // wrong old value; the resulting retry status supplies the new count.
    pinTries = 0xFF;
  }

  rv = readPivPinRetriesOnCard(session, card, CNK_PIV_PIN_TYPE_PUK, &pinTries);
  if (rv == CKR_OK && pinTries != 0)
    rv = CKR_DEVICE_ERROR;

cleanup:
  mbedtls_platform_zeroize(knownPuk, sizeof(knownPuk));
  mbedtls_platform_zeroize(replacementPuk, sizeof(replacementPuk));
  mbedtls_platform_zeroize(randomPuk, sizeof(randomPuk));
  cnk_disconnect_card(card);
  return rv;
}

CK_RV cnk_get_metadata_cached(CNK_PKCS11_SESSION *session, CK_BYTE pivTag, CK_BYTE_PTR algorithmType,
                              CNK_PIV_PUBLIC_KEY *publicKey, CK_BYTE_PTR pinPolicy, CK_BYTE_PTR touchPolicy) {
  CNK_ENSURE_NONNULL(session, session->token, algorithmType);
  /* Build the immutable libcanokey profile once per card binding. */
  CNK_ENSURE_OK(cnk_ensure_libcanokey_profile(session));
  if (g_cnk_is_managed_mode || !atomic_load(&g_cnk_piv_metadata_cache_enabled)) {
    CNK_DEBUG("hardware metadata read (%s): PIV slot 0x%02X", g_cnk_is_managed_mode ? "managed mode" : "cache disabled",
              pivTag);
    return cnk_get_metadata_libcanokey(session, pivTag, algorithmType, publicKey, pinPolicy, touchPolicy);
  }

  CK_LONG index = cnk_public_cache_index(pivTag);
  if (index < 0)
    return cnk_get_metadata_libcanokey(session, pivTag, algorithmType, publicKey, pinPolicy, touchPolicy);

  uint64_t nowMs = cnk_public_cache_now_ms();
  CNK_PIV_PUBLIC_CACHE_ENTRY *entry = &session->token->pivPublicCache.slots[index];
  CNK_ENSURE_OK(cnk_mutex_lock(&session->token->lock));
  if (entry->metadataValid && cnk_public_cache_fresh(entry->metadataRefreshedAtMs, nowMs)) {
    CK_RV copyRv = cnk_copy_cached_metadata(entry, algorithmType, publicKey, pinPolicy, touchPolicy);
    cnk_mutex_unlock(&session->token->lock);
    CNK_DEBUG("cached metadata read: PIV slot 0x%02X", pivTag);
    return copyRv;
  }
  cnk_mutex_unlock(&session->token->lock);

  CNK_PIV_PUBLIC_KEY cachedPublicKey;
  CK_BYTE cachedAlgorithmType = 0;
  CK_BYTE cachedPinPolicy = 0;
  CK_BYTE cachedTouchPolicy = 0;
  CNK_DEBUG("hardware metadata read: PIV slot 0x%02X", pivTag);
  CK_RV rv = cnk_get_metadata_libcanokey(session, pivTag, &cachedAlgorithmType, &cachedPublicKey, &cachedPinPolicy,
                                         &cachedTouchPolicy);
  if (rv != CKR_OK)
    return rv;

  CNK_ENSURE_OK(cnk_mutex_lock(&session->token->lock));
  entry->algorithmType = cachedAlgorithmType;
  entry->pinPolicy = cachedPinPolicy;
  entry->touchPolicy = cachedTouchPolicy;
  entry->publicKey = cachedPublicKey;
  entry->metadataRefreshedAtMs = cnk_public_cache_now_ms();
  entry->metadataValid = CK_TRUE;
  CK_RV copyRv = cnk_copy_cached_metadata(entry, algorithmType, publicKey, pinPolicy, touchPolicy);
  cnk_mutex_unlock(&session->token->lock);
  return copyRv;
}

static CK_RV cnk_get_piv_metadata_directory_libcanokey(CNK_PKCS11_SESSION *session,
                                                       CNK_PIV_METADATA_DIRECTORY_ENTRY *entries,
                                                       CK_ULONG_PTR entryCount) {
  CNK_ENSURE_NONNULL(session, entryCount);
  CNK_ENSURE_OK(cnk_ensure_libcanokey_profile(session));
  SCARDHANDLE card = 0;
  CNK_ENSURE_OK(cnk_begin_piv_transaction(session->slotId, &card));
  CNK_LIBCANO_CONTEXT *context = NULL;
  CNK_LIBCANO_OPERATION *operation = NULL;
  CNK_LIBCANO_ERROR error = {.struct_size = sizeof(error)};
  CK_RV rv = cnk_piv_context_for_session(session, CNK_LIBCANO_CONTEXT_SELECTED, &context);
  if (rv != CKR_OK)
    goto cleanup;
  uint32_t status =
      CNK_EXTERNAL_CALL(cnk_piv_read_metadata_directory_in_context_new, context, NULL, &operation, &error);
  rv = cnk_piv_operation_status(status, &error, CKR_DATA_INVALID);
  if (rv != CKR_OK)
    goto cleanup;
  rv = cnk_run_piv_operation(card, operation, CKR_DATA_INVALID, NULL);
  if (rv != CKR_OK)
    goto cleanup;
  rv = CKR_DEVICE_ERROR;
  CNK_LIBCANO_DIRECTORY_INFO info = {.struct_size = sizeof(info)};
  CNK_PIV_METADATA_DIRECTORY_ENTRY snapshot[32];
  if (CNK_EXTERNAL_CALL(cnk_operation_directory_info, operation, &info) != CNK_LIBCANO_OK || info.decoded != 1 ||
      info.version != 1 || info.count > sizeof(snapshot) / sizeof(snapshot[0]))
    goto cleanup;
  for (CK_ULONG i = 0; i < info.count; i++) {
    CNK_LIBCANO_DIRECTORY_ENTRY entry = {.struct_size = sizeof(entry)};
    if (CNK_EXTERNAL_CALL(cnk_operation_directory_entry, operation, i, &entry) != CNK_LIBCANO_OK || entry.issues != 0)
      goto cleanup;
    snapshot[i] = (CNK_PIV_METADATA_DIRECTORY_ENTRY){entry.reference, entry.flags,      entry.algorithm_id,
                                                     entry.origin,    entry.pin_policy, entry.touch_policy};
  }
  CK_ULONG capacity = entries == NULL ? 0 : *entryCount;
  *entryCount = info.count;
  if (entries != NULL && capacity < info.count) {
    rv = CKR_BUFFER_TOO_SMALL;
    goto cleanup;
  }
  if (entries != NULL)
    memcpy(entries, snapshot, info.count * sizeof(snapshot[0]));
  rv = CKR_OK;
cleanup:
  if (operation)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  if (context)
    CNK_EXTERNAL_VOID(cnk_piv_context_free, context);
  cnk_disconnect_card(card);
  return rv;
}

CK_RV cnk_get_piv_metadata_directory_cached(CNK_PKCS11_SESSION *session, CNK_PIV_METADATA_DIRECTORY_ENTRY *entries,
                                            CK_ULONG_PTR entryCount) {
  CNK_ENSURE_NONNULL(session, session->token, entryCount);
  if (g_cnk_is_managed_mode || !atomic_load(&g_cnk_piv_metadata_cache_enabled)) {
    CNK_DEBUG("hardware metadata-directory read (%s)", g_cnk_is_managed_mode ? "managed mode" : "cache disabled");
    return cnk_get_piv_metadata_directory_libcanokey(session, entries, entryCount);
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
  CK_RV rv = cnk_get_piv_metadata_directory_libcanokey(session, fetched, &fetchedCount);
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
    return cnk_get_certificate_libcanokey(session, pivTag, data, data_len, fetch_data);
  }

  CK_LONG index = cnk_public_cache_index(pivTag);
  if (index < 0)
    return cnk_get_certificate_libcanokey(session, pivTag, data, data_len, fetch_data);
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
  CK_RV rv = cnk_get_certificate_libcanokey(session, pivTag, fetched, &fetchedLen, CK_TRUE);
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
  CNK_ENSURE_OK(connectPiv(slotID, &card));
  CNK_LIBCANO_OPERATION *operation = NULL;
  CNK_LIBCANO_ERROR error = {.struct_size = sizeof(error)};
  uint32_t status = CNK_EXTERNAL_CALL(cnk_piv_read_configuration_selected_new, NULL, &operation, &error);
  CK_RV rv = cnk_piv_operation_status(status, &error, CKR_DEVICE_ERROR);
  if (rv == CKR_OK)
    rv = cnk_run_piv_operation(card, operation, CKR_DEVICE_ERROR, NULL);
  if (rv == CKR_OK) {
    size_t length = sizeof(*config);
    status = CNK_EXTERNAL_CALL(cnk_operation_piv_configuration_copy, operation, (CK_BYTE *)config, &length);
    rv = status == CNK_LIBCANO_OK && length == sizeof(*config) ? CKR_OK : CKR_DEVICE_ERROR;
  }
  if (operation)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  cnk_disconnect_card(card);
  return rv;
}

CK_RV cnk_get_piv_algorithm_extension_cached(CK_SLOT_ID slotID, CNK_PIV_ALGORITHM_EXTENSION_CONFIG *config) {
  CNK_ENSURE_NONNULL(config);
  // Managed callers share a host-owned card handle and may observe external
  // key changes between callbacks; never reuse a standalone snapshot there.
  if (atomic_load(&g_cnk_is_managed_mode))
    return cnk_get_piv_algorithm_extension(slotID, config);
  CK_ULONG index = (CK_ULONG)slotID % CNK_PIV_EXTENSION_CACHE_SLOTS;
  uint64_t nowMs = cnk_public_cache_now_ms();
  CK_ULONG bindingEpoch = atomic_load(&g_cnk_managed_binding_epoch);
  CNK_ENSURE_OK(cnk_mutex_lock(&g_cnk_readers_mutex));
  CNK_PIV_EXTENSION_CACHE_ENTRY *entry = &g_piv_extension_cache[index];
  if (entry->valid && entry->slotId == slotID && entry->bindingEpoch == bindingEpoch &&
      cnk_public_cache_fresh(entry->refreshedAtMs, nowMs)) {
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
  entry->bindingEpoch = atomic_load(&g_cnk_managed_binding_epoch);
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

CK_RV cnk_piv_v6_supported_on_card(SCARDHANDLE card, CK_BBOOL *supported) {
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
  rv = cnk_piv_v6_supported_on_card(card, supported);
  cnk_disconnect_card(card);
  return rv;
}

CK_RV cnk_piv_generate_random(CK_SLOT_ID slotID, CK_BYTE_PTR output, CK_ULONG outputLen) {
  if (output == NULL && outputLen > 0)
    return CKR_ARGUMENTS_BAD;
  SCARDHANDLE card = 0;
  CNK_ENSURE_OK(connectPiv(slotID, &card));
  CK_RV rv = CKR_OK;
  CK_ULONG offset = 0;
  // Bound each Rust result while preserving arbitrarily large caller buffers.
  // All chunks retain this transaction; a later failure wipes the whole output.
  do {
    CK_ULONG chunk = outputLen - offset;
    if (chunk > 65536)
      chunk = 65536;
    CNK_LIBCANO_OPERATION *operation = NULL;
    CNK_LIBCANO_ERROR error = {.struct_size = sizeof(error)};
    uint32_t status = CNK_EXTERNAL_CALL(cnk_piv_random_selected_new, chunk, NULL, &operation, &error);
    rv = cnk_piv_operation_status(status, &error, CKR_DEVICE_ERROR);
    if (rv == CKR_OK)
      rv = cnk_run_piv_operation(card, operation, CKR_DEVICE_ERROR, NULL);
    if (rv == CKR_OK) {
      size_t length = chunk;
      status = CNK_EXTERNAL_CALL(cnk_operation_result_copy_bytes, operation, output ? output + offset : NULL, &length);
      rv = status == CNK_LIBCANO_OK && length == chunk ? CKR_OK : CKR_DEVICE_ERROR;
    }
    if (operation)
      CNK_EXTERNAL_VOID(cnk_operation_free, operation);
    if (rv != CKR_OK)
      break;
    offset += chunk;
  } while (offset < outputLen);
  cnk_disconnect_card(card);
  if (rv != CKR_OK && outputLen > 0)
    mbedtls_platform_zeroize(output, outputLen);
  return rv == CKR_FUNCTION_NOT_SUPPORTED ? CKR_RANDOM_NO_RNG : rv;
}
