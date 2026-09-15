#include "backend/libcanokey.h"
#include "backend/pcsc.h"
#include "backend/piv_operation.h"

#include "api/session.h"
#include "internal/logging.h"
#include "internal/macros.h"
#include "internal/util.h"

#include <mbedtls/platform_util.h>
#include <stdlib.h>
#include <string.h>

static uint64_t cnk_public_cache_now_ms(void);
static CK_BBOOL cnk_public_cache_fresh(uint64_t refreshedAtMs, uint64_t nowMs);

CK_RV cnk_ensure_libcanokey_profile(CNK_PKCS11_SESSION *session) {
  CNK_ENSURE_NONNULL(session, session->token);
  for (unsigned attempt = 0; attempt < 3; attempt++) {
    CK_ULONG epoch = atomic_load(&g_cnk_managed_binding_epoch);
    uint64_t generation = atomic_load(&session->token->profileGeneration);
    CNK_ENSURE_OK(cnk_mutex_lock(&session->token->lock));
    CK_BBOOL fresh = session->token->loadedProfileGeneration == generation &&
                     session->token->libcanokeyProfile != NULL && session->token->libcanokeyProfileEpoch == epoch &&
                     cnk_public_cache_fresh(session->token->libcanokeyProfileRefreshedAtMs, cnk_public_cache_now_ms());
    CNK_ENSURE_OK(cnk_mutex_unlock(&session->token->lock));
    if (fresh)
      return CKR_OK;

    // Keep the previous immutable profile while a refresh waits for the card.
    // A transaction already admitted with that profile must be able to clone
    // it after VERIFY; clearing it here would break that in-flight operation.
    cnk_profile_t *candidate = NULL;
    CK_RV rv = cnk_probe_libcanokey_profile(session->slotId, &candidate);
    if (rv != CKR_OK)
      return rv;
    rv = cnk_mutex_lock(&session->token->lock);
    if (rv != CKR_OK) {
      CNK_EXTERNAL_VOID(cnk_profile_free, candidate);
      return rv;
    }
    cnk_profile_t *retired = NULL;
    CK_ULONG currentEpoch = atomic_load(&g_cnk_managed_binding_epoch);
    CK_BBOOL current = currentEpoch == epoch && generation == atomic_load(&session->token->profileGeneration);
    if (current &&
        (session->token->loadedProfileGeneration != generation || session->token->libcanokeyProfile == NULL ||
         session->token->libcanokeyProfileEpoch != epoch ||
         !cnk_public_cache_fresh(session->token->libcanokeyProfileRefreshedAtMs, cnk_public_cache_now_ms()))) {
      retired = session->token->libcanokeyProfile;
      session->token->libcanokeyProfile = candidate;
      session->token->libcanokeyProfileEpoch = epoch;
      session->token->loadedProfileGeneration = generation;
      session->token->libcanokeyProfileRefreshedAtMs = cnk_public_cache_now_ms();
      candidate = NULL;
    }
    rv = cnk_mutex_unlock(&session->token->lock);
    if (retired != NULL)
      CNK_EXTERNAL_VOID(cnk_profile_free, retired);
    if (candidate != NULL)
      CNK_EXTERNAL_VOID(cnk_profile_free, candidate);
    if (rv != CKR_OK || current)
      return rv;
  }
  return CKR_OPERATION_ACTIVE;
}

static CK_RV cnk_get_metadata_libcanokey(CNK_PKCS11_SESSION *session, CK_BYTE pivTag, uint32_t *algorithmType,
                                         CNK_PIV_PUBLIC_KEY *publicKey, CK_BYTE_PTR pinPolicy,
                                         CK_BYTE_PTR touchPolicy) {
  CNK_ENSURE_NONNULL(session, session->token, algorithmType);
  CNK_ENSURE_OK(cnk_ensure_libcanokey_profile(session));
  SCARDHANDLE card = 0;
  CNK_ENSURE_OK(cnk_begin_piv_transaction(session->slotId, &card));
  cnk_operation_t *operation = NULL;
  cnk_error_v1 error = {.struct_size = sizeof(error)};
  CK_RV rv;
  rv = CNK_PIV_CREATE(session, cnk_piv_get_metadata_new, &operation, &error, pivTag, NULL);
  if (rv != CKR_OK)
    goto cleanup;
  rv = cnk_run_piv_operation(card, operation, CKR_DATA_INVALID, NULL);
  if (rv != CKR_OK)
    goto cleanup;
  rv = CKR_DEVICE_ERROR;
  cnk_metadata_v1 metadata = {.struct_size = sizeof(metadata)};
  if (CNK_EXTERNAL_CALL(cnk_operation_metadata, operation, &metadata) != CNK_OK ||
      (metadata.presence_flags & CNK_METADATA_HAS_ALGORITHM) == 0)
    goto cleanup;
  uint32_t algorithm = 0;
  if (CNK_EXTERNAL_CALL(cnk_operation_key_algorithm, operation, &algorithm) != CNK_OK)
    goto cleanup;
  rv = publicKey != NULL ? cnk_copy_piv_public_key(operation, publicKey) : CKR_OK;
  if (rv == CKR_OK) {
    *algorithmType = algorithm;
    if (pinPolicy != NULL && (metadata.presence_flags & CNK_METADATA_HAS_POLICY) != 0)
      *pinPolicy = metadata.pin_policy;
    if (touchPolicy != NULL && (metadata.presence_flags & CNK_METADATA_HAS_POLICY) != 0)
      *touchPolicy = metadata.touch_policy;
  }
cleanup:
  if (operation)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  cnk_disconnect_card(card);
  return rv;
}

static CK_RV cnk_get_certificate_libcanokey(CNK_PKCS11_SESSION *session, CK_BYTE pivTag, CK_BYTE_PTR data,
                                            CK_ULONG_PTR dataLen, CK_BBOOL fetchData) {
  CNK_ENSURE_NONNULL(session, session->token);
  CNK_ENSURE_OK(cnk_ensure_libcanokey_profile(session));
  if (!fetchData)
    dataLen = NULL;
  else if (dataLen == NULL)
    return CKR_ARGUMENTS_BAD;
  SCARDHANDLE card = 0;
  CNK_ENSURE_OK(cnk_begin_piv_transaction(session->slotId, &card));
  cnk_operation_t *operation = NULL;
  cnk_error_v1 error = {.struct_size = sizeof(error)};
  CK_RV rv;
  rv = CNK_PIV_CREATE(session, cnk_piv_read_certificate_new, &operation, &error, pivTag);
  if (rv != CKR_OK)
    goto cleanup;
  rv = cnk_run_piv_operation(card, operation, CKR_DATA_INVALID, NULL);
  if (rv != CKR_OK)
    goto cleanup;
  rv = CKR_DEVICE_ERROR;
  size_t required = 0;
  if (CNK_EXTERNAL_CALL(cnk_operation_result_copy_bytes, operation, NULL, &required) != CNK_OK ||
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
  if (CNK_EXTERNAL_CALL(cnk_operation_result_copy_bytes, operation, data, &required) != CNK_OK)
    goto cleanup;
  rv = CKR_OK;
cleanup:
  if (operation)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  cnk_disconnect_card(card);
  return rv;
}
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#define CNK_PIV_PUBLIC_CACHE_TTL_MS 60000
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
  case 0x9a:
    return 0;
  case 0x9c:
    return 1;
  case 0x9d:
    return 2;
  case 0x9e:
    return 3;
  default:
    return pivTag >= 0x82 && pivTag <= 0x95 ? 4 + (CK_LONG)(pivTag - 0x82) : -1;
  }
}

static CK_RV cnk_copy_cached_metadata(const CNK_PIV_PUBLIC_CACHE_ENTRY *entry, uint32_t *algorithmType,
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

CK_RV cnk_get_metadata_cached(CNK_PKCS11_SESSION *session, CK_BYTE pivTag, uint32_t *algorithmType,
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
  uint64_t generation = atomic_load(&session->token->publicCacheGeneration);
  if (entry->metadataValid && entry->metadataGeneration == generation &&
      cnk_public_cache_fresh(entry->metadataRefreshedAtMs, nowMs)) {
    CK_RV copyRv = cnk_copy_cached_metadata(entry, algorithmType, publicKey, pinPolicy, touchPolicy);
    CNK_ENSURE_OK(cnk_mutex_unlock(&session->token->lock));
    CNK_DEBUG("cached metadata read: PIV slot 0x%02X", pivTag);
    return copyRv;
  }
  CNK_ENSURE_OK(cnk_mutex_unlock(&session->token->lock));

  CNK_PIV_PUBLIC_KEY cachedPublicKey;
  uint32_t cachedAlgorithmType = 0;
  CK_BYTE cachedPinPolicy = 0;
  CK_BYTE cachedTouchPolicy = 0;
  CNK_DEBUG("hardware metadata read: PIV slot 0x%02X", pivTag);
  CK_RV rv = cnk_get_metadata_libcanokey(session, pivTag, &cachedAlgorithmType, &cachedPublicKey, &cachedPinPolicy,
                                         &cachedTouchPolicy);
  if (rv != CKR_OK)
    return rv;

  CNK_ENSURE_OK(cnk_mutex_lock(&session->token->lock));
  if (generation == atomic_load(&session->token->publicCacheGeneration)) {
    entry->algorithmType = cachedAlgorithmType;
    entry->pinPolicy = cachedPinPolicy;
    entry->touchPolicy = cachedTouchPolicy;
    entry->publicKey = cachedPublicKey;
    entry->metadataRefreshedAtMs = nowMs;
    entry->metadataGeneration = generation;
    entry->metadataValid = CK_TRUE;
  }
  CNK_ENSURE_OK(cnk_mutex_unlock(&session->token->lock));
  // The read itself can linearize before an overlapping mutation. Its result
  // remains valid for this call, but must not resurrect an invalidated cache.
  *algorithmType = cachedAlgorithmType;
  if (pinPolicy)
    *pinPolicy = cachedPinPolicy;
  if (touchPolicy)
    *touchPolicy = cachedTouchPolicy;
  if (publicKey)
    *publicKey = cachedPublicKey;
  return CKR_OK;
}

static CK_RV cnk_get_piv_metadata_directory_libcanokey(CNK_PKCS11_SESSION *session,
                                                       CNK_PIV_METADATA_DIRECTORY_ENTRY *entries,
                                                       CK_ULONG_PTR entryCount) {
  CNK_ENSURE_NONNULL(session, entryCount);
  CNK_ENSURE_OK(cnk_ensure_libcanokey_profile(session));
  SCARDHANDLE card = 0;
  CNK_ENSURE_OK(cnk_begin_piv_transaction(session->slotId, &card));
  cnk_operation_t *operation = NULL;
  cnk_error_v1 error = {.struct_size = sizeof(error)};
  CK_RV rv;
  rv = CNK_PIV_CREATE(session, cnk_piv_read_metadata_directory_new, &operation, &error, NULL);
  if (rv != CKR_OK)
    goto cleanup;
  rv = cnk_run_piv_operation(card, operation, CKR_DATA_INVALID, NULL);
  if (rv != CKR_OK)
    goto cleanup;
  rv = CKR_DEVICE_ERROR;
  cnk_directory_info_v1 info = {.struct_size = sizeof(info)};
  CNK_PIV_METADATA_DIRECTORY_ENTRY snapshot[32];
  if (CNK_EXTERNAL_CALL(cnk_operation_directory_info, operation, &info) != CNK_OK || info.decoded != 1 ||
      info.version != 1 || info.count > sizeof(snapshot) / sizeof(snapshot[0]))
    goto cleanup;
  for (CK_ULONG i = 0; i < info.count; i++) {
    cnk_directory_entry_v1 entry = {.struct_size = sizeof(entry)};
    if (CNK_EXTERNAL_CALL(cnk_operation_directory_entry, operation, i, &entry) != CNK_OK || entry.issues != 0)
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
  uint64_t generation = atomic_load(&session->token->publicCacheGeneration);
  if (cache->directoryValid && cache->directoryGeneration == generation &&
      cnk_public_cache_fresh(cache->directoryRefreshedAtMs, nowMs)) {
    CK_ULONG required = cache->directoryCount;
    CK_ULONG capacity = entries == NULL ? 0 : *entryCount;
    *entryCount = required;
    if (entries != NULL && capacity < required) {
      CNK_ENSURE_OK(cnk_mutex_unlock(&session->token->lock));
      return CKR_BUFFER_TOO_SMALL;
    }
    if (entries != NULL)
      for (CK_ULONG i = 0; i < required; i++)
        entries[i] =
            (CNK_PIV_METADATA_DIRECTORY_ENTRY){cache->directory[i][0], cache->directory[i][1], cache->directory[i][2],
                                               cache->directory[i][3], cache->directory[i][4], cache->directory[i][5]};
    CNK_ENSURE_OK(cnk_mutex_unlock(&session->token->lock));
    CNK_DEBUG("cached metadata-directory read: %lu entries", required);
    return CKR_OK;
  }
  CNK_ENSURE_OK(cnk_mutex_unlock(&session->token->lock));

  CNK_PIV_METADATA_DIRECTORY_ENTRY fetched[CNK_PIV_METADATA_DIRECTORY_MAX_ENTRIES];
  CK_ULONG fetchedCount = CNK_PIV_METADATA_DIRECTORY_MAX_ENTRIES;
  CNK_DEBUG("hardware metadata-directory read");
  CK_RV rv = cnk_get_piv_metadata_directory_libcanokey(session, fetched, &fetchedCount);
  if (rv != CKR_OK)
    return rv;

  CNK_ENSURE_OK(cnk_mutex_lock(&session->token->lock));
  if (generation == atomic_load(&session->token->publicCacheGeneration)) {
    cache->directoryCount = fetchedCount;
    for (CK_ULONG i = 0; i < fetchedCount; i++)
      memcpy(cache->directory[i], &fetched[i], sizeof(fetched[i]));
    cache->directoryRefreshedAtMs = nowMs;
    cache->directoryGeneration = generation;
    cache->directoryValid = CK_TRUE;
  }
  CK_ULONG capacity = entries == NULL ? 0 : *entryCount;
  *entryCount = fetchedCount;
  if (entries != NULL && capacity < fetchedCount) {
    CNK_ENSURE_OK(cnk_mutex_unlock(&session->token->lock));
    return CKR_BUFFER_TOO_SMALL;
  }
  if (entries != NULL)
    memcpy(entries, fetched, fetchedCount * sizeof(*entries));
  CNK_ENSURE_OK(cnk_mutex_unlock(&session->token->lock));
  return CKR_OK;
}

CK_RV cnk_get_piv_certificate_cached(CNK_PKCS11_SESSION *session, CK_BYTE pivTag, CK_BYTE_PTR data,
                                     CK_ULONG_PTR data_len, CK_BBOOL fetch_data) {
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
  uint64_t generation = atomic_load(&session->token->publicCacheGeneration);
  if (entry->certificateValid && entry->certificateGeneration == generation &&
      cnk_public_cache_fresh(entry->certificateRefreshedAtMs, nowMs)) {
    CK_ULONG required = entry->certificateLen;
    if (!fetch_data) {
      CNK_ENSURE_OK(cnk_mutex_unlock(&session->token->lock));
      CNK_DEBUG("cached certificate existence read: PIV slot 0x%02X", pivTag);
      return CKR_OK;
    }
    if (data_len == NULL) {
      CNK_ENSURE_OK(cnk_mutex_unlock(&session->token->lock));
      return CKR_ARGUMENTS_BAD;
    }
    CK_ULONG capacity = *data_len;
    *data_len = required;
    if (data == NULL || capacity < required) {
      CNK_ENSURE_OK(cnk_mutex_unlock(&session->token->lock));
      return data == NULL ? CKR_OK : CKR_BUFFER_TOO_SMALL;
    }
    memcpy(data, entry->certificate, required);
    CNK_ENSURE_OK(cnk_mutex_unlock(&session->token->lock));
    CNK_DEBUG("cached certificate read: PIV slot 0x%02X", pivTag);
    return CKR_OK;
  }
  CNK_ENSURE_OK(cnk_mutex_unlock(&session->token->lock));

  CK_BYTE fetched[CNK_PIV_PUBLIC_CACHE_MAX_CERTIFICATE];
  CK_ULONG fetchedLen = sizeof(fetched);
  CNK_DEBUG("hardware certificate read: PIV slot 0x%02X", pivTag);
  CK_RV rv = cnk_get_certificate_libcanokey(session, pivTag, fetched, &fetchedLen, CK_TRUE);
  if (rv != CKR_OK)
    return rv;
  if (fetchedLen > sizeof(entry->certificate))
    return CKR_DATA_LEN_RANGE;

  CNK_ENSURE_OK(cnk_mutex_lock(&session->token->lock));
  if (generation == atomic_load(&session->token->publicCacheGeneration)) {
    entry->certificateLen = fetchedLen;
    memcpy(entry->certificate, fetched, fetchedLen);
    entry->certificateRefreshedAtMs = nowMs;
    entry->certificateGeneration = generation;
    entry->certificateValid = CK_TRUE;
  }
  if (!fetch_data) {
    CNK_ENSURE_OK(cnk_mutex_unlock(&session->token->lock));
    return CKR_OK;
  }
  if (data_len == NULL) {
    CNK_ENSURE_OK(cnk_mutex_unlock(&session->token->lock));
    return CKR_ARGUMENTS_BAD;
  }
  CK_ULONG capacity = *data_len;
  *data_len = fetchedLen;
  if (data == NULL) {
    CNK_ENSURE_OK(cnk_mutex_unlock(&session->token->lock));
    return CKR_OK;
  }
  if (capacity < fetchedLen) {
    CNK_ENSURE_OK(cnk_mutex_unlock(&session->token->lock));
    return CKR_BUFFER_TOO_SMALL;
  }
  memcpy(data, fetched, fetchedLen);
  CNK_ENSURE_OK(cnk_mutex_unlock(&session->token->lock));
  return CKR_OK;
}

void cnk_piv_public_cache_invalidate(CNK_PKCS11_SESSION *session) {
  if (session == NULL || session->token == NULL)
    return;
  // Invalidate before trying the callback lock: a failed callback must not
  // keep old data valid or allow an in-flight read to publish it later.
  atomic_fetch_add(&session->token->publicCacheGeneration, 1);
  if (cnk_mutex_lock(&session->token->lock) != CKR_OK)
    return;
  memset(&session->token->pivPublicCache, 0, sizeof(session->token->pivPublicCache));
  cnk_mutex_unlock(&session->token->lock);
  CNK_DEBUG("invalidated public PIV snapshot cache");
}

CK_RV cnk_session_piv_capabilities(CNK_PKCS11_SESSION *session, cnk_piv_capabilities_v1 *capabilities) {
  CNK_ENSURE_NONNULL(capabilities);
  CNK_ENSURE_OK(cnk_ensure_libcanokey_profile(session));
  const cnk_profile_t *profile = NULL;
  CNK_ENSURE_OK(cnk_piv_profile_begin(session, &profile));
  cnk_piv_capabilities_v1 value = {.struct_size = sizeof(value)};
  uint32_t status = CNK_EXTERNAL_CALL(cnk_profile_piv_capabilities, profile, &value);
  CK_RV rv = cnk_mutex_unlock(&session->token->lock);
  if (rv == CKR_OK)
    rv = cnk_piv_operation_status(status, NULL, CKR_DEVICE_ERROR);
  if (rv == CKR_OK)
    *capabilities = value;
  return rv;
}

CK_RV cnk_get_piv_capabilities(CK_SLOT_ID slotID, cnk_piv_capabilities_v1 *capabilities) {
  CNK_PKCS11_SESSION view = {.slotId = slotID};
  CNK_ENSURE_OK(cnk_token_for_slot(slotID, &view.token));
  return cnk_session_piv_capabilities(&view, capabilities);
}

CK_RV cnk_piv_random_supported(CK_SLOT_ID slotID, CK_BBOOL *supported) {
  CNK_ENSURE_NONNULL(supported);
  cnk_piv_capabilities_v1 capabilities;
  CNK_ENSURE_OK(cnk_get_piv_capabilities(slotID, &capabilities));
  if (capabilities.unknown_features & CNK_PIV_FEATURE_RANDOM)
    return CKR_DEVICE_ERROR;
  *supported = !!(capabilities.features & CNK_PIV_FEATURE_RANDOM);
  return CKR_OK;
}

CK_RV cnk_piv_generate_random(CK_SLOT_ID slotID, CK_BYTE_PTR output, CK_ULONG outputLen) {
  if (output == NULL && outputLen > 0)
    return CKR_ARGUMENTS_BAD;
  SCARDHANDLE card = 0;
  CNK_ENSURE_OK(cnk_begin_piv_transaction(slotID, &card));
  CK_RV rv = CKR_OK;
  CK_ULONG offset = 0;
  // Bound each Rust result while preserving arbitrarily large caller buffers.
  // All chunks retain this transaction; a later failure wipes the whole output.
  do {
    CK_ULONG chunk = outputLen - offset;
    if (chunk > 65536)
      chunk = 65536;
    cnk_operation_t *operation = NULL;
    cnk_error_v1 error = {.struct_size = sizeof(error)};
    uint32_t status = CNK_EXTERNAL_CALL(cnk_piv_random_selected_new, chunk, NULL, &operation, &error);
    rv = cnk_piv_operation_status(status, &error, CKR_DEVICE_ERROR);
    if (rv == CKR_OK)
      rv = cnk_run_piv_operation(card, operation, CKR_DEVICE_ERROR, NULL);
    if (rv == CKR_OK) {
      size_t length = chunk;
      status = CNK_EXTERNAL_CALL(cnk_operation_result_copy_bytes, operation, output ? output + offset : NULL, &length);
      rv = status == CNK_OK && length == chunk ? CKR_OK : CKR_DEVICE_ERROR;
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
