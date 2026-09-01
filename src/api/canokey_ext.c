#include "api/session.h"
#include "backend/pcsc.h"
#include "internal/logging.h"
#include "internal/macros.h"
#include "internal/util.h"
#include "pkcs11.h"
#include "pkcs11_canokey.h"

#include <mbedtls/platform.h>
#include <mbedtls/platform_util.h>
#include <nsync_malloc.h>
#include <stdlib.h>
#include <string.h>

#define CNK_ADMIN_DATA_MAX_LEN 128
#define CNK_PIN_PROTECTED_DATA_MAX_LEN 64
#define CNK_MANAGEMENT_KEY_LEN 24
#define CNK_ADMIN_PIN_PROTECTED_BIT 0x02

static const CK_BYTE CNK_ADMIN_DATA_TAG[] = {0x5F, 0xFF, 0x00};
static const CK_BYTE CNK_PRINTED_INFORMATION_TAG[] = {0x5F, 0xC1, 0x09};

// Parse one bounded BER-TLV element and advance the caller-owned cursor. These
// PIN-management objects are security decisions, so trailing or duplicate
// fields are rejected by their higher-level parsers rather than ignored.
static CK_RV readTlv(const CK_BYTE *data, CK_ULONG dataLen, CK_ULONG_PTR offset, CK_BYTE expectedTag,
                     const CK_BYTE **value, CK_ULONG_PTR valueLen) {
  CNK_ENSURE_NONNULL(data, offset, value, valueLen);
  if (*offset >= dataLen || data[*offset] != expectedTag)
    return CKR_DATA_INVALID;

  CK_ULONG cursor = *offset + 1;
  CK_LONG fail = 0;
  CK_ULONG lengthSize = 0;
  CK_ULONG length = tlvGetLengthSafe(data + cursor, dataLen - cursor, &fail, &lengthSize);
  if (fail)
    return CKR_DATA_INVALID;
  cursor += lengthSize;
  if (length > dataLen - cursor)
    return CKR_DATA_INVALID;

  *value = data + cursor;
  *valueLen = length;
  *offset = cursor + length;
  return CKR_OK;
}

static CK_RV checkPinManagedAdminData(const CK_BYTE *data, CK_ULONG dataLen) {
  // Yubico ADMIN DATA: 53 { 80 { 81 bit-field, [82 salt], [83 date] } }.
  // Bit 0x02 is the explicit opt-in to reading a key from PRINTED.
  CK_ULONG offset = 0;
  const CK_BYTE *outer;
  CK_ULONG outerLen;
  if (readTlv(data, dataLen, &offset, 0x53, &outer, &outerLen) != CKR_OK || offset != dataLen)
    return CKR_DATA_INVALID;

  offset = 0;
  const CK_BYTE *admin;
  CK_ULONG adminLen;
  if (readTlv(outer, outerLen, &offset, 0x80, &admin, &adminLen) != CKR_OK || offset != outerLen)
    return CKR_DATA_INVALID;

  CK_BBOOL sawBitField = CK_FALSE;
  CK_BBOOL sawSalt = CK_FALSE;
  CK_BBOOL sawDate = CK_FALSE;
  CK_BBOOL pinProtected = CK_FALSE;
  offset = 0;
  while (offset < adminLen) {
    CK_BYTE tag = admin[offset];
    const CK_BYTE *value;
    CK_ULONG valueLen;
    if (readTlv(admin, adminLen, &offset, tag, &value, &valueLen) != CKR_OK)
      return CKR_DATA_INVALID;
    switch (tag) {
    case 0x81:
      if (sawBitField || valueLen != 1)
        return CKR_DATA_INVALID;
      sawBitField = CK_TRUE;
      pinProtected = (value[0] & CNK_ADMIN_PIN_PROTECTED_BIT) != 0;
      break;
    case 0x82:
      if (sawSalt || (valueLen != 0 && valueLen != 16))
        return CKR_DATA_INVALID;
      sawSalt = CK_TRUE;
      break;
    case 0x83:
      if (sawDate || valueLen > 8)
        return CKR_DATA_INVALID;
      sawDate = CK_TRUE;
      break;
    default:
      return CKR_DATA_INVALID;
    }
  }

  return sawBitField && pinProtected ? CKR_OK : CKR_DATA_INVALID;
}

static CK_RV parsePinProtectedManagementKey(const CK_BYTE *data, CK_ULONG dataLen,
                                            CK_BYTE managementKey[CNK_MANAGEMENT_KEY_LEN]) {
  // PIN-protected PRINTED: 53 { 88 { 89 <24-byte management key> } }.
  // Require exact nesting so unrelated PRINTED data cannot be used as a key.
  CK_ULONG offset = 0;
  const CK_BYTE *outer;
  CK_ULONG outerLen;
  if (readTlv(data, dataLen, &offset, 0x53, &outer, &outerLen) != CKR_OK || offset != dataLen)
    return CKR_DATA_INVALID;

  offset = 0;
  const CK_BYTE *container;
  CK_ULONG containerLen;
  if (readTlv(outer, outerLen, &offset, 0x88, &container, &containerLen) != CKR_OK || offset != outerLen)
    return CKR_DATA_INVALID;

  offset = 0;
  const CK_BYTE *key;
  CK_ULONG keyLen;
  if (readTlv(container, containerLen, &offset, 0x89, &key, &keyLen) != CKR_OK || offset != containerLen ||
      keyLen != CNK_MANAGEMENT_KEY_LEN)
    return CKR_DATA_INVALID;

  memcpy(managementKey, key, keyLen);
  return CKR_OK;
}

// Function pointers for memory allocation (global)
CNK_MALLOC_FUNC g_cnk_malloc_func = malloc;
CNK_FREE_FUNC g_cnk_free_func = free;

CK_BBOOL g_cnk_is_managed_mode = CK_FALSE; // False for standalone mode, True for managed mode
SCARDCONTEXT g_cnk_pcsc_context = 0L;
SCARDHANDLE g_cnk_scard = 0L;

CK_RV C_CNK_EnableManagedMode(CNK_MANAGED_MODE_INIT_ARGS_PTR pInitArgs) {
  CNK_LOG_FUNC(": pInitArgs: %p", pInitArgs);

  // Check if initialization arguments are provided
  if (pInitArgs != NULL_PTR) {
    if (pInitArgs->malloc_func == NULL || pInitArgs->free_func == NULL || pInitArgs->hSCardCtx == 0 ||
        pInitArgs->hScard == 0) {
      return CKR_ARGUMENTS_BAD;
    }

    g_cnk_is_managed_mode = CK_TRUE;
    g_cnk_malloc_func = pInitArgs->malloc_func;
    g_cnk_free_func = pInitArgs->free_func;
    // call mbedtls hook to use the same malloc/free functions
    mbedtls_platform_set_calloc_free(ck_calloc, ck_free);
    // tell nsync to use the same malloc/free functions
    nsync_malloc_ptr_ = g_cnk_malloc_func;
    nsync_free_ptr_ = g_cnk_free_func;
    g_cnk_pcsc_context = pInitArgs->hSCardCtx;
    g_cnk_scard = pInitArgs->hScard;
    return CKR_OK;
  }

  return CKR_ARGUMENTS_BAD;
}

CK_RV C_CNK_ConfigLogging(int level, FILE *file, CK_BBOOL unsafe_log_apdu) {
  return cnk_config_logging(level, file, unsafe_log_apdu);
}

CK_RV C_CNK_GetPivData(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pTag, CK_ULONG ulTagLen, CK_BYTE_PTR pValue,
                       CK_ULONG_PTR pulValueLen) {
  CNK_LOG_FUNC(": hSession: %lu, pTag: %p, ulTagLen: %lu, pValue: %p, pulValueLen: %p", hSession, pTag, ulTagLen,
               pValue, pulValueLen);
  CNK_ENSURE_INITIALIZED();
  CNK_ENSURE_NONNULL(pTag, pulValueLen);
  if (ulTagLen == 0 || ulTagLen > 4)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "Invalid PIV data-object tag");

  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  return cnk_get_piv_data_by_tag_with_session(session->slotId, session, pTag, ulTagLen, pValue, pulValueLen, CK_TRUE);
}

CK_RV C_CNK_LoginPinManaged(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  CNK_LOG_FUNC(": hSession: %lu, pPin: %p, ulPinLen: %lu", hSession, pPin, ulPinLen);
  CNK_ENSURE_INITIALIZED();
  CNK_ENSURE_NONNULL(pPin);

  // Keep USER login active while GET DATA reads PRINTED. The management-key
  // cache is separate, allowing managed callers to retain normal USER state.
  CK_RV rv = C_CNK_Login(hSession, CKU_USER, pPin, ulPinLen, NULL);
  if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
    return rv;

  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (cnk_token_management_key_is_cached(session))
    return CKR_OK;

  CK_BYTE adminData[CNK_ADMIN_DATA_MAX_LEN];
  CK_BYTE protectedData[CNK_PIN_PROTECTED_DATA_MAX_LEN];
  CK_BYTE managementKey[CNK_MANAGEMENT_KEY_LEN];
  CK_ULONG dataLen = sizeof(adminData);

  rv = cnk_get_piv_data_by_tag_with_session(session->slotId, session, CNK_ADMIN_DATA_TAG, sizeof(CNK_ADMIN_DATA_TAG),
                                            adminData, &dataLen, CK_TRUE);
  if (rv == CKR_OK)
    rv = checkPinManagedAdminData(adminData, dataLen);

  if (rv == CKR_OK) {
    dataLen = sizeof(protectedData);
    rv = cnk_get_piv_data_by_tag_with_session(session->slotId, session, CNK_PRINTED_INFORMATION_TAG,
                                              sizeof(CNK_PRINTED_INFORMATION_TAG), protectedData, &dataLen, CK_TRUE);
  }
  if (rv == CKR_OK)
    rv = parsePinProtectedManagementKey(protectedData, dataLen, managementKey);
  if (rv == CKR_OK)
    rv = C_CNK_LoginProtectedManagementKey(hSession, managementKey, sizeof(managementKey));
  if (rv == CKR_USER_ALREADY_LOGGED_IN)
    rv = CKR_OK;

  // None of the ADMIN/PRINTED payload or recovered key escapes this boundary.
  mbedtls_platform_zeroize(managementKey, sizeof(managementKey));
  mbedtls_platform_zeroize(protectedData, sizeof(protectedData));
  mbedtls_platform_zeroize(adminData, sizeof(adminData));
  return rv;
}

CK_RV C_CNK_SetPIN(CK_SESSION_HANDLE hSession, CK_BYTE pinType, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen,
                   CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen, CK_BYTE_PTR pPinTries) {
  CNK_LOG_FUNC(": hSession: %lu, pinType: 0x%02x, pOldPin: %p, ulOldLen: %lu, pNewPin: %p, ulNewLen: %lu, "
               "pPinTries: %p",
               hSession, pinType, pOldPin, ulOldLen, pNewPin, ulNewLen, pPinTries);

  CNK_ENSURE_INITIALIZED();
  CNK_ENSURE_NONNULL(pOldPin, pNewPin);

  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (!(session->flags & CKF_RW_SESSION))
    CNK_RETURN(CKR_SESSION_READ_ONLY, "write session is required");

  return cnk_change_piv_secret_with_session(session->slotId, session, pinType, pOldPin, ulOldLen, pNewPin, ulNewLen,
                                            pPinTries);
}

CK_RV C_CNK_UnblockPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPuk, CK_ULONG ulPukLen, CK_UTF8CHAR_PTR pNewPin,
                       CK_ULONG ulNewPinLen, CK_BYTE_PTR pPinTries) {
  CNK_LOG_FUNC(": hSession: %lu, pPuk: %p, ulPukLen: %lu, pNewPin: %p, ulNewPinLen: %lu, pPinTries: %p", hSession, pPuk,
               ulPukLen, pNewPin, ulNewPinLen, pPinTries);

  CNK_ENSURE_INITIALIZED();
  CNK_ENSURE_NONNULL(pPuk, pNewPin);

  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (!(session->flags & CKF_RW_SESSION))
    CNK_RETURN(CKR_SESSION_READ_ONLY, "write session is required");

  return cnk_unblock_piv_pin_with_session(session->slotId, session, pPuk, ulPukLen, pNewPin, ulNewPinLen, pPinTries);
}
