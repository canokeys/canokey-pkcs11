#include "api/session.h"
#include "backend/pcsc.h"
#include "internal/macros.h"
#include "pkcs11_canokey.h"

#include <string.h>

static CK_BBOOL valid_slot(CK_BYTE slot) {
  return slot == 0x9A || slot == 0x9C || slot == 0x9D || slot == 0x9E || (slot >= 0x82 && slot <= 0x95) || slot == 0xF9;
}

static CK_BBOOL valid_name(const CK_BYTE *name, CK_ULONG len) {
  if (len > CNK_PIV_CONTAINER_NAME_MAX_BYTES || (len & 1))
    return CK_FALSE;
  for (CK_ULONG i = 0; i < len; i += 2) {
    unsigned unit = name[i] | ((unsigned)name[i + 1] << 8);
    if (unit == 0 || (unit >= 0xDC00 && unit <= 0xDFFF))
      return CK_FALSE;
    if (unit >= 0xD800 && unit <= 0xDBFF) {
      if (i + 3 >= len)
        return CK_FALSE;
      i += 2;
      unit = name[i] | ((unsigned)name[i + 1] << 8);
      if (unit < 0xDC00 || unit > 0xDFFF)
        return CK_FALSE;
    }
  }
  return CK_TRUE;
}

// SELECT and (for writes) management authentication are completed by the caller
// in this same reader transaction. F5 never chains or retries a mutation.
static CK_RV exchange_name(SCARDHANDLE card, CK_BYTE slot, CK_BBOOL write, const CK_BYTE *name, CK_ULONG len,
                           CK_BYTE *result, CK_ULONG *resultLen) {
  CK_BBOOL supported = CK_FALSE;
  CK_RV rv = cnk_piv_v6_supported_on_card(card, &supported);
  if (rv != CKR_OK)
    return rv;
  if (!supported)
    return CKR_FUNCTION_NOT_SUPPORTED;
  CK_BYTE apdu[5 + CNK_PIV_CONTAINER_NAME_MAX_BYTES] = {0, 0xF5, write ? 1 : 0, slot, 0};
  CK_ULONG apduLen = 5;
  if (write && len) {
    apdu[4] = (CK_BYTE)len;
    memcpy(apdu + 5, name, len);
    apduLen += len;
  }
  CK_BYTE response[258];
  DWORD responseLen = sizeof(response);
  if (cnk_transceive_apdu(card, apdu, apduLen, response, &responseLen, CK_FALSE) != SCARD_S_SUCCESS)
    return CKR_DEVICE_ERROR;
  if (responseLen < 2 || responseLen > sizeof(response))
    return CKR_DEVICE_ERROR;
  unsigned sw = ((unsigned)response[responseLen - 2] << 8) | response[responseLen - 1];
  switch (sw) {
  case 0x6982:
    return CKR_USER_NOT_LOGGED_IN;
  case 0x6A88:
    return CKR_KEY_HANDLE_INVALID;
  case 0x6A86:
    return CKR_ARGUMENTS_BAD;
  case 0x6700:
    return CKR_DATA_LEN_RANGE;
  case 0x6A80:
    return CKR_DATA_INVALID;
  case 0x9000:
    break;
  default:
    return CKR_DEVICE_ERROR;
  }
  CK_ULONG size = responseLen - 2;
  if (write)
    return size == 0 ? CKR_OK : CKR_DEVICE_ERROR;
  if (!valid_name(response, size))
    return CKR_DATA_INVALID;
  CK_ULONG capacity = *resultLen;
  *resultLen = size;
  if (!result)
    return CKR_OK;
  if (capacity < size)
    return CKR_BUFFER_TOO_SMALL;
  if (size)
    memcpy(result, response, size);
  return CKR_OK;
}

CK_RV C_CNK_GetContainerName(CK_SESSION_HANDLE hSession, CK_BYTE pivSlot, CK_BYTE_PTR name, CK_ULONG_PTR nameLen) {
  CNK_ENSURE_INITIALIZED();
  CNK_ENSURE_NONNULL(nameLen);
  if (!valid_slot(pivSlot))
    return CKR_ARGUMENTS_BAD;
  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  SCARDHANDLE card = 0;
  CK_RV rv = cnk_begin_piv_transaction(session->slotId, &card);
  if (rv != CKR_OK)
    return rv;
  rv = exchange_name(card, pivSlot, CK_FALSE, NULL, 0, name, nameLen);
  cnk_disconnect_card(card);
  return rv;
}

CK_RV C_CNK_SetContainerName(CK_SESSION_HANDLE hSession, CK_BYTE pivSlot, CK_BYTE_PTR name, CK_ULONG nameLen) {
  CNK_ENSURE_INITIALIZED();
  if (!valid_slot(pivSlot) || (nameLen && !name))
    return CKR_ARGUMENTS_BAD;
  if (!valid_name(name, nameLen))
    return CKR_DATA_INVALID;
  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (!(session->flags & CKF_RW_SESSION))
    return CKR_SESSION_READ_ONLY;
  CNK_ENSURE_OK(cnk_token_begin_management_operation(session));
  SCARDHANDLE card = 0;
  CK_RV rv = cnk_authenticate_admin_for_write(session->slotId, session, &card);
  if (rv == CKR_OK) {
    // Invalidate even when the response is lost after the card committed.
    cnk_piv_public_cache_invalidate(session);
    rv = exchange_name(card, pivSlot, CK_TRUE, name, nameLen, NULL, NULL);
    cnk_disconnect_card(card);
  }
  cnk_token_end_management_operation(session);
  return rv;
}
