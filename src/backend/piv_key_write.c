#include "backend/pcsc.h"

CK_RV cnk_begin_key_write(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_BYTE pivSlot, SCARDHANDLE *card) {
  CK_RV rv = cnk_authenticate_admin_for_write(slotID, session, card);
  if (rv != CKR_OK || !g_cnk_is_managed_mode)
    return rv;

  // Do not use cached metadata or reconnect after management authentication.
  // Unknown algorithms still occupy a slot; only explicit absence permits a
  // Windows create. Standalone provisioning retains explicit replacement.
  CK_BYTE apdu[] = {0x00, 0xF7, 0x00, pivSlot, 0x00};
  CK_BYTE response[4096];
  DWORD len = sizeof(response);
  LONG pcscRv = cnk_transceive_apdu(*card, apdu, sizeof(apdu), response, &len, CK_TRUE);
  rv = CKR_DEVICE_ERROR;
  if (pcscRv == SCARD_S_SUCCESS && len >= 2 && len <= sizeof(response)) {
    unsigned sw = ((unsigned)response[len - 2] << 8) | response[len - 1];
    if (len == 2 && (sw == 0x6A82 || sw == 0x6A88))
      return CKR_OK;
    if (sw == 0x9000)
      rv = CKR_ACTION_PROHIBITED;
  }
  cnk_disconnect_card(*card);
  *card = 0;
  return rv;
}
