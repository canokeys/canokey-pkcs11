#include "backend/pcsc.h"
#include "backend/piv_operation.h"
#include "internal/logging.h"

CK_RV cnk_begin_key_write(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_BYTE pivSlot, SCARDHANDLE *card) {
  CK_RV rv = cnk_authenticate_admin_for_write(slotID, session, card);
  if (rv != CKR_OK || !g_cnk_is_managed_mode)
    return rv;
  cnk_piv_context_t *context = NULL;
  cnk_operation_t *operation = NULL;
  cnk_error_v1 error = {.struct_size = sizeof(error)};
  rv = cnk_piv_context_for_session(session, CNK_PIV_CONTEXT_MANAGEMENT_AUTHORIZED, &context);
  if (rv == CKR_OK) {
    uint32_t status =
        CNK_EXTERNAL_CALL(cnk_piv_require_empty_key_slot_in_context_new, context, pivSlot, NULL, &operation, &error);
    rv = cnk_piv_operation_status(status, &error, CKR_DEVICE_ERROR);
    if (rv == CKR_OK)
      rv = cnk_run_piv_operation(*card, operation, CKR_DEVICE_ERROR, NULL);
    if (rv != CKR_OK) {
      if (operation)
        CNK_EXTERNAL_CALL(cnk_operation_error, operation, &error);
      // A successful metadata status means occupied even for unknown key types.
      rv = error.kind == CNK_ERROR_CONDITIONS && !(error.presence_flags & 1) ? CKR_ACTION_PROHIBITED : CKR_DEVICE_ERROR;
    }
  }
  if (operation)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  if (context)
    CNK_EXTERNAL_VOID(cnk_piv_context_free, context);
  if (rv != CKR_OK) {
    cnk_disconnect_card(*card);
    *card = 0;
  }
  return rv;
}
