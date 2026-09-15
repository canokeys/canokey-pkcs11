#include "api/session.h"
#include "backend/pcsc.h"
#include "backend/piv_operation.h"
#include "internal/macros.h"
#include "pkcs11_canokey.h"

static CK_BBOOL valid_slot(CK_BYTE slot) {
  return slot == 0x9A || slot == 0x9C || slot == 0x9D || slot == 0x9E || (slot >= 0x82 && slot <= 0x95) || slot == 0xF9;
}

static CK_RV name_error(const cnk_error_v1 *error, CK_RV fallback, CK_BBOOL write) {
  // The extension's legacy fallback is a version decision. An unexpected F5
  // status on supported firmware must remain a device error, even if the
  // general PIV status category calls it unsupported or absent.
  if (error->presence_flags & 1) {
    switch (error->status_word) {
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
    default:
      return CKR_DEVICE_ERROR;
    }
  }
  if (!write && error->phase == CNK_PHASE_PARSING &&
      (error->kind == CNK_ERROR_INVALID_RESPONSE || error->kind == CNK_ERROR_PROTOCOL_VIOLATION))
    return CKR_DATA_INVALID;
  return fallback == CKR_FUNCTION_NOT_SUPPORTED ? CKR_DEVICE_ERROR : fallback;
}

static CK_RV container_name_operation(CNK_PKCS11_SESSION *session, CK_BYTE slot, CK_BBOOL write, const CK_BYTE *name,
                                      CK_ULONG nameLen, CK_BYTE *output, CK_ULONG *outputLen) {
  CNK_ENSURE_OK(cnk_ensure_libcanokey_profile(session));
  SCARDHANDLE card = 0;
  CK_RV rv = write ? cnk_authenticate_admin_for_write(session->slotId, session, &card)
                   : cnk_begin_piv_transaction(session->slotId, &card);
  if (rv != CKR_OK)
    return rv;
  cnk_piv_context_t *context = NULL;
  cnk_operation_t *operation = NULL;
  cnk_error_v1 error = {.struct_size = sizeof(error)};
  CK_BBOOL supported = CK_FALSE;
  rv = cnk_piv_v6_supported_on_card(card, &supported);
  if (rv != CKR_OK)
    goto cleanup;
  if (!supported) {
    rv = CKR_FUNCTION_NOT_SUPPORTED;
    goto cleanup;
  }
  rv = cnk_piv_context_for_session(session, write ? CNK_PIV_CONTEXT_MANAGEMENT_AUTHORIZED : CNK_PIV_CONTEXT_SELECTED,
                                   &context);
  if (rv != CKR_OK)
    goto cleanup;
  uint32_t status =
      write ? CNK_EXTERNAL_CALL(cnk_piv_set_container_name_in_context_new, context, slot, name, nameLen, NULL,
                                &operation, &error)
            : CNK_EXTERNAL_CALL(cnk_piv_read_container_name_in_context_new, context, slot, NULL, &operation, &error);
  rv = name_error(&error, cnk_piv_operation_status(status, &error, CKR_KEY_HANDLE_INVALID), write);
  if (rv != CKR_OK)
    goto cleanup;
  if (write)
    cnk_piv_public_cache_invalidate(session);
  rv = cnk_run_piv_operation(card, operation, CKR_KEY_HANDLE_INVALID, NULL);
  if (rv != CKR_OK) {
    if (CNK_EXTERNAL_CALL(cnk_operation_error, operation, &error) == CNK_OK)
      rv = name_error(&error, rv, write);
    goto cleanup;
  }
  if (write)
    goto cleanup;
  size_t required = 0;
  rv = CKR_DEVICE_ERROR;
  if (CNK_EXTERNAL_CALL(cnk_operation_result_copy_bytes, operation, NULL, &required) != CNK_OK)
    goto cleanup;
  CK_ULONG capacity = *outputLen;
  *outputLen = (CK_ULONG)required;
  if (output == NULL) {
    rv = CKR_OK;
    goto cleanup;
  }
  if (capacity < required) {
    rv = CKR_BUFFER_TOO_SMALL;
    goto cleanup;
  }
  if (CNK_EXTERNAL_CALL(cnk_operation_result_copy_bytes, operation, output, &required) == CNK_OK)
    rv = CKR_OK;
cleanup:
  if (operation)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  if (context)
    CNK_EXTERNAL_VOID(cnk_piv_context_free, context);
  cnk_disconnect_card(card);
  return rv;
}

CK_RV C_CNK_GetContainerName(CK_SESSION_HANDLE hSession, CK_BYTE pivSlot, CK_BYTE_PTR name, CK_ULONG_PTR nameLen) {
  CNK_ENSURE_INITIALIZED();
  CNK_ENSURE_NONNULL(nameLen);
  if (!valid_slot(pivSlot))
    return CKR_ARGUMENTS_BAD;
  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  return container_name_operation(session, pivSlot, CK_FALSE, NULL, 0, name, nameLen);
}

CK_RV C_CNK_SetContainerName(CK_SESSION_HANDLE hSession, CK_BYTE pivSlot, CK_BYTE_PTR name, CK_ULONG nameLen) {
  CNK_ENSURE_INITIALIZED();
  if (!valid_slot(pivSlot) || (nameLen && !name))
    return CKR_ARGUMENTS_BAD;
  if (CNK_EXTERNAL_CALL(cnk_piv_container_name_validate, name, nameLen, NULL) != CNK_OK)
    return CKR_DATA_INVALID;
  CNK_PKCS11_SESSION *session CNK_SESSION_REF = NULL;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  if (!(session->flags & CKF_RW_SESSION))
    return CKR_SESSION_READ_ONLY;
  CNK_ENSURE_OK(cnk_token_begin_management_operation(session));
  CK_RV rv = container_name_operation(session, pivSlot, CK_TRUE, name, nameLen, NULL, NULL);
  cnk_token_end_management_operation(session);
  return rv;
}
