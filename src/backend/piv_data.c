#include "backend/libcanokey.h"
#include "backend/pcsc.h"
#include "backend/piv_operation.h"

#include "api/session.h"
#include "internal/logging.h"
#include "internal/macros.h"

#include <mbedtls/platform_util.h>
#include <string.h>

#define CNK_PIV_MAX_DATA_OBJECT_SIZE 8192
#define PIV_PADDED_PIN_LEN 8

static CK_RV map_libcanokey_object_error(const cnk_operation_t *operation, uint32_t status) {
  cnk_error_v1 error = {.struct_size = sizeof(error)};
  if (status == CNK_PROTOCOL_ERROR && operation != NULL)
    CNK_EXTERNAL_CALL(cnk_operation_error, operation, &error);
  return cnk_piv_operation_status(status, &error, CKR_DATA_INVALID);
}

static CK_RV read_piv_data_selected(SCARDHANDLE card, CNK_PKCS11_SESSION *session, const CK_BYTE *tag, CK_ULONG tag_len,
                                    CK_BYTE_PTR data, CK_ULONG_PTR data_len, CK_BBOOL fetch_data) {
  CNK_ENSURE_NONNULL(session, tag);
  if (tag_len == 0 || tag_len > 4 || (fetch_data && data_len == NULL))
    return CKR_ARGUMENTS_BAD;
  cnk_operation_t *operation = NULL;
  cnk_error_v1 error = {.struct_size = sizeof(error)};
  CK_RV rv;
  uint32_t status;
  rv = CNK_PIV_CREATE(session, cnk_piv_read_object_container_new, &operation, &error, tag, tag_len);
  if (rv != CKR_OK)
    goto cleanup;
  rv = cnk_run_piv_operation(card, operation, CKR_DATA_INVALID, NULL);
  if (rv != CKR_OK)
    goto cleanup;
  size_t required = 0;
  status = CNK_EXTERNAL_CALL(cnk_operation_result_copy_bytes, operation, NULL, &required);
  if (status != CNK_OK) {
    rv = map_libcanokey_object_error(operation, status);
    goto cleanup;
  }
  if (!fetch_data) {
    rv = CKR_OK;
    goto cleanup;
  }
  CK_ULONG capacity = *data_len;
  *data_len = (CK_ULONG)required;
  if (data == NULL) {
    rv = CKR_OK;
    goto cleanup;
  }
  if (capacity < required) {
    rv = CKR_BUFFER_TOO_SMALL;
    goto cleanup;
  }
  status = CNK_EXTERNAL_CALL(cnk_operation_result_copy_bytes, operation, data, &required);
  rv = status == CNK_OK ? CKR_OK : map_libcanokey_object_error(operation, status);

cleanup:
  if (operation != NULL)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  return rv;
}

CK_RV cnk_get_public_piv_data_on_card(CNK_PKCS11_SESSION *session, SCARDHANDLE card, const CK_BYTE *tag,
                                      CK_ULONG tagLen, CK_BYTE *data, CK_ULONG *dataLen) {
  // Recovery policy reads must not submit a stale cached PIN before the PUK
  // can replace it. Rust still validates framing and reports card access denial.
  return read_piv_data_selected(card, session, tag, tagLen, data, dataLen, CK_TRUE);
}

CK_RV cnk_get_piv_data_by_tag_with_session(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, const CK_BYTE *tag,
                                           CK_ULONG tag_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len,
                                           CK_BBOOL fetch_data) {
  CNK_LOG_FUNC(": slotID: %ld, session: %p, tag: %p, tag_len: %lu, data: %p, data_len: %p, fetch_data: %d", slotID,
               session, tag, tag_len, data, data_len, fetch_data);
  CNK_ENSURE_NONNULL(session, tag);
  if (tag_len == 0 || tag_len > 4 || (fetch_data && data_len == NULL))
    return CKR_ARGUMENTS_BAD;
  CNK_ENSURE_OK(cnk_ensure_libcanokey_profile(session));
  SCARDHANDLE card = 0;
  CK_BYTE pin[PIV_PADDED_PIN_LEN] = {0};
  CK_ULONG pinLen = 0;
  CK_RV rv = cnk_token_copy_pin(session, pin, &pinLen);
  if (rv == CKR_OK) {
    rv = cnk_verify_piv_pin_with_session_ex(slotID, session, pin, pinLen, NULL, &card);
  } else if (rv == CKR_USER_NOT_LOGGED_IN) {
    rv = cnk_begin_piv_transaction(slotID, &card);
  }
  mbedtls_platform_zeroize(pin, sizeof(pin));
  if (rv == CKR_OK)
    rv = read_piv_data_selected(card, session, tag, tag_len, data, data_len, fetch_data);
  if (card)
    cnk_disconnect_card(card);
  return rv;
}

static CK_RV cnk_put_piv_data_libcanokey(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, const CK_BYTE *tag,
                                         CK_ULONG tag_len, CK_BYTE_PTR data, CK_ULONG data_len) {
  CNK_ENSURE_NONNULL(session);
  cnk_operation_t *operation = NULL;
  cnk_error_v1 error = {.struct_size = sizeof(error)};
  CK_BBOOL attempted = CK_FALSE;
  SCARDHANDLE card = 0;
  // Authentication resolves the profile before opening the PIV transaction.
  CK_RV rv = cnk_authenticate_admin_for_write(slotID, session, &card);
  if (rv != CKR_OK)
    return rv;
  rv = CNK_PIV_CREATE(session, cnk_piv_write_object_container_new, &operation, &error, tag, tag_len, data, data_len,
                      NULL);
  if (rv != CKR_OK)
    goto cleanup;
  rv = cnk_run_piv_operation(card, operation, CKR_DATA_INVALID, &attempted);
cleanup:
  // A lost response cannot prove that a mutation did not reach the card.
  if (attempted)
    cnk_piv_public_cache_invalidate(session);
  if (operation)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  cnk_disconnect_card(card);
  return rv;
}

static CK_RV mutate_certificate(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_BYTE pivSlot,
                                const CK_BYTE *certificate, CK_ULONG certificateLen) {
  CNK_ENSURE_NONNULL(session);
  cnk_operation_t *operation = NULL;
  cnk_error_v1 error = {.struct_size = sizeof(error)};
  CK_BBOOL attempted = CK_FALSE;
  SCARDHANDLE card = 0;
  // Authentication resolves the profile before opening the PIV transaction.
  CK_RV rv = cnk_authenticate_admin_for_write(slotID, session, &card);
  if (rv != CKR_OK)
    return rv;
  rv = certificate != NULL ? CNK_PIV_CREATE(session, cnk_piv_write_certificate_new, &operation, &error, pivSlot,
                                            certificate, certificateLen, NULL)
                           : CNK_PIV_CREATE(session, cnk_piv_delete_certificate_new, &operation, &error, pivSlot, NULL);
  if (rv != CKR_OK)
    goto cleanup;
  rv = cnk_run_piv_operation(card, operation, CKR_DATA_INVALID, &attempted);
cleanup:
  // A lost response cannot prove that a mutation did not reach the card.
  if (attempted)
    cnk_piv_public_cache_invalidate(session);
  if (operation)
    CNK_EXTERNAL_VOID(cnk_operation_free, operation);
  cnk_disconnect_card(card);
  return rv;
}

CK_RV cnk_put_piv_data_by_tag(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, const CK_BYTE *tag, CK_ULONG tag_len,
                              CK_BYTE_PTR data, CK_ULONG data_len) {
  CNK_LOG_FUNC(": slotID: %ld, tag: %p, tag_len: %lu, data: %p, data_len: %lu", slotID, tag, tag_len, data, data_len);

  CNK_ENSURE_NONNULL(tag);
  if (tag_len == 0 || tag_len > 4)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "bad PIV data object tag");
  if (data_len > 0)
    CNK_ENSURE_NONNULL(data);

  if (data_len > CNK_PIV_MAX_DATA_OBJECT_SIZE)
    CNK_RETURN(CKR_DATA_LEN_RANGE, "PIV data object too large");
  return cnk_put_piv_data_libcanokey(slotID, session, tag, tag_len, data, data_len);
}

CK_RV cnk_write_piv_certificate(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_BYTE pivSlot,
                                const CK_BYTE *certificate, CK_ULONG certificateLen) {
  CNK_ENSURE_NONNULL(certificate);
  return mutate_certificate(slotID, session, pivSlot, certificate, certificateLen);
}

CK_RV cnk_delete_piv_certificate_libcanokey(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, CK_BYTE pivSlot) {
  return mutate_certificate(slotID, session, pivSlot, NULL, 0);
}

CK_RV cnk_get_version(CK_SLOT_ID slotID, CK_BYTE *major, CK_BYTE *minor, char *model, size_t modelLen) {
  CNK_ENSURE_NONNULL(major, minor);
  cnk_profile_t *profile = NULL;
  CNK_ENSURE_OK(cnk_probe_device_profile(slotID, 0, &profile));
  uint32_t version[3] = {0};
  uint32_t status = CNK_EXTERNAL_CALL(cnk_profile_firmware_version, profile, version);
  CK_RV rv = CKR_OK;
  if (status != CNK_OK && status != CNK_RESULT_TYPE_MISMATCH)
    rv = CKR_DEVICE_ERROR;
  if (rv == CKR_OK) {
    // Preserve the PKCS#11 version presentation; Rust owns text parsing.
    *major = (CK_BYTE)version[0];
    *minor = (CK_BYTE)(version[1] * 10 + version[2]);
    if (model && modelLen) {
      CK_BYTE name[256];
      size_t length = sizeof(name);
      status = CNK_EXTERNAL_CALL(cnk_profile_model_copy, profile, name, &length);
      if (status == CNK_RESULT_TYPE_MISMATCH) {
        memcpy(name, "CanoKey", 7);
        length = 7;
      } else if (status != CNK_OK) {
        rv = CKR_DEVICE_ERROR;
      }
      if (rv == CKR_OK) {
        if (length >= modelLen)
          length = modelLen - 1;
        memcpy(model, name, length);
        model[length] = 0;
      }
    }
  }
  CNK_EXTERNAL_VOID(cnk_profile_free, profile);
  return rv;
}

CK_RV cnk_get_serial_number(CK_SLOT_ID slotID, CK_ULONG *serial) {
  CNK_ENSURE_NONNULL(serial);
  cnk_profile_t *profile = NULL;
  CNK_ENSURE_OK(cnk_probe_device_profile(slotID, 0, &profile));
  uint32_t value = 0;
  uint32_t status = CNK_EXTERNAL_CALL(cnk_profile_serial_u32, profile, &value);
  if (status == CNK_OK)
    *serial = value;
  CNK_EXTERNAL_VOID(cnk_profile_free, profile);
  return status == CNK_OK ? CKR_OK : CKR_DEVICE_ERROR;
}
