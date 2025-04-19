#include "logging.h"
#include "pcsc_backend.h"
#include "pkcs11.h"
#include "pkcs11_macros.h"
#include "pkcs11_object.h"
#include "pkcs11_session.h"
#include "rsa_utils.h"
#include "utils.h"

#include <string.h>

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, hKey: %lu", hSession, pMechanism, hKey);

  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pMechanism);

  // Find the session
  CNK_PKCS11_SESSION *session;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  // Validate the key object
  CK_BYTE obj_id;
  CNK_ENSURE_OK(cnk_validate_object(hKey, session, CKO_PRIVATE_KEY, &obj_id));

  // Map object ID to PIV tag
  CK_BYTE piv_tag;
  CNK_ENSURE_OK(cnk_obj_id_to_piv_tag(obj_id, &piv_tag));

  // Verify that the key matches the mechanism and retrieve modulus if available
  CK_BYTE algorithm_type;

  // Reset modulus length to the maximum buffer size
  session->active_key_modulus_len = sizeof(session->active_key_modulus);

  // Get metadata including the modulus
  CNK_ENSURE_OK(cnk_get_metadata(session->slot_id, piv_tag, &algorithm_type, session->active_key_modulus,
                                 &session->active_key_modulus_len));

  CNK_DEBUG("Modulus length: %lu", session->active_key_modulus_len);

  // Check if the mechanism is supported
  switch (pMechanism->mechanism) {
  case CKM_RSA_X_509:
  case CKM_RSA_PKCS:
    if (algorithm_type != PIV_ALG_RSA_2048 && algorithm_type != PIV_ALG_RSA_3072 && algorithm_type != PIV_ALG_RSA_4096)
      CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "key is not RSA");
    break;

  case CKM_RSA_PKCS_PSS:
  case CKM_SHA1_RSA_PKCS_PSS:
  case CKM_SHA224_RSA_PKCS_PSS:
  case CKM_SHA256_RSA_PKCS_PSS:
  case CKM_SHA384_RSA_PKCS_PSS:
  case CKM_SHA512_RSA_PKCS_PSS:
    // For PSS mechanisms, validate the parameter
    if (algorithm_type != PIV_ALG_RSA_2048 && algorithm_type != PIV_ALG_RSA_3072 && algorithm_type != PIV_ALG_RSA_4096)
      CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "key is not RSA");

    // Check if parameters are provided
    if (pMechanism->pParameter == NULL || pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS))
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "PSS mechanism requires valid parameters");

    // Validate the PSS parameters
    CK_RSA_PKCS_PSS_PARAMS *pss_params = pMechanism->pParameter;

    // Validate hash algorithm
    switch (pss_params->hashAlg) {
    case CKM_SHA_1:
    case CKM_SHA224:
    case CKM_SHA256:
    case CKM_SHA384:
    case CKM_SHA512:
      break;
    default:
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "unsupported hash algorithm in PSS parameters");
    }

    // Validate MGF
    switch (pss_params->mgf) {
    case CKG_MGF1_SHA1:
    case CKG_MGF1_SHA224:
    case CKG_MGF1_SHA256:
    case CKG_MGF1_SHA384:
    case CKG_MGF1_SHA512:
      break;
    default:
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "unsupported MGF function in PSS parameters");
    }

    break;

  case CKM_SHA1_RSA_PKCS:
  case CKM_SHA256_RSA_PKCS:
  case CKM_SHA384_RSA_PKCS:
  case CKM_SHA512_RSA_PKCS:
  case CKM_SHA224_RSA_PKCS:
  case CKM_SHA3_256_RSA_PKCS:
  case CKM_SHA3_384_RSA_PKCS:
  case CKM_SHA3_512_RSA_PKCS:
    if (algorithm_type != PIV_ALG_RSA_2048 && algorithm_type != PIV_ALG_RSA_3072 && algorithm_type != PIV_ALG_RSA_4096)
      CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "key is not RSA");
    break;

  default:
    CNK_RETURN(CKR_MECHANISM_INVALID, "unsupported mechanism");
  }

  // Store the key handle, mechanism, and validated info in the session for C_Sign
  session->active_key = hKey;
  session->active_mechanism_ptr = pMechanism;
  session->active_key_piv_tag = piv_tag;
  session->active_key_algorithm_type = algorithm_type;

  CNK_DEBUG("Setting active_mechanism to %lu, PIV tag %u, algorithm type %u", pMechanism->mechanism, piv_tag,
            algorithm_type);

  CNK_RET_OK;
}

// Main C_Sign function
CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
             CK_ULONG_PTR pulSignatureLen) {
  CNK_LOG_FUNC(": hSession: %lu, ulDataLen: %lu, pSignature: %p, pulSignatureLen: %p", hSession, ulDataLen, pSignature,
               pulSignatureLen);

  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pulSignatureLen);

  // Parameter validation
  if (!pData && ulDataLen > 0)
    CNK_RETURN(CKR_ARGUMENTS_BAD, "pData is NULL but ulDataLen > 0");

  // Validate the session
  CNK_PKCS11_SESSION *session;
  CK_RV rv = CNK_ENSURE_OK(cnk_session_find(hSession, &session));

  // Verify that we have an active key and mechanism
  if (session->active_key == 0)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_SignInit not called - no active key");

  if (session->active_mechanism_ptr == NULL)
    CNK_RETURN(CKR_OPERATION_NOT_INITIALIZED, "C_SignInit not called - no active mechanism");

  // All key validation was already done in C_SignInit, so we use the cached values
  CK_BYTE piv_tag = session->active_key_piv_tag;
  CK_BYTE algorithm_type = session->active_key_algorithm_type;
  CK_MECHANISM_PTR mechanism_ptr = session->active_mechanism_ptr;

  CNK_DEBUG("Signing with active key, PIV tag %u, algorithm type %u", piv_tag, algorithm_type);

  // For signature-only call to get the signature length
  if (pSignature == NULL) {
    switch (algorithm_type) {
    case PIV_ALG_RSA_2048:
      *pulSignatureLen = 256; // 2048 bits = 256 bytes
      break;
    case PIV_ALG_RSA_3072:
      *pulSignatureLen = 384; // 3072 bits = 384 bytes
      break;
    case PIV_ALG_RSA_4096:
      *pulSignatureLen = 512; // 4096 bits = 512 bytes
      break;
    default:
      CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "unsupported key algorithm");
    }

    // We don't need to reset the session state here since we're just querying the length
    CNK_RET_OK;
  }

  // Prepare data for RSA signing (add padding, etc.)
  CK_BYTE prepared_data[512]; // Max RSA key size (4096 bits = 512 bytes)
  CK_ULONG prepared_data_len = sizeof(prepared_data);

  rv = cnk_prepare_rsa_sign_data(mechanism_ptr, pData, ulDataLen, session->active_key_modulus,
                                 session->active_key_modulus_len, algorithm_type, prepared_data, &prepared_data_len);
  if (rv != CKR_OK) {
    // Reset the session state
    session->active_mechanism_ptr = NULL;
    session->active_key = 0;
    session->active_key_piv_tag = 0;
    session->active_key_algorithm_type = 0;
    return rv;
  }

  // Now pass the prepared data to the PIV sign function
  rv = cnk_piv_sign(session->slot_id, session, piv_tag, prepared_data, prepared_data_len, pSignature, pulSignatureLen);

  // Reset the active mechanism and related fields to indicate operation is complete
  session->active_mechanism_ptr = NULL;
  session->active_key = 0;
  session->active_key_piv_tag = 0;
  session->active_key_algorithm_type = 0;

  return rv;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pPart: %p, ulPartLen: %lu", hSession, pPart, ulPartLen);
  CNK_RET_UNIMPL;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
  CNK_LOG_FUNC(": hSession: %lu, pSignature: %p, pulSignatureLen: %p", hSession, pSignature, pulSignatureLen);
  CNK_RET_UNIMPL;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, hKey: %lu", hSession, pMechanism, hKey);
  CNK_RET_UNIMPL;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                    CK_ULONG_PTR pulSignatureLen) {
  CNK_LOG_FUNC(": hSession: %lu, pData: %p, ulDataLen: %lu, pSignature: %p, pulSignatureLen: %p", hSession, pData,
               ulDataLen, pSignature, pulSignatureLen);
  CNK_RET_UNIMPL;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, hKey: %lu", hSession, pMechanism, hKey);
  CNK_RET_UNIMPL;
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
               CK_ULONG ulSignatureLen) {
  CNK_LOG_FUNC(": hSession: %lu, pData: %p, ulDataLen: %lu, pSignature: %p, ulSignatureLen: %lu", hSession, pData,
               ulDataLen, pSignature, ulSignatureLen);
  CNK_RET_UNIMPL;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  CNK_LOG_FUNC(": hSession: %lu, pPart: %p, ulPartLen: %lu", hSession, pPart, ulPartLen);
  CNK_RET_UNIMPL;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
  CNK_LOG_FUNC(": hSession: %lu, pSignature: %p, ulSignatureLen: %lu", hSession, pSignature, ulSignatureLen);
  CNK_RET_UNIMPL;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, hKey: %lu", hSession, pMechanism, hKey);
  CNK_RET_UNIMPL;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData,
                      CK_ULONG_PTR pulDataLen) {
  CNK_LOG_FUNC(": hSession: %lu, pSignature: %p, ulSignatureLen: %lu, pData: %p, pulDataLen: %p", hSession, pSignature,
               ulSignatureLen, pData, pulDataLen);
  CNK_RET_UNIMPL;
}
