#include "logging.h"
#include "pcsc_backend.h"
#include "pkcs11.h"
#include "pkcs11_macros.h"
#include "pkcs11_object.h"
#include "pkcs11_session.h"
#include "rsa_utils.h"
#include "utils.h"

#include <string.h>

static const CK_MECHANISM_TYPE rsaMechs[] = {
    CKM_RSA_PKCS,          CKM_RSA_X_509,           CKM_RSA_PKCS_OAEP,     CKM_RSA_PKCS_PSS,
    CKM_SHA1_RSA_PKCS,     CKM_SHA1_RSA_PKCS_PSS,   CKM_SHA256_RSA_PKCS,   CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA384_RSA_PKCS,   CKM_SHA384_RSA_PKCS_PSS, CKM_SHA512_RSA_PKCS,   CKM_SHA512_RSA_PKCS_PSS,
    CKM_SHA224_RSA_PKCS,   CKM_SHA224_RSA_PKCS_PSS, CKM_SHA3_256_RSA_PKCS, CKM_SHA3_384_RSA_PKCS,
    CKM_SHA3_512_RSA_PKCS,
};

static const CK_MECHANISM_TYPE rsaPssMechs[] = {
    CKM_RSA_PKCS_PSS,          CKM_SHA1_RSA_PKCS_PSS,     CKM_SHA224_RSA_PKCS_PSS,   CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA384_RSA_PKCS_PSS,   CKM_SHA512_RSA_PKCS_PSS,   CKM_SHA3_224_RSA_PKCS_PSS, CKM_SHA3_256_RSA_PKCS_PSS,
    CKM_SHA3_384_RSA_PKCS_PSS, CKM_SHA3_512_RSA_PKCS_PSS,
};

static const CK_MECHANISM_TYPE ecMechs[] = {
    CKM_ECDSA,        CKM_ECDSA_SHA1,     CKM_ECDSA_SHA224,   CKM_ECDSA_SHA256,   CKM_ECDSA_SHA384,
    CKM_ECDSA_SHA512, CKM_ECDSA_SHA3_224, CKM_ECDSA_SHA3_256, CKM_ECDSA_SHA3_384, CKM_ECDSA_SHA3_512,
};

static CK_BBOOL mechInList(CK_MECHANISM_TYPE m, const CK_MECHANISM_TYPE *list, CK_ULONG len) {
  for (CK_ULONG i = 0; i < len; ++i)
    if (list[i] == m)
      return CK_TRUE;
  return CK_FALSE;
}

static inline CK_BBOOL isMechRSA(CK_MECHANISM_TYPE m) {
  return mechInList(m, rsaMechs, sizeof(rsaMechs) / sizeof(rsaMechs[0]));
}

static inline CK_BBOOL isMechRsaPss(CK_MECHANISM_TYPE m) {
  return mechInList(m, rsaPssMechs, sizeof(rsaPssMechs) / sizeof(rsaPssMechs[0]));
}

static inline CK_BBOOL isMechEC(CK_MECHANISM_TYPE m) {
  return mechInList(m, ecMechs, sizeof(ecMechs) / sizeof(ecMechs[0]));
}

static CK_RV validateRsaPssParams(const CK_MECHANISM *m) {
  // Check if parameters are provided
  if (m->pParameter == NULL || m->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS))
    CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad PSS param pointer/len");

  const CK_RSA_PKCS_PSS_PARAMS *p = (const CK_RSA_PKCS_PSS_PARAMS *)m->pParameter;

  // Validate parameters based on mechanism
  switch (m->mechanism) {
  case CKM_SHA1_RSA_PKCS_PSS:
    if (p->hashAlg != CKM_SHA_1 || p->mgf != CKG_MGF1_SHA1)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad PSS param: hashAlg or mgf");
    break;
  case CKM_SHA224_RSA_PKCS_PSS:
    if (p->hashAlg != CKM_SHA224 || p->mgf != CKG_MGF1_SHA224)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad PSS param: hashAlg or mgf");
    break;
  case CKM_SHA256_RSA_PKCS_PSS:
    if (p->hashAlg != CKM_SHA256 || p->mgf != CKG_MGF1_SHA256)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad PSS param: hashAlg or mgf");
    break;
  case CKM_SHA384_RSA_PKCS_PSS:
    if (p->hashAlg != CKM_SHA384 || p->mgf != CKG_MGF1_SHA384)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad PSS param: hashAlg or mgf");
    break;
  case CKM_SHA512_RSA_PKCS_PSS:
    if (p->hashAlg != CKM_SHA512 || p->mgf != CKG_MGF1_SHA512)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad PSS param: hashAlg or mgf");
    break;
  case CKM_SHA3_224_RSA_PKCS_PSS:
    if (p->hashAlg != CKM_SHA3_224 || p->mgf != CKG_MGF1_SHA3_224)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad PSS param: hashAlg or mgf");
    break;
  case CKM_SHA3_256_RSA_PKCS_PSS:
    if (p->hashAlg != CKM_SHA3_256 || p->mgf != CKG_MGF1_SHA3_256)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad PSS param: hashAlg or mgf");
    break;
  case CKM_SHA3_384_RSA_PKCS_PSS:
    if (p->hashAlg != CKM_SHA3_384 || p->mgf != CKG_MGF1_SHA3_384)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad PSS param: hashAlg or mgf");
    break;
  case CKM_SHA3_512_RSA_PKCS_PSS:
    if (p->hashAlg != CKM_SHA3_512 || p->mgf != CKG_MGF1_SHA3_512)
      CNK_RETURN(CKR_MECHANISM_PARAM_INVALID, "bad PSS param: hashAlg or mgf");
    break;
  default:
    // CKM_RSA_PKCS_PSS: hashAlg and mgf are not used
    break;
  }

  return CKR_OK;
}

static CK_RV validateRsaMech(CNK_PKCS11_SESSION *session, const CK_MECHANISM *m, CK_BYTE algorithmType,
                             const CK_BYTE *abPublicKey, CK_ULONG cbPublicKey) {
  if (algorithmType != PIV_ALG_RSA_2048 && algorithmType != PIV_ALG_RSA_3072 && algorithmType != PIV_ALG_RSA_4096)
    CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "key is not RSA");

  if (isMechRsaPss(m->mechanism))
    CNK_ENSURE_OK(validateRsaPssParams(m));

  // Get modulus
  session->active_key_modulus_len = 0;

  CK_ULONG vpos = 0;
  while (vpos < cbPublicKey) {
    CK_BYTE itag = abPublicKey[vpos++];
    if (vpos >= cbPublicKey)
      break;
    CK_LONG fail;
    CK_ULONG lengthSize;
    CK_ULONG ilen = tlv_get_length_safe(&abPublicKey[vpos], cbPublicKey - vpos, &fail, &lengthSize);
    if (fail)
      CNK_RETURN(CKR_DEVICE_ERROR, "Bad length in public-key TLV");
    vpos += lengthSize;

    // RSA modulus lives in tag 0x81
    if (itag == 0x81) {
      memcpy(session->active_key_modulus, abPublicKey + vpos, ilen);
      session->active_key_modulus_len = ilen;
      break;
    }

    vpos += ilen;
  }

  CNK_DEBUG("Modulus length: %lu", session->active_key_modulus_len);

  if (session->active_key_modulus_len == 0)
    CNK_RETURN(CKR_DEVICE_ERROR, "Modulus not found in public key");

  return CKR_OK;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  CNK_LOG_FUNC(": hSession: %lu, pMechanism: %p, hKey: %lu", hSession, pMechanism, hKey);

  PKCS11_VALIDATE_INITIALIZED_AND_ARGUMENT(pMechanism);

  // Find the session, validate the key object, and map object ID to PIV tag
  CNK_PKCS11_SESSION *session;
  CK_BYTE obj_id;
  CK_BYTE piv_tag;
  CNK_ENSURE_OK(cnk_session_find(hSession, &session));
  CNK_ENSURE_OK(cnk_validate_object(hKey, session, CKO_PRIVATE_KEY, &obj_id));
  CNK_ENSURE_OK(C_CNK_ObjIdToPivTag(obj_id, &piv_tag));

  // Get metadata
  CK_BYTE algorithmType;
  CK_BYTE abPublicKey[512];
  CK_ULONG cbPublicKey = sizeof(abPublicKey);
  CNK_ENSURE_OK(cnk_get_metadata(session->slot_id, piv_tag, &algorithmType, abPublicKey, &cbPublicKey));

  if (isMechRSA(pMechanism->mechanism))
    CNK_ENSURE_OK(validateRsaMech(session, pMechanism, algorithmType, abPublicKey, cbPublicKey));
  else if (!isMechEC(pMechanism->mechanism))
    CNK_RETURN(CKR_MECHANISM_INVALID, "Invalid mechanism");

  // Store the key handle, mechanism, and validated info in the session for C_Sign
  session->active_key = hKey;
  session->active_mechanism_ptr = pMechanism;
  session->active_key_piv_tag = piv_tag;

  CNK_DEBUG("Setting active_mechanism to %lu, PIV tag %u, algorithm type %u", pMechanism->mechanism, piv_tag,
            algorithmType);

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
  CK_MECHANISM_PTR mechanism_ptr = session->active_mechanism_ptr;

  CNK_DEBUG("Signing with active key, PIV tag 0x%x", piv_tag);

  // For signature-only call to get the signature length
  if (pSignature == NULL) {
    if (isMechRSA(session->active_mechanism_ptr->mechanism)) {
      *pulSignatureLen = session->active_key_modulus_len;
    } else
      CNK_RETURN(CKR_KEY_TYPE_INCONSISTENT, "unsupported key algorithm");

    // We don't need to reset the session state here since we're just querying the length
    CNK_RET_OK;
  }

  // Prepare data for RSA signing (add padding, etc.)
  CK_BYTE prepared_data[512]; // Max RSA key size (4096 bits = 512 bytes)
  CK_ULONG prepared_data_len = sizeof(prepared_data);

  rv = cnk_prepare_rsa_sign_data(mechanism_ptr, pData, ulDataLen, session->active_key_modulus,
                                 session->active_key_modulus_len, prepared_data, &prepared_data_len);
  if (rv != CKR_OK) {
    // Reset the session state
    session->active_mechanism_ptr = NULL;
    session->active_key = 0;
    session->active_key_piv_tag = 0;
    return rv;
  }

  // Now pass the prepared data to the PIV sign function
  rv = cnk_piv_sign(session->slot_id, session, piv_tag, prepared_data, prepared_data_len, pSignature, pulSignatureLen);

  // Reset the active mechanism and related fields to indicate operation is complete
  session->active_mechanism_ptr = NULL;
  session->active_key = 0;
  session->active_key_piv_tag = 0;

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
