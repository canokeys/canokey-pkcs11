#include "internal/piv_object.h"

#include "api/object.h"
#include "backend/pcsc.h"
#include "internal/macros.h"
#include "internal/template.h"
#include "internal/util.h"

#include <string.h>

static CK_ULONG rsaWidthFromModulusLength(CK_ULONG modulusLen) {
  if (modulusLen == 255 || modulusLen == 256)
    return 128;
  if (modulusLen == 383 || modulusLen == 384)
    return 192;
  if (modulusLen == 511 || modulusLen == 512)
    return 256;
  return 0;
}

static CK_ULONG rsaWidthFromPrimeLength(CK_ULONG primeLen) {
  if (primeLen == 127 || primeLen == 128)
    return 128;
  if (primeLen == 191 || primeLen == 192)
    return 192;
  if (primeLen == 255 || primeLen == 256)
    return 256;
  return 0;
}

static CK_RV prepareRsaImport(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CNK_PIV_IMPORT *material) {
  CK_ATTRIBUTE_PTR components[5];
  static const CK_ATTRIBUTE_TYPE types[] = {
      CKA_PRIME_1, CKA_PRIME_2, CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_COEFFICIENT,
  };
  CK_ULONG maxPrimeLen = 0;
  for (CK_ULONG i = 0; i < 5; i++) {
    CK_RV rv = cnk_template_get_attribute(attributes, attributeCount, types[i], &components[i]);
    if (rv != CKR_OK)
      return rv;
    if (components[i]->pValue == NULL)
      return CKR_ATTRIBUTE_VALUE_INVALID;
    if (i < 2 && components[i]->ulValueLen > maxPrimeLen)
      maxPrimeLen = components[i]->ulValueLen;
  }

  CK_ATTRIBUTE_PTR modulus = NULL;
  CNK_ENSURE_OK(cnk_template_find_attribute(attributes, attributeCount, CKA_MODULUS, &modulus));
  CK_ULONG componentWidth = 0;
  if (modulus != NULL && (modulus->pValue == NULL || modulus->ulValueLen == 0))
    return CKR_ATTRIBUTE_VALUE_INVALID;
  if (modulus != NULL) {
    componentWidth = rsaWidthFromModulusLength(modulus->ulValueLen);
    if (componentWidth == 0)
      return CKR_KEY_SIZE_RANGE;
  } else {
    componentWidth = rsaWidthFromPrimeLength(maxPrimeLen);
  }
  if (componentWidth == 0 || maxPrimeLen > componentWidth)
    return CKR_KEY_SIZE_RANGE;
  CK_ULONG primeWidth = componentWidth;
  // Keep the PKCS#11 size-inference rule: a prime may omit one leading zero
  // byte, but shorter values must not select a larger RSA size implicitly.
  for (CK_ULONG i = 0; i < 2; i++) {
    if (components[i]->ulValueLen != primeWidth && (primeWidth == 0 || components[i]->ulValueLen != primeWidth - 1))
      return CKR_KEY_SIZE_RANGE;
  }
  switch (componentWidth) {
  case 128:
    material->parameters.algorithm = CNK_LIBCANO_ALG_RSA_2048;
    break;
  case 192:
    material->parameters.algorithm = CNK_LIBCANO_ALG_RSA_3072;
    break;
  case 256:
    material->parameters.algorithm = CNK_LIBCANO_ALG_RSA_4096;
    break;
  default:
    return CKR_KEY_SIZE_RANGE;
  }
  for (size_t i = 0; i < 5; ++i) {
    if (components[i]->ulValueLen == 0 || components[i]->ulValueLen > componentWidth)
      return CKR_ATTRIBUTE_VALUE_INVALID;
    material->components[i] = (CNK_LIBCANO_BYTES){components[i]->pValue, components[i]->ulValueLen};
  }
  // The Rust constructor copies and pads CRT components; C only checks the
  // PKCS#11 template's modulus/prime width convention.
  material->count = 5;
  return CKR_OK;
}

CK_RV cnk_prepare_piv_import(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_BYTE objectId,
                             CK_KEY_TYPE keyType, CNK_PIV_IMPORT *material) {
  CNK_ENSURE_NONNULL(material);
  if (keyType != CKK_RSA && keyType != CKK_EC && keyType != CKK_EC_EDWARDS && keyType != CKK_EC_MONTGOMERY &&
      keyType != CKK_ML_DSA && keyType != CKK_ML_KEM)
    return CKR_KEY_TYPE_INCONSISTENT;
  memset(material, 0, sizeof(*material));
  material->parameters.struct_size = sizeof(material->parameters);
  CK_BYTE pivSlot, pinPolicy, touchPolicy;
  uint32_t canonical = 0;
  CNK_ENSURE_OK(C_CNK_ObjIdToPivTag(objectId, &pivSlot));
  CNK_ENSURE_OK(CNK_GetPivPolicies(attributes, attributeCount, CNK_DefaultPinPolicyForPivObjectId(objectId), &pinPolicy,
                                   &touchPolicy));
  material->parameters.slot = pivSlot;
  material->parameters.pin_policy = pinPolicy;
  material->parameters.touch_policy = touchPolicy;
  if (keyType == CKK_RSA) {
    CNK_ENSURE_OK(prepareRsaImport(attributes, attributeCount, material));
  } else {
    CK_ATTRIBUTE_PTR value, params;
    CK_BBOOL pqc = keyType == CKK_ML_DSA || keyType == CKK_ML_KEM;
    CNK_ENSURE_OK(cnk_template_get_attribute(attributes, attributeCount, pqc ? CKA_SEED : CKA_VALUE, &value));
    CNK_ENSURE_OK(
        cnk_template_get_attribute(attributes, attributeCount, pqc ? CKA_PARAMETER_SET : CKA_EC_PARAMS, &params));
    if (value->pValue == NULL || value->ulValueLen == 0 || params->pValue == NULL || params->ulValueLen == 0)
      return CKR_ATTRIBUTE_VALUE_INVALID;
    size_t width = 0;
    if (pqc) {
      if (params->ulValueLen != sizeof(CK_ULONG))
        return CKR_ATTRIBUTE_VALUE_INVALID;
      CK_ULONG parameterSet;
      memcpy(&parameterSet, params->pValue, sizeof(parameterSet));
      if (parameterSet != (keyType == CKK_ML_DSA ? CKP_ML_DSA_65 : CKP_ML_KEM_768))
        return CKR_ATTRIBUTE_VALUE_INVALID;
      material->parameters.algorithm = keyType == CKK_ML_DSA ? CNK_LIBCANO_ALG_MLDSA65 : CNK_LIBCANO_ALG_MLKEM768;
      width = keyType == CKK_ML_DSA ? 32 : 64;
    } else {
      CNK_ENSURE_OK(cnk_ec_params_to_piv_algorithm(params->pValue, params->ulValueLen, &canonical));
      material->parameters.algorithm = canonical;
      if (keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
        if (canonical != (keyType == CKK_EC_EDWARDS ? CNK_LIBCANO_ALG_ED25519 : CNK_LIBCANO_ALG_X25519))
          return CKR_TEMPLATE_INCONSISTENT;
        width = 32;
      } else if (keyType == CKK_EC) {
        switch (canonical) {
        case CNK_LIBCANO_ALG_P256:
          width = 32;
          break;
        case CNK_LIBCANO_ALG_P384:
          width = 48;
          break;
        case CNK_LIBCANO_ALG_P521:
          width = 66;
          break;
        case CNK_LIBCANO_ALG_SECP256K1:
          width = 32;
          break;
        case CNK_LIBCANO_ALG_SM2:
          width = 32;
          break;
        default:
          return CKR_ATTRIBUTE_VALUE_INVALID;
        }
      } else {
        return CKR_KEY_TYPE_INCONSISTENT;
      }
    }
    if (value->ulValueLen > width || (keyType != CKK_EC && value->ulValueLen != width))
      return CKR_ATTRIBUTE_VALUE_INVALID;
    material->count = 1;
    if (keyType == CKK_EC) {
      // PKCS#11 unsigned scalars may omit leading zeros; libcanokey accepts a
      // fixed-width scalar. The caller clears this sole temporary secret copy.
      memcpy(material->scalar + width - value->ulValueLen, value->pValue, value->ulValueLen);
      material->components[0] = (CNK_LIBCANO_BYTES){material->scalar, width};
    } else {
      material->components[0] = (CNK_LIBCANO_BYTES){value->pValue, value->ulValueLen};
    }
  }
  return CKR_OK;
}
