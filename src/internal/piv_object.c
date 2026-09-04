#include "internal/piv_object.h"

#include "api/object.h"
#include "backend/pcsc.h"
#include "internal/macros.h"
#include "internal/template.h"
#include "internal/util.h"

#include <mbedtls/platform_util.h>
#include <string.h>

#define CNK_MAX_PIV_CERTIFICATE_OBJECT_SIZE 8192

static CK_RV writeTlvLength(CK_BYTE *buffer, CK_ULONG bufferLen, CK_ULONG length, CK_ULONG_PTR written) {
  CNK_ENSURE_NONNULL(buffer, written);
  if (length < 0x80) {
    if (bufferLen < 1)
      return CKR_BUFFER_TOO_SMALL;
    buffer[0] = (CK_BYTE)length;
    *written = 1;
  } else if (length <= 0xFF) {
    if (bufferLen < 2)
      return CKR_BUFFER_TOO_SMALL;
    buffer[0] = 0x81;
    buffer[1] = (CK_BYTE)length;
    *written = 2;
  } else if (length <= 0xFFFF) {
    if (bufferLen < 3)
      return CKR_BUFFER_TOO_SMALL;
    buffer[0] = 0x82;
    buffer[1] = (CK_BYTE)(length >> 8);
    buffer[2] = (CK_BYTE)length;
    *written = 3;
  } else {
    return CKR_DATA_LEN_RANGE;
  }
  return CKR_OK;
}

static CK_RV appendTlv(CK_BYTE *buffer, CK_ULONG bufferLen, CK_ULONG_PTR offset, CK_BYTE tag, const CK_BYTE *value,
                       CK_ULONG valueLen) {
  CNK_ENSURE_NONNULL(buffer, offset);
  if (valueLen > 0)
    CNK_ENSURE_NONNULL(value);
  if (*offset >= bufferLen)
    return CKR_BUFFER_TOO_SMALL;
  buffer[(*offset)++] = tag;

  CK_ULONG lengthSize;
  CK_RV rv = writeTlvLength(buffer + *offset, bufferLen - *offset, valueLen, &lengthSize);
  if (rv != CKR_OK)
    return rv;
  *offset += lengthSize;
  if (bufferLen - *offset < valueLen)
    return CKR_BUFFER_TOO_SMALL;
  if (valueLen > 0)
    memcpy(buffer + *offset, value, valueLen);
  *offset += valueLen;
  return CKR_OK;
}

static CK_RV appendImportAttribute(CK_BYTE *buffer, CK_ULONG bufferLen, CK_ULONG_PTR offset, CK_BYTE tag,
                                   CK_ATTRIBUTE_PTR attribute) {
  CNK_ENSURE_NONNULL(attribute);
  if (attribute->pValue == NULL || attribute->ulValueLen == 0 || attribute->ulValueLen > 0xFFFF)
    return CKR_ATTRIBUTE_VALUE_INVALID;
  return appendTlv(buffer, bufferLen, offset, tag, attribute->pValue, attribute->ulValueLen);
}

static CK_RV appendPaddedImportAttribute(CK_BYTE *buffer, CK_ULONG bufferLen, CK_ULONG_PTR offset, CK_BYTE tag,
                                         CK_ATTRIBUTE_PTR attribute, CK_ULONG width) {
  CNK_ENSURE_NONNULL(attribute);
  if (attribute->pValue == NULL || attribute->ulValueLen == 0 || attribute->ulValueLen > width)
    return CKR_ATTRIBUTE_VALUE_INVALID;
  if (*offset >= bufferLen)
    return CKR_BUFFER_TOO_SMALL;
  buffer[(*offset)++] = tag;
  CK_ULONG lengthSize;
  CK_RV rv = writeTlvLength(buffer + *offset, bufferLen - *offset, width, &lengthSize);
  if (rv != CKR_OK)
    return rv;
  *offset += lengthSize;
  if (bufferLen - *offset < width)
    return CKR_BUFFER_TOO_SMALL;
  memset(buffer + *offset, 0, width);
  memcpy(buffer + *offset + width - attribute->ulValueLen, attribute->pValue, attribute->ulValueLen);
  *offset += width;
  return CKR_OK;
}

static CK_RV rsaComponentSizeToAlgorithm(CK_ULONG componentLen, CK_BYTE *algorithmType) {
  CNK_ENSURE_NONNULL(algorithmType);
  switch (componentLen) {
  case 128:
    *algorithmType = PIV_ALG_RSA_2048;
    return CKR_OK;
  case 192:
    *algorithmType = PIV_ALG_RSA_3072;
    return CKR_OK;
  case 256:
    *algorithmType = PIV_ALG_RSA_4096;
    return CKR_OK;
  default:
    return CKR_KEY_SIZE_RANGE;
  }
}

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

static CK_RV appendPolicies(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_BYTE objectId, CK_BYTE *output,
                            CK_ULONG outputLen, CK_ULONG_PTR offset) {
  CK_BYTE pinPolicy;
  CK_BYTE touchPolicy;
  CK_RV rv = CNK_GetPivPolicies(attributes, attributeCount, CNK_DefaultPinPolicyForPivObjectId(objectId), &pinPolicy,
                                &touchPolicy);
  if (rv != CKR_OK)
    return rv;
  rv = appendTlv(output, outputLen, offset, 0xAA, &pinPolicy, sizeof(pinPolicy));
  if (rv != CKR_OK)
    return rv;
  return appendTlv(output, outputLen, offset, 0xAB, &touchPolicy, sizeof(touchPolicy));
}

CK_RV cnk_build_piv_certificate_object(CK_BYTE_PTR certificate, CK_ULONG certificateLen, CK_BYTE *output,
                                       CK_ULONG outputLen, CK_ULONG_PTR written) {
  CNK_ENSURE_NONNULL(certificate, output, written);
  CK_BYTE inner[CNK_MAX_PIV_CERTIFICATE_OBJECT_SIZE];
  CK_ULONG innerLen = 0;
  CK_BYTE certInfo = 0;

  CK_RV rv = appendTlv(inner, sizeof(inner), &innerLen, 0x70, certificate, certificateLen);
  if (rv == CKR_OK)
    rv = appendTlv(inner, sizeof(inner), &innerLen, 0x71, &certInfo, sizeof(certInfo));
  if (rv == CKR_OK)
    rv = appendTlv(inner, sizeof(inner), &innerLen, 0xFE, NULL, 0);
  CK_ULONG offset = 0;
  if (rv == CKR_OK)
    rv = appendTlv(output, outputLen, &offset, 0x53, inner, innerLen);
  if (rv == CKR_OK)
    *written = offset;
  return rv;
}

CK_RV cnk_build_piv_rsa_import(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_BYTE objectId, CK_BYTE *output,
                               CK_ULONG outputLen, CK_ULONG_PTR written, CK_BYTE *algorithmType) {
  CK_ATTRIBUTE_PTR components[5];
  static const CK_ATTRIBUTE_TYPE types[] = {
      CKA_PRIME_1, CKA_PRIME_2, CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_COEFFICIENT,
  };
  CNK_ENSURE_NONNULL(output, written, algorithmType);
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
  // Firmware accepts fixed-width CRT values with at most one omitted leading
  // zero byte. Reject shorter primes instead of silently padding malformed
  // RSA components into a supported slot size.
  for (CK_ULONG i = 0; i < 2; i++) {
    if (components[i]->ulValueLen != primeWidth && (primeWidth == 0 || components[i]->ulValueLen != primeWidth - 1))
      return CKR_KEY_SIZE_RANGE;
  }
  CK_RV rv = rsaComponentSizeToAlgorithm(componentWidth, algorithmType);
  CK_ULONG offset = 0;
  for (CK_ULONG i = 0; rv == CKR_OK && i < 5; i++)
    rv = appendPaddedImportAttribute(output, outputLen, &offset, (CK_BYTE)(i + 1), components[i], componentWidth);
  if (rv == CKR_OK)
    rv = appendPolicies(attributes, attributeCount, objectId, output, outputLen, &offset);
  if (rv == CKR_OK)
    *written = offset;
  return rv;
}

CK_RV cnk_build_piv_ec_import(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_BYTE objectId, CK_BYTE *output,
                              CK_ULONG outputLen, CK_ULONG_PTR written, CK_BYTE *algorithmType) {
  CK_ATTRIBUTE_PTR paramsAttribute;
  CK_ATTRIBUTE_PTR valueAttribute;
  CNK_ENSURE_NONNULL(output, written, algorithmType);
  CK_RV rv = cnk_template_get_attribute(attributes, attributeCount, CKA_EC_PARAMS, &paramsAttribute);
  if (rv == CKR_OK)
    rv = cnk_template_get_attribute(attributes, attributeCount, CKA_VALUE, &valueAttribute);
  if (rv != CKR_OK)
    return rv;
  if (paramsAttribute->pValue == NULL || paramsAttribute->ulValueLen == 0 || valueAttribute->pValue == NULL ||
      valueAttribute->ulValueLen == 0)
    return CKR_ATTRIBUTE_VALUE_INVALID;
  rv = cnk_ec_params_to_piv_algorithm(paramsAttribute->pValue, paramsAttribute->ulValueLen, algorithmType);
  if (rv != CKR_OK)
    return rv;
  CK_ULONG expectedLen;
  switch (*algorithmType) {
  case PIV_ALG_ECC_256:
  case PIV_ALG_SECP256K1:
    expectedLen = 32;
    break;
  case PIV_ALG_ECC_384:
    expectedLen = 48;
    break;
  case PIV_ALG_ECC_521:
    expectedLen = 66;
    break;
  case PIV_ALG_SM2:
    expectedLen = 32;
    break;
  default:
    return CKR_ATTRIBUTE_VALUE_INVALID;
  }
  if (valueAttribute->ulValueLen == 0 || valueAttribute->ulValueLen > expectedLen)
    return CKR_ATTRIBUTE_VALUE_INVALID;

  CK_ULONG offset = 0;
  rv = appendPaddedImportAttribute(output, outputLen, &offset, 0x06, valueAttribute, expectedLen);
  if (rv == CKR_OK)
    rv = appendPolicies(attributes, attributeCount, objectId, output, outputLen, &offset);
  if (rv == CKR_OK)
    *written = offset;
  return rv;
}

CK_RV cnk_build_piv_25519_import(CNK_PKCS11_SESSION *session, CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount,
                                 CK_BYTE objectId, CK_KEY_TYPE keyType, CK_BYTE *output, CK_ULONG outputLen,
                                 CK_ULONG_PTR written, CK_BYTE *algorithmType) {
  CNK_ENSURE_NONNULL(session, output, written, algorithmType);
  if (keyType != CKK_EC_EDWARDS && keyType != CKK_EC_MONTGOMERY)
    return CKR_KEY_TYPE_INCONSISTENT;

  CK_ATTRIBUTE_PTR valueAttribute;
  CK_ATTRIBUTE_PTR paramsAttribute;
  CNK_ENSURE_OK(cnk_template_get_attribute(attributes, attributeCount, CKA_VALUE, &valueAttribute));
  CNK_ENSURE_OK(cnk_template_get_attribute(attributes, attributeCount, CKA_EC_PARAMS, &paramsAttribute));
  if (valueAttribute->pValue == NULL || valueAttribute->ulValueLen != 32)
    return CKR_ATTRIBUTE_VALUE_INVALID;

  CK_BYTE namedAlgorithm;
  CNK_ENSURE_OK(cnk_ec_params_to_piv_algorithm(paramsAttribute->pValue, paramsAttribute->ulValueLen, &namedAlgorithm));
  if (keyType == CKK_EC_EDWARDS && namedAlgorithm == PIV_ALG_ED25519)
    *algorithmType = session->ed25519Algorithm;
  else if (keyType == CKK_EC_MONTGOMERY && namedAlgorithm == PIV_ALG_X25519)
    *algorithmType = session->x25519Algorithm;
  else
    return CKR_TEMPLATE_INCONSISTENT;
  if (*algorithmType == 0)
    return CKR_MECHANISM_INVALID;

  CK_BYTE privateValue[32];
  memcpy(privateValue, valueAttribute->pValue, sizeof(privateValue));
  CK_BYTE tag = keyType == CKK_EC_EDWARDS ? 0x07 : 0x08;
  // The X25519 import tag and PKCS#11 both use RFC 7748 little-endian bytes;
  // firmware performs the conversion to its internal big-endian key form.

  CK_ULONG offset = 0;
  CK_RV rv = appendTlv(output, outputLen, &offset, tag, privateValue, sizeof(privateValue));
  if (rv == CKR_OK)
    rv = appendPolicies(attributes, attributeCount, objectId, output, outputLen, &offset);
  mbedtls_platform_zeroize(privateValue, sizeof(privateValue));
  if (rv == CKR_OK)
    *written = offset;
  return rv;
}

CK_RV cnk_build_piv_pqc_import(CNK_PKCS11_SESSION *session, CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount,
                               CK_BYTE objectId, CK_KEY_TYPE keyType, CK_BYTE *output, CK_ULONG outputLen,
                               CK_ULONG_PTR written, CK_BYTE *algorithmType) {
  CK_ATTRIBUTE_PTR parameterSetAttribute;
  CK_ATTRIBUTE_PTR seedAttribute;
  CNK_ENSURE_NONNULL(session, output, written, algorithmType);
  CK_RV rv = cnk_template_get_attribute(attributes, attributeCount, CKA_PARAMETER_SET, &parameterSetAttribute);
  if (rv == CKR_OK)
    rv = cnk_template_get_attribute(attributes, attributeCount, CKA_SEED, &seedAttribute);
  if (rv != CKR_OK)
    return rv;
  if (parameterSetAttribute->pValue == NULL || parameterSetAttribute->ulValueLen != sizeof(CK_ULONG) ||
      seedAttribute->pValue == NULL)
    return CKR_ATTRIBUTE_VALUE_INVALID;

  CK_ULONG expectedParameterSet;
  CK_ULONG expectedSeedLen;
  CK_BYTE componentTag;
  if (keyType == CKK_ML_DSA) {
    expectedParameterSet = CKP_ML_DSA_65;
    expectedSeedLen = 32;
    componentTag = 0x09;
    *algorithmType = session->mldsa65Algorithm;
  } else if (keyType == CKK_ML_KEM) {
    expectedParameterSet = CKP_ML_KEM_768;
    expectedSeedLen = 64;
    componentTag = 0x0A;
    *algorithmType = session->mlkem768Algorithm;
  } else {
    return CKR_KEY_TYPE_INCONSISTENT;
  }
  if (*(CK_ULONG *)parameterSetAttribute->pValue != expectedParameterSet ||
      seedAttribute->ulValueLen != expectedSeedLen)
    return CKR_ATTRIBUTE_VALUE_INVALID;

  CK_ULONG offset = 0;
  rv = appendImportAttribute(output, outputLen, &offset, componentTag, seedAttribute);
  if (rv == CKR_OK)
    rv = appendPolicies(attributes, attributeCount, objectId, output, outputLen, &offset);
  if (rv == CKR_OK)
    *written = offset;
  return rv;
}
