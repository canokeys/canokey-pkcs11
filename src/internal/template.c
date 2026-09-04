#include "internal/template.h"

#include "backend/pcsc.h"
#include "internal/macros.h"
#include "internal/util.h"

#include <string.h>

CK_RV cnk_template_get_attribute(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_ATTRIBUTE_TYPE type,
                                 CK_ATTRIBUTE_PTR *attribute) {
  CNK_ENSURE_NONNULL(attribute);
  *attribute = NULL;
  for (CK_ULONG i = 0; i < attributeCount; i++) {
    if (attributes[i].type == type) {
      *attribute = &attributes[i];
      return CKR_OK;
    }
  }
  return CKR_TEMPLATE_INCOMPLETE;
}

CK_RV cnk_template_find_attribute(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_ATTRIBUTE_TYPE type,
                                  CK_ATTRIBUTE_PTR *attribute) {
  CNK_ENSURE_NONNULL(attribute);
  *attribute = NULL;
  for (CK_ULONG i = 0; i < attributeCount; i++) {
    if (attributes[i].type == type) {
      *attribute = &attributes[i];
      break;
    }
  }
  return CKR_OK;
}

CK_RV cnk_attribute_get_bool(CK_ATTRIBUTE_PTR attribute, CK_BBOOL *value) {
  CNK_ENSURE_NONNULL(attribute, value);
  if (attribute->pValue == NULL || attribute->ulValueLen != sizeof(*value))
    return CKR_ATTRIBUTE_VALUE_INVALID;
  *value = *(CK_BBOOL *)attribute->pValue;
  if (*value != CK_FALSE && *value != CK_TRUE)
    return CKR_ATTRIBUTE_VALUE_INVALID;
  return CKR_OK;
}

CK_RV cnk_attribute_get_byte(CK_ATTRIBUTE_PTR attribute, CK_BYTE *value) {
  CNK_ENSURE_NONNULL(attribute, value);
  if (attribute->pValue == NULL || attribute->ulValueLen != sizeof(*value))
    return CKR_ATTRIBUTE_VALUE_INVALID;
  *value = *(CK_BYTE *)attribute->pValue;
  return CKR_OK;
}

CK_RV cnk_attribute_get_object_class(CK_ATTRIBUTE_PTR attribute, CK_OBJECT_CLASS *value) {
  CNK_ENSURE_NONNULL(attribute, value);
  if (attribute->pValue == NULL || attribute->ulValueLen != sizeof(*value))
    return CKR_ATTRIBUTE_VALUE_INVALID;
  *value = *(CK_OBJECT_CLASS *)attribute->pValue;
  return CKR_OK;
}

CK_RV cnk_attribute_get_key_type(CK_ATTRIBUTE_PTR attribute, CK_KEY_TYPE *value) {
  CNK_ENSURE_NONNULL(attribute, value);
  if (attribute->pValue == NULL || attribute->ulValueLen != sizeof(*value))
    return CKR_ATTRIBUTE_VALUE_INVALID;
  *value = *(CK_KEY_TYPE *)attribute->pValue;
  return CKR_OK;
}

CK_RV cnk_template_get_byte(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_ATTRIBUTE_TYPE type,
                            CK_BYTE *value) {
  CK_ATTRIBUTE_PTR attribute;
  CK_RV rv = cnk_template_get_attribute(attributes, attributeCount, type, &attribute);
  return rv == CKR_OK ? cnk_attribute_get_byte(attribute, value) : rv;
}

CK_RV cnk_template_get_object_class(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_ATTRIBUTE_TYPE type,
                                    CK_OBJECT_CLASS *value) {
  CK_ATTRIBUTE_PTR attribute;
  CK_RV rv = cnk_template_get_attribute(attributes, attributeCount, type, &attribute);
  return rv == CKR_OK ? cnk_attribute_get_object_class(attribute, value) : rv;
}

CK_RV cnk_template_get_key_type(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_ATTRIBUTE_TYPE type,
                                CK_KEY_TYPE *value) {
  CK_ATTRIBUTE_PTR attribute;
  CK_RV rv = cnk_template_get_attribute(attributes, attributeCount, type, &attribute);
  return rv == CKR_OK ? cnk_attribute_get_key_type(attribute, value) : rv;
}

CK_RV cnk_template_get_optional_bool(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_ATTRIBUTE_TYPE type,
                                     CK_BBOOL defaultValue, CK_BBOOL *value) {
  CK_ATTRIBUTE_PTR attribute;
  CNK_ENSURE_NONNULL(value);
  *value = defaultValue;
  CNK_ENSURE_OK(cnk_template_find_attribute(attributes, attributeCount, type, &attribute));
  return attribute == NULL ? CKR_OK : cnk_attribute_get_bool(attribute, value);
}

CK_RV cnk_template_get_optional_byte(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_ATTRIBUTE_TYPE type,
                                     CK_BYTE defaultValue, CK_BYTE *value) {
  CK_ATTRIBUTE_PTR attribute;
  CNK_ENSURE_NONNULL(value);
  *value = defaultValue;
  CNK_ENSURE_OK(cnk_template_find_attribute(attributes, attributeCount, type, &attribute));
  return attribute == NULL ? CKR_OK : cnk_attribute_get_byte(attribute, value);
}

CK_RV cnk_ec_params_to_piv_algorithm(const CK_BYTE *params, CK_ULONG paramsLen, CK_BYTE *algorithmType) {
  static const CK_BYTE p256[] = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
  static const CK_BYTE p384[] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22};
  static const CK_BYTE p521[] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23};
  static const CK_BYTE secp256k1[] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A};
  static const CK_BYTE ed25519[] = {0x06, 0x03, 0x2B, 0x65, 0x70};
  static const CK_BYTE x25519[] = {0x06, 0x03, 0x2B, 0x65, 0x6E};
  static const CK_BYTE sm2[] = {0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D};
  CNK_ENSURE_NONNULL(params, algorithmType);

  if (paramsLen == sizeof(p256) && memcmp(params, p256, sizeof(p256)) == 0)
    *algorithmType = PIV_ALG_ECC_256;
  else if (paramsLen == sizeof(p384) && memcmp(params, p384, sizeof(p384)) == 0)
    *algorithmType = PIV_ALG_ECC_384;
  else if (paramsLen == sizeof(p521) && memcmp(params, p521, sizeof(p521)) == 0)
    *algorithmType = PIV_ALG_ECC_521;
  else if (paramsLen == sizeof(secp256k1) && memcmp(params, secp256k1, sizeof(secp256k1)) == 0)
    *algorithmType = PIV_ALG_SECP256K1;
  else if (paramsLen == sizeof(ed25519) && memcmp(params, ed25519, sizeof(ed25519)) == 0)
    *algorithmType = PIV_ALG_ED25519;
  else if (paramsLen == sizeof(x25519) && memcmp(params, x25519, sizeof(x25519)) == 0)
    *algorithmType = PIV_ALG_X25519;
  else if (paramsLen == sizeof(sm2) && memcmp(params, sm2, sizeof(sm2)) == 0)
    *algorithmType = PIV_ALG_SM2;
  else
    return CKR_ATTRIBUTE_VALUE_INVALID;
  return CKR_OK;
}
