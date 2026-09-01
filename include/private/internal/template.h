#ifndef CNK_INTERNAL_TEMPLATE_H
#define CNK_INTERNAL_TEMPLATE_H

#include "pkcs11.h"

CK_RV cnk_template_get_attribute(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_ATTRIBUTE_TYPE type,
                                 CK_ATTRIBUTE_PTR *attribute);
CK_RV cnk_template_find_attribute(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_ATTRIBUTE_TYPE type,
                                  CK_ATTRIBUTE_PTR *attribute);

CK_RV cnk_attribute_get_bool(CK_ATTRIBUTE_PTR attribute, CK_BBOOL *value);
CK_RV cnk_attribute_get_byte(CK_ATTRIBUTE_PTR attribute, CK_BYTE *value);
CK_RV cnk_attribute_get_object_class(CK_ATTRIBUTE_PTR attribute, CK_OBJECT_CLASS *value);
CK_RV cnk_attribute_get_key_type(CK_ATTRIBUTE_PTR attribute, CK_KEY_TYPE *value);

CK_RV cnk_template_get_byte(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_ATTRIBUTE_TYPE type,
                            CK_BYTE *value);
CK_RV cnk_template_get_object_class(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_ATTRIBUTE_TYPE type,
                                    CK_OBJECT_CLASS *value);
CK_RV cnk_template_get_key_type(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_ATTRIBUTE_TYPE type,
                                CK_KEY_TYPE *value);
CK_RV cnk_template_get_optional_bool(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_ATTRIBUTE_TYPE type,
                                     CK_BBOOL defaultValue, CK_BBOOL *value);
CK_RV cnk_template_get_optional_byte(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_ATTRIBUTE_TYPE type,
                                     CK_BYTE defaultValue, CK_BYTE *value);

CK_RV cnk_ec_params_to_piv_algorithm(const CK_BYTE *params, CK_ULONG paramsLen, CK_BYTE *algorithmType);

#endif // CNK_INTERNAL_TEMPLATE_H
