#ifndef CNK_INTERNAL_PIV_OBJECT_H
#define CNK_INTERNAL_PIV_OBJECT_H

#include "api/session.h"
#include "backend/libcanokey.h"
#include "pkcs11.h"

// Component views borrow the caller's template, except a padded EC scalar.
// Do not copy this descriptor: its scalar view points inside it. Keep it alive
// through cnk_piv_import_key(), then zeroize the complete descriptor on all exits.
typedef struct {
  CNK_LIBCANO_KEY_PARAMETERS parameters;
  CNK_LIBCANO_BYTES components[5];
  size_t count;
  CK_BYTE scalar[66];
} CNK_PIV_IMPORT;

CK_RV cnk_prepare_piv_import(CNK_PKCS11_SESSION *session, CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount,
                             CK_BYTE objectId, CK_KEY_TYPE keyType, CNK_PIV_IMPORT *material);
CK_RV cnk_piv_import_key(CK_SLOT_ID slotID, CNK_PKCS11_SESSION *session, const CNK_PIV_IMPORT *material);

#endif // CNK_INTERNAL_PIV_OBJECT_H
