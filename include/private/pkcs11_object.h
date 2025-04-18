#ifndef CANOKEY_PKCS11_OBJ_H
#define CANOKEY_PKCS11_OBJ_H

#include "pkcs11.h"

/**
 * Converts an object ID to a PIV tag.
 *
 * @param obj_id The object ID
 * @param piv_tag The PIV tag
 */
CK_RV cnk_obj_id_to_piv_tag(CK_BYTE obj_id, CK_BYTE *piv_tag);

/**
 * Validates an object.
 *
 * @param hObject The object handle
 * @param session The session
 * @param expected_class The expected object class
 * @param obj_id The object ID
 */
CK_RV cnk_validate_object(CK_OBJECT_HANDLE hObject, CNK_PKCS11_SESSION *session, CK_OBJECT_CLASS expected_class,
                          CK_BYTE *obj_id);

#endif // CANOKEY_PKCS11_OBJ_H
