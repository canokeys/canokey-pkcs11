#ifndef CANOKEY_PKCS11_OBJ_H
#define CANOKEY_PKCS11_OBJ_H

#include "pkcs11.h"
#include "pkcs11_session.h"

/**
 * Validates an object.
 *
 * @param hObject The object handle
 * @param session The session
 * @param expected_class The expected object class
 * @param obj_id The object ID
 */
CK_RV CNK_ValidateObject(CK_OBJECT_HANDLE hObject, CNK_PKCS11_SESSION *session, CK_OBJECT_CLASS expected_class,
                         CK_BYTE *obj_id);

#endif // CANOKEY_PKCS11_OBJ_H
