#ifndef CNK_API_OBJECT_H
#define CNK_API_OBJECT_H

#include "api/session.h"
#include "pkcs11.h"

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

#endif // CNK_API_OBJECT_H
