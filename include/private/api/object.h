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

/**
 * Builds an object handle using the module's internal handle encoding.
 *
 * @param slot_id Slot ID associated with the object
 * @param object_class PKCS#11 object class
 * @param object_id Object ID
 */
CK_OBJECT_HANDLE CNK_MakeObjectHandle(CK_SLOT_ID slot_id, CK_OBJECT_CLASS object_class, CK_BYTE object_id);

CK_RV CNK_GetSessionSecretKey(CNK_PKCS11_SESSION *session, CK_OBJECT_HANDLE object,
                              CNK_PKCS11_SECRET_KEY_OBJECT **secret);

CK_RV CNK_CreateSessionSecretKey(CNK_PKCS11_SESSION *session, const CNK_PKCS11_SECRET_KEY_OBJECT *prototype,
                                 CK_OBJECT_HANDLE_PTR object);

CK_RV CNK_GetPivPolicies(CK_ATTRIBUTE_PTR p_template, CK_ULONG ul_count, CK_BYTE default_pin_policy,
                         CK_BYTE *pin_policy, CK_BYTE *touch_policy);

/**
 * Returns the CanoKey PIV default PIN policy for a key slot.
 *
 * CanoKey defaults 9E to PIN never and other PIV key slots to PIN once.
 * Touch policy defaults are handled by CNK_GetPivPolicies().
 *
 * @param obj_id Internal object ID
 */
CK_BYTE CNK_DefaultPinPolicyForPivObjectId(CK_BYTE obj_id);

/**
 * Reports whether a stored PIV key algorithm supports PKCS#11 signing.
 *
 * PIV retired slots can also sign, so this is intentionally based on the
 * algorithm metadata instead of a slot whitelist.
 *
 * @param algorithm_type PIV algorithm type from metadata
 */
CK_BBOOL CNK_PivPrivateKeyCanSign(CK_BYTE algorithm_type);

CK_BBOOL CNK_PivPrivateKeyCanDecrypt(CK_BYTE algorithm_type);

CK_BBOOL CNK_PivPrivateKeyCanDerive(CK_BYTE algorithm_type);

/**
 * Maps a PIV object ID to its PIV certificate data-object tag.
 *
 * @param obj_id Internal object ID
 * @param data_tag PIV 0x5FC1xx data-object tag
 */
CK_RV CNK_ObjectIdToCertificateTag(CK_BYTE obj_id, CK_BYTE *data_tag);

#endif // CNK_API_OBJECT_H
