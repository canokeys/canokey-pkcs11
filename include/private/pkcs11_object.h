#ifndef CANOKEY_PKCS11_OBJ_H
#define CANOKEY_PKCS11_OBJ_H

#include "pkcs11.h"
#include "pkcs11_session.h"

/**
 * Extracts object information from a PKCS#11 object handle.
 *
 * @param hObject The object handle
 * @param slot_id The slot ID
 * @param obj_class The object class
 * @param obj_id The object ID
 */
void cnk_extract_object_info(CK_OBJECT_HANDLE hObject, CK_SLOT_ID *slot_id, CK_OBJECT_CLASS *obj_class,
                             CK_BYTE *obj_id);

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

/**
 * Converts an algorithm type to a key type.
 *
 * @param algorithm_type The algorithm type
 * @return The key type
 */
CK_KEY_TYPE cnk_algo_type_to_key_type(CK_BYTE algorithm_type);

/**
 * Creates a new object.
 *
 * @param hSession The session handle
 * @param pTemplate The template
 * @param ulCount The number of attributes
 * @param phObject The object handle
 */
CK_RV cnk_create_object(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                        CK_OBJECT_HANDLE_PTR phObject);

/**
 * Copies an object.
 *
 * @param hSession The session handle
 * @param hObject The object handle
 * @param pTemplate The template
 * @param ulCount The number of attributes
 * @param phNewObject The new object handle
 */
CK_RV cnk_copy_object(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                      CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject);

/**
 * Destroys an object.
 *
 * @param hSession The session handle
 * @param hObject The object handle
 */
CK_RV cnk_destroy_object(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);

/**
 * Gets the size of an object.
 *
 * @param hSession The session handle
 * @param hObject The object handle
 * @param pulSize The size
 */
CK_RV cnk_get_object_size(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);

/**
 * Gets the attribute value of an object.
 *
 * @param hSession The session handle
 * @param hObject The object handle
 * @param pTemplate The template
 * @param ulCount The number of attributes
 */
CK_RV cnk_get_attribute_value(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                              CK_ULONG ulCount);

/**
 * Sets the attribute value of an object.
 *
 * @param hSession The session handle
 * @param hObject The object handle
 * @param pTemplate The template
 * @param ulCount The number of attributes
 */
CK_RV cnk_set_attribute_value(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                              CK_ULONG ulCount);

/**
 * Initializes a find objects operation.
 *
 * @param hSession The session handle
 * @param pTemplate The template
 * @param ulCount The number of attributes
 */
CK_RV cnk_find_objects_init(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

/**
 * Finds objects.
 *
 * @param hSession The session handle
 * @param phObject The object handle
 * @param ulMaxObjectCount The maximum number of objects
 * @param pulObjectCount The number of objects found
 */
CK_RV cnk_find_objects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
                       CK_ULONG_PTR pulObjectCount);

/**
 * Finalizes a find objects operation.
 *
 * @param hSession The session handle
 */
CK_RV cnk_find_objects_final(CK_SESSION_HANDLE hSession);

#endif // CANOKEY_PKCS11_OBJ_H
