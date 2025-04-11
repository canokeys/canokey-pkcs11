#ifndef CANOKEY_PKCS11_OBJ_H
#define CANOKEY_PKCS11_OBJ_H

#include "pkcs11.h"
#include "pkcs11_canokey.h"
#include "pkcs11_session.h"

// Object operation functions
CK_RV cnk_create_object(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                        CK_OBJECT_HANDLE_PTR phObject);

CK_RV cnk_copy_object(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                      CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject);

CK_RV cnk_destroy_object(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);

CK_RV cnk_get_object_size(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);

CK_RV cnk_get_attribute_value(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                              CK_ULONG ulCount);

CK_RV cnk_set_attribute_value(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                              CK_ULONG ulCount);

CK_RV cnk_find_objects_init(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

CK_RV cnk_find_objects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
                       CK_ULONG_PTR pulObjectCount);

CK_RV cnk_find_objects_final(CK_SESSION_HANDLE hSession);

#endif // CANOKEY_PKCS11_OBJ_H
