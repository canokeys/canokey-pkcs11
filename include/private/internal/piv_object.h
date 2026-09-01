#ifndef CNK_INTERNAL_PIV_OBJECT_H
#define CNK_INTERNAL_PIV_OBJECT_H

#include "api/session.h"
#include "pkcs11.h"

CK_RV cnk_build_piv_certificate_object(CK_BYTE_PTR certificate, CK_ULONG certificateLen, CK_BYTE *output,
                                       CK_ULONG outputLen, CK_ULONG_PTR written);
CK_RV cnk_build_piv_rsa_import(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_BYTE objectId, CK_BYTE *output,
                               CK_ULONG outputLen, CK_ULONG_PTR written, CK_BYTE *algorithmType);
CK_RV cnk_build_piv_ec_import(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_BYTE objectId, CK_BYTE *output,
                              CK_ULONG outputLen, CK_ULONG_PTR written, CK_BYTE *algorithmType);
CK_RV cnk_build_piv_pqc_import(CNK_PKCS11_SESSION *session, CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount,
                               CK_BYTE objectId, CK_KEY_TYPE keyType, CK_BYTE *output, CK_ULONG outputLen,
                               CK_ULONG_PTR written, CK_BYTE *algorithmType);

#endif // CNK_INTERNAL_PIV_OBJECT_H
