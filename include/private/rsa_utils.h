#ifndef RSA_UTILS_H
#define RSA_UTILS_H

#include "pkcs11.h"

CK_RV cnk_prepare_rsa_sign_data(CK_MECHANISM_PTR mechanism_ptr, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                                CK_BYTE algorithm_type, CK_BYTE_PTR pPreparedData, CK_ULONG_PTR pulPreparedDataLen);

#endif //RSA_UTILS_H
