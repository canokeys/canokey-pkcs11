#ifndef RSA_UTILS_H
#define RSA_UTILS_H

#include "pkcs11.h"

CK_RV cnk_prepare_rsa_sign_data(CK_MECHANISM_PTR pMechanism, CK_BYTE_PTR data_ptr, CK_ULONG data_len,
                                CK_BYTE_PTR pModulus, CK_ULONG ulModulusLen, CK_BYTE bAlgorithmType,
                                CK_BYTE_PTR prepared_data_ptr, CK_ULONG_PTR prepared_data_len_ptr);

#endif // RSA_UTILS_H
