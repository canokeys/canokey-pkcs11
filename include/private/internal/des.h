#ifndef CNK_INTERNAL_DES_H
#define CNK_INTERNAL_DES_H

#include "pkcs11.h"

CK_RV cnk_des3_encrypt_block(const CK_BYTE key[24], const CK_BYTE input[8], CK_BYTE output[8]);

#endif // CNK_INTERNAL_DES_H
