#ifndef CNK_INTERNAL_MLKEM_H
#define CNK_INTERNAL_MLKEM_H

#include "pkcs11.h"

#define CNK_MLKEM768_PUBLIC_KEY_BYTES 1184
#define CNK_MLKEM768_CIPHERTEXT_BYTES 1088
#define CNK_MLKEM768_SHARED_SECRET_BYTES 32

CK_RV cnk_mlkem768_encapsulate(const CK_BYTE publicKey[CNK_MLKEM768_PUBLIC_KEY_BYTES],
                               CK_BYTE ciphertext[CNK_MLKEM768_CIPHERTEXT_BYTES],
                               CK_BYTE sharedSecret[CNK_MLKEM768_SHARED_SECRET_BYTES]);

#endif
