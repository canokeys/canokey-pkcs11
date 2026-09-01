#ifndef CNK_INTERNAL_MLDSA_H
#define CNK_INTERNAL_MLDSA_H

#include "pkcs11.h"

#define CNK_MLDSA65_PUBLIC_KEY_BYTES 1952
#define CNK_MLDSA65_SIGNATURE_BYTES 3309

CK_RV cnk_mldsa65_verify_signature(const CK_BYTE publicKey[CNK_MLDSA65_PUBLIC_KEY_BYTES], const CK_BYTE *message,
                                   CK_ULONG messageLen, const CK_BYTE signature[CNK_MLDSA65_SIGNATURE_BYTES]);

#endif // CNK_INTERNAL_MLDSA_H
