#ifndef CNK_INTERNAL_PUBLIC_KEY_H
#define CNK_INTERNAL_PUBLIC_KEY_H

#include "pkcs11.h"
#include <stdint.h>

// Owned public components copied from a validated Rust result. value is the
// big-endian RSA modulus, EC point, or raw RFC/PQC key; only RSA has an exponent.
// No card encoding or Rust-owned pointer survives in a cache or host operation.
typedef struct {
  uint32_t algorithm;
  CK_BYTE value[2048];
  CK_ULONG valueLen;
  CK_BYTE exponent[8];
  CK_ULONG exponentLen;
} CNK_PIV_PUBLIC_KEY;

#endif
