#include "backend/libcanokey.h"

#include <stdlib.h>
#include <string.h>

// Exercise the PIV TLV parsers used by production through their actual C ABI.
// The retired C length decoder has no callers and is no longer a fuzz target.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  cnk_error_v1 error = {.struct_size = sizeof(error)};
  uint32_t flags = 0xdeadbeef;
  uint32_t status = cnk_piv_admin_data_flags(data, size, &flags, &error);
  if (status != CNK_OK && flags != 0xdeadbeef)
    abort();
  uint8_t key[24], original[24];
  memset(original, 0xcc, sizeof(original));
  memcpy(key, original, sizeof(key));
  size_t length = sizeof(key);
  status = cnk_piv_printed_management_key_copy(data, size, key, &length, &error);
  if ((status == CNK_OK && length != sizeof(key)) || (status != CNK_OK && memcmp(key, original, sizeof(key))))
    abort();
  memset(key, 0, sizeof(key));
  return 0;
}
