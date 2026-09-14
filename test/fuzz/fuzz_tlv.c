#include "internal/util.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  CK_LONG failed = 0;
  CK_ULONG lengthSize = 0;
  (void)tlvGetLengthSafe(data, (CK_ULONG)size, &failed, &lengthSize);
  return 0;
}
