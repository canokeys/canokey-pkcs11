// Shared real-Rust profile fixture. No card transport or production mock state.
#ifndef CNK_TEST_PROFILE_H
#define CNK_TEST_PROFILE_H
#include "backend/libcanokey.h"
#include <string.h>
static cnk_profile_t *test_profile(const char *firmware, CK_BYTE generateWire) {
  cnk_operation_t *operation = NULL;
  uint32_t step = 0;
  CHECK(cnk_probe_device_new(1, NULL, &operation, NULL) == CNK_OK);
  CHECK(cnk_operation_start(operation, &step, NULL) == CNK_OK);
  for (unsigned count = 0; step == CNK_STEP_EXCHANGE; count++) {
    CHECK(count < 20);
    CK_BYTE command[300], response[64];
    size_t commandLen = sizeof(command), n = 0;
    CHECK(cnk_operation_command(operation, command, &commandLen) == CNK_OK && commandLen >= 4);
    if (command[1] == 0x31 && command[2] == 0) {
      n = strlen(firmware);
      CHECK(n < sizeof(response) - 2);
      memcpy(response, firmware, n);
    } else if (command[1] == 0xfd) {
      response[0] = 6;
      response[1] = response[2] = 0;
      n = 3;
    } else if (command[1] == 0xee && generateWire) {
      const CK_BYTE config[] = {1, 0xe0, generateWire, 0x16, 0xe1, 0x53, 0x15, 0x54, 0xe2, 0xe3};
      memcpy(response, config, sizeof(config));
      n = sizeof(config);
    } else if (command[1] != 0xa4) {
      response[n++] = 0x6d;
      response[n++] = 0;
    }
    if (n != 2 || response[0] != 0x6d) {
      response[n++] = 0x90;
      response[n++] = 0;
    }
    CHECK(cnk_operation_advance(operation, response, n, &step, NULL) == CNK_OK);
  }
  CHECK(step == CNK_STEP_DONE);
  cnk_profile_t *profile = NULL;
  CHECK(cnk_operation_take_profile(operation, &profile) == CNK_OK);
  cnk_operation_free(operation);
  return profile;
}
#endif
