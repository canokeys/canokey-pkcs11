#include "backend/libcanokey.h"
#include <stdio.h>
#include <string.h>
#define CHECK(x)                                                                                                       \
  do {                                                                                                                 \
    if (!(x)) {                                                                                                        \
      fprintf(stderr, "Protocol check failed at %d\n", __LINE__);                                                      \
      return 1;                                                                                                        \
    }                                                                                                                  \
  } while (0)
int main(void) {
  CNK_LIBCANO_OPERATION *op = NULL;
  CNK_LIBCANO_ERROR error = {.struct_size = sizeof(error)};
  uint32_t step = 0;
  CHECK(cnk_piv_read_version_selected_new(NULL, &op, &error) == CNK_LIBCANO_OK);
  CHECK(cnk_operation_start(op, &step, &error) == CNK_LIBCANO_OK && step == CNK_LIBCANO_STEP_EXCHANGE);
  const CK_BYTE first[] = {0, 0xfd, 0, 0, 0}, next[] = {0, 0xc0, 0, 0, 2};
  CK_BYTE command[8];
  size_t size = sizeof(command);
  CHECK(cnk_operation_command(op, command, &size) == CNK_LIBCANO_OK && size == 5 && !memcmp(command, first, 5));
  const CK_BYTE partial[] = {6, 0x61, 2};
  CHECK(cnk_operation_advance(op, partial, sizeof(partial), &step, &error) == CNK_LIBCANO_OK);
  size = sizeof(command);
  CHECK(cnk_operation_command(op, command, &size) == CNK_LIBCANO_OK && size == 5 && !memcmp(command, next, 5));
  const CK_BYTE final[] = {0, 0, 0x90, 0};
  CHECK(cnk_operation_advance(op, final, sizeof(final), &step, &error) == CNK_LIBCANO_OK &&
        step == CNK_LIBCANO_STEP_DONE);
  size = 0;
  CHECK(cnk_operation_result_copy_bytes(op, NULL, &size) == CNK_LIBCANO_OK && size == 3);
  CK_BYTE result[4] = {0xcc, 0xcc, 0xcc, 0xcc};
  size = 2;
  CHECK(cnk_operation_result_copy_bytes(op, result, &size) == CNK_LIBCANO_BUFFER_TOO_SMALL && size == 3 &&
        result[0] == 0xcc);
  CHECK(cnk_operation_result_copy_bytes(op, result, &size) == CNK_LIBCANO_OK && !memcmp(result, "\6\0\0", 3) &&
        result[3] == 0xcc);
  cnk_operation_free(op);
  return 0;
}
