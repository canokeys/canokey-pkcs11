#ifndef CNK_BACKEND_LIBCANOKEY_H
#define CNK_BACKEND_LIBCANOKEY_H

#include <stddef.h>
#include <stdint.h>

typedef struct CNK_LIBCANO_OPERATION CNK_LIBCANO_OPERATION;
typedef struct CNK_LIBCANO_CONTEXT CNK_LIBCANO_CONTEXT;
typedef struct {
  uint32_t struct_size;
  uint32_t kind, phase, reference, presence_flags;
  uint16_t status_word;
  uint8_t retries_remaining, reserved;
} CNK_LIBCANO_ERROR;
typedef struct {
  uint32_t struct_size, flags, max_command_bytes, max_response_bytes,
      max_total_response_bytes, max_exchanges;
} CNK_LIBCANO_OPTIONS;

enum { CNK_LIBCANO_OK = 0, CNK_LIBCANO_STEP_EXCHANGE = 1, CNK_LIBCANO_STEP_DONE = 2 };
enum { CNK_LIBCANO_CONTEXT_SELECTED = 1 };

uint32_t cnk_piv_context_new(const void *, uint32_t, CNK_LIBCANO_CONTEXT **, CNK_LIBCANO_ERROR *);
void cnk_piv_context_free(CNK_LIBCANO_CONTEXT *);
uint32_t cnk_piv_get_metadata_in_context_new(const CNK_LIBCANO_CONTEXT *, uint32_t,
                                             const CNK_LIBCANO_OPTIONS *, CNK_LIBCANO_OPERATION **,
                                             CNK_LIBCANO_ERROR *);
uint32_t cnk_operation_start(CNK_LIBCANO_OPERATION *, uint32_t *, CNK_LIBCANO_ERROR *);
uint32_t cnk_operation_advance(CNK_LIBCANO_OPERATION *, const uint8_t *, size_t, uint32_t *, CNK_LIBCANO_ERROR *);
uint32_t cnk_operation_command(const CNK_LIBCANO_OPERATION *, uint8_t *, size_t *);
uint32_t cnk_operation_result_copy_bytes(const CNK_LIBCANO_OPERATION *, uint8_t *, size_t *);
void cnk_operation_free(CNK_LIBCANO_OPERATION *);

#endif
