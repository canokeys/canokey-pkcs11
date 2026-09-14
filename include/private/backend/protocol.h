#ifndef CNK_BACKEND_PROTOCOL_H
#define CNK_BACKEND_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

/* Private synchronous ABI. Buffers and callback context are borrowed only until
 * return, must not alias outputs, and must not unwind across the C boundary.
 * Rust owns/wipes its copies; C owns the card transaction and original secrets. */
typedef uint32_t (*CNK_PROTOCOL_TRANSMIT)(void *context, const uint8_t *command, size_t command_len, uint8_t *response,
                                          size_t *response_len);

typedef struct {
  uint8_t header[4];
  const uint8_t *data;
  size_t data_len;
  uint32_t le; /* 0 means absent; 1..256 is a short-APDU Le. */
  uint32_t chain;
  uint32_t get_response;
} CNK_PROTOCOL_COMMAND;

enum {
  CNK_PROTOCOL_OK = 0,
  CNK_PROTOCOL_ARGUMENT = 1,
  CNK_PROTOCOL_TRANSPORT = 2,
  CNK_PROTOCOL_SMALL = 3,
  CNK_PROTOCOL_FAILED = 4
};

/* Output is untouched on failure; SMALL sets the complete required size,
 * including SW1/SW2. This is not permission to repeat card-side mutations. */
uint32_t cnk_protocol_run(const CNK_PROTOCOL_COMMAND *command, CNK_PROTOCOL_TRANSMIT transmit, void *context,
                          uint8_t *response, size_t *response_len);

#endif
