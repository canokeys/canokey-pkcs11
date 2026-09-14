#include "backend/protocol.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition)                                                                                               \
  do {                                                                                                                 \
    if (!(condition)) {                                                                                                \
      fprintf(stderr, "Protocol ABI check failed at line %d\n", __LINE__);                                             \
      return 1;                                                                                                        \
    }                                                                                                                  \
  } while (0)

typedef struct {
  unsigned calls;
  unsigned failed;
  unsigned transport_failure;
} CARD;

static uint32_t transmit(void *opaque, const uint8_t *command, size_t command_len, uint8_t *response,
                         size_t *response_len) {
  CARD *card = opaque;
  static const uint8_t first[] = {0, 0xCB, 0x3F, 0xFF, 3, 0x5C, 1, 0x7E, 0};
  static const uint8_t continuation[] = {0, 0xC0, 0, 0, 1};
  const uint8_t *expected = card->calls == 0 ? first : continuation;
  size_t expected_len = card->calls == 0 ? sizeof(first) : sizeof(continuation);
  card->calls++;
  if (card->calls > 2 || command_len != expected_len || memcmp(command, expected, expected_len) != 0 ||
      *response_len < 3) {
    card->failed = 1;
    return 1;
  }
  if (card->transport_failure && card->calls == 2)
    return 1;
  response[0] = card->calls == 1 ? 0xA5 : 0x5A;
  response[1] = card->calls == 1 ? 0x61 : 0x90;
  response[2] = card->calls == 1 ? 1 : 0;
  *response_len = 3;
  return 0;
}

int main(void) {
  const uint8_t data[] = {0x5C, 1, 0x7E};
  CNK_PROTOCOL_COMMAND command = {
      .header = {0, 0xCB, 0x3F, 0xFF}, .data = data, .data_len = sizeof(data), .le = 256, .get_response = 1};
  CARD card = {0};
  uint8_t output[5] = {0, 0, 0, 0, 0xCC};
  size_t length = 4;
  CHECK(cnk_protocol_run(&command, transmit, &card, output, &length) == CNK_PROTOCOL_OK);
  CHECK(length == 4 && card.calls == 2 && !card.failed);
  CHECK(memcmp(output, "\xA5\x5A\x90\x00\xCC", 5) == 0);

  card = (CARD){0};
  memset(output, 0xCC, sizeof(output));
  length = 3;
  CHECK(cnk_protocol_run(&command, transmit, &card, output, &length) == CNK_PROTOCOL_SMALL);
  CHECK(length == 4 && card.calls == 2 && !card.failed);
  CHECK(memcmp(output, "\xCC\xCC\xCC\xCC\xCC", 5) == 0);

  card = (CARD){.transport_failure = 1};
  length = sizeof(output);
  CHECK(cnk_protocol_run(&command, transmit, &card, output, &length) == CNK_PROTOCOL_TRANSPORT);
  CHECK(length == sizeof(output) && card.calls == 2 && !card.failed);
  CHECK(memcmp(output, "\xCC\xCC\xCC\xCC\xCC", 5) == 0);
  return 0;
}
