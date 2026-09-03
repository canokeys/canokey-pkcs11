#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
#if defined(CNK_REPLAY_HAS_INITIALIZER)
int LLVMFuzzerInitialize(int *argc, char ***argv);
#endif

static uint32_t next_random(uint32_t *state) {
  *state = *state * 1664525u + 1013904223u;
  return *state;
}

int main(int argc, char **argv) {
#if defined(CNK_REPLAY_HAS_INITIALIZER)
  LLVMFuzzerInitialize(&argc, &argv);
#endif
  unsigned long seconds = 1;
  const char *corpusFile = NULL;
  for (int i = 1; i < argc; i++) {
    if (strncmp(argv[i], "-max_total_time=", 16) == 0)
      seconds = strtoul(argv[i] + 16, NULL, 10);
    else if (argv[i][0] != '-')
      corpusFile = argv[i];
  }
  if (seconds == 0)
    seconds = 1;

  uint8_t input[4096] = {0};
  size_t inputLen = 1;
  if (corpusFile != NULL) {
    FILE *file = fopen(corpusFile, "rb");
    if (file != NULL) {
      inputLen = fread(input, 1, sizeof(input), file);
      fclose(file);
      if (inputLen == 0)
        inputLen = 1;
    }
  }

  uint32_t state = 0xC0DEC0DEu;
  clock_t deadline = clock() + (clock_t)seconds * CLOCKS_PER_SEC;
  do {
    LLVMFuzzerTestOneInput(input, inputLen);
    size_t index = next_random(&state) % inputLen;
    input[index] ^= (uint8_t)next_random(&state);
    if (inputLen < sizeof(input) && (next_random(&state) & 7u) == 0)
      input[inputLen++] = (uint8_t)next_random(&state);
  } while (clock() < deadline);
  return 0;
}
