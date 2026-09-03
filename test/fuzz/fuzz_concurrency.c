#include "pkcs11.h"
#include "pkcs11_canokey.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
typedef HANDLE CNK_FUZZ_THREAD;
#else
#include <pthread.h>
typedef pthread_t CNK_FUZZ_THREAD;
#endif

typedef struct {
  CK_FUNCTION_LIST_PTR functions;
  uint32_t seed;
} CNK_FUZZ_WORK;

static void run_worker(const CNK_FUZZ_WORK *work) {
  CK_SESSION_HANDLE session = (CK_SESSION_HANDLE)work->seed;
  CK_OBJECT_HANDLE object = (CK_OBJECT_HANDLE)(work->seed ^ 0xA5A5A5A5u);
  CK_INFO info;
  CK_ULONG slotCount = 0;
  CK_SESSION_INFO sessionInfo;
  CK_BYTE randomData[16] = {0};
  CK_ATTRIBUTE attribute = {CKA_VALUE, randomData, sizeof(randomData)};

  (void)work->functions->C_GetInfo(&info);
  (void)work->functions->C_GetSlotList(CK_TRUE, NULL, &slotCount);
  (void)work->functions->C_GetSessionInfo(session, &sessionInfo);
  (void)work->functions->C_GenerateRandom(session, randomData, sizeof(randomData));
  (void)work->functions->C_GetAttributeValue(session, object, &attribute, 1);

  // Invalid managed arguments exercise the lifecycle lock without creating a
  // card binding or touching PC/SC state.
  CNK_MANAGED_MODE_INIT_ARGS managed = {0};
  (void)C_CNK_EnableManagedMode(&managed);
}

#ifdef _WIN32
static DWORD WINAPI worker_entry(void *arg) {
  run_worker((const CNK_FUZZ_WORK *)arg);
  return 0;
}
#else
static void *worker_entry(void *arg) {
  run_worker((const CNK_FUZZ_WORK *)arg);
  return NULL;
}
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  CK_FUNCTION_LIST_PTR functions = NULL;
  if (C_GetFunctionList(&functions) != CKR_OK || functions == NULL)
    return 0;

  uint32_t seed = 0;
  if (size >= sizeof(seed))
    memcpy(&seed, data, sizeof(seed));
  CNK_FUZZ_WORK work = {.functions = functions, .seed = seed};
  CNK_FUZZ_THREAD threads[4];

#ifdef _WIN32
  for (size_t i = 0; i < 4; i++)
    threads[i] = CreateThread(NULL, 0, worker_entry, &work, 0, NULL);
  for (size_t i = 0; i < 4; i++) {
    if (threads[i] != NULL) {
      WaitForSingleObject(threads[i], INFINITE);
      CloseHandle(threads[i]);
    }
  }
#else
  size_t created = 0;
  for (; created < 4; created++) {
    if (pthread_create(&threads[created], NULL, worker_entry, &work) != 0)
      break;
  }
  for (size_t i = 0; i < created; i++)
    pthread_join(threads[i], NULL);
#endif
  return 0;
}
