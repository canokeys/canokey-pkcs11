#include "pkcs11.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  CK_FUNCTION_LIST_PTR functions = NULL;
  if (C_GetFunctionList(&functions) != CKR_OK || functions == NULL)
    return 0;

  // This target deliberately stays before C_Initialize: every call below is
  // required to reject invalid state without opening PC/SC or touching a card.
  CK_INFO info;
  (void)functions->C_GetInfo(&info);
  CK_ULONG count = 0;
  (void)functions->C_GetSlotList(CK_TRUE, NULL, &count);

  CK_SESSION_HANDLE session = 0;
  CK_OBJECT_HANDLE object = 0;
  if (size >= sizeof(session))
    memcpy(&session, data, sizeof(session));
  if (size >= sizeof(session) + sizeof(object))
    memcpy(&object, data + sizeof(session), sizeof(object));

  CK_BYTE randomBytes[32] = {0};
  (void)functions->C_GenerateRandom(session, randomBytes,
                                    size < sizeof(randomBytes) ? (CK_ULONG)size : sizeof(randomBytes));
  CK_SESSION_INFO sessionInfo;
  (void)functions->C_GetSessionInfo(session, &sessionInfo);
  CK_ATTRIBUTE attribute = {CKA_VALUE, randomBytes, sizeof(randomBytes)};
  (void)functions->C_GetAttributeValue(session, object, &attribute, 1);
  return 0;
}
