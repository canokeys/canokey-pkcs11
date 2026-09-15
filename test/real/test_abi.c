#include "pkcs11.h"
#include "pkcs11_canokey.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#define CHECK(call)                                                                                                    \
  do {                                                                                                                 \
    CK_RV checkRv = (call);                                                                                            \
    if (checkRv != CKR_OK) {                                                                                           \
      fprintf(stderr, "%s:%d: %s failed: 0x%lx\n", __FILE__, __LINE__, #call, checkRv);                                \
      return 1;                                                                                                        \
    }                                                                                                                  \
  } while (0)

static int testSessionSecretLifecycle(CK_FUNCTION_LIST_3_2_PTR functions, CK_SESSION_HANDLE session) {
  CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
  CK_KEY_TYPE genericType = CKK_GENERIC_SECRET;
  CK_ULONG valueLen = 32;
  CK_BBOOL falseValue = CK_FALSE;
  CK_BBOOL trueValue = CK_TRUE;
  CK_BYTE label[] = "lifecycle-secret";
  CK_ATTRIBUTE generateTemplate[] = {
      {CKA_CLASS, &secretClass, sizeof(secretClass)},   {CKA_KEY_TYPE, &genericType, sizeof(genericType)},
      {CKA_VALUE_LEN, &valueLen, sizeof(valueLen)},     {CKA_TOKEN, &falseValue, sizeof(falseValue)},
      {CKA_PRIVATE, &trueValue, sizeof(trueValue)},     {CKA_SENSITIVE, &falseValue, sizeof(falseValue)},
      {CKA_EXTRACTABLE, &trueValue, sizeof(trueValue)}, {CKA_LABEL, label, sizeof(label) - 1},
  };
  CK_MECHANISM mechanism = {CKM_GENERIC_SECRET_KEY_GEN, NULL, 0};
  CK_OBJECT_HANDLE generated;
  CHECK(functions->C_GenerateKey(session, &mechanism, generateTemplate,
                                 sizeof(generateTemplate) / sizeof(generateTemplate[0]), &generated));

  CK_BYTE value[32];
  CK_BBOOL local = CK_FALSE, modifiable = CK_FALSE, copyable = CK_FALSE, destroyable = CK_FALSE;
  CK_MECHANISM_TYPE generatedBy = 0;
  CK_ATTRIBUTE generatedAttributes[] = {
      {CKA_VALUE, value, sizeof(value)},
      {CKA_LOCAL, &local, sizeof(local)},
      {CKA_KEY_GEN_MECHANISM, &generatedBy, sizeof(generatedBy)},
      {CKA_MODIFIABLE, &modifiable, sizeof(modifiable)},
      {CKA_COPYABLE, &copyable, sizeof(copyable)},
      {CKA_DESTROYABLE, &destroyable, sizeof(destroyable)},
  };
  CHECK(functions->C_GetAttributeValue(session, generated, generatedAttributes,
                                       sizeof(generatedAttributes) / sizeof(generatedAttributes[0])));
  if (generatedAttributes[0].ulValueLen != sizeof(value) || !local || !modifiable || !copyable || !destroyable ||
      generatedBy != CKM_GENERIC_SECRET_KEY_GEN)
    return 1;

  CK_BYTE copyLabel[] = "copy";
  CK_ATTRIBUTE copyTemplate = {CKA_LABEL, copyLabel, sizeof(copyLabel) - 1};
  CK_OBJECT_HANDLE copy;
  CHECK(functions->C_CopyObject(session, generated, &copyTemplate, 1, &copy));

  CK_BYTE rejectedLabel[] = "must-not-stick";
  CK_BYTE rejectedValue = 0;
  CK_ATTRIBUTE rejectedUpdate[] = {
      {CKA_LABEL, rejectedLabel, sizeof(rejectedLabel) - 1},
      {CKA_VALUE, &rejectedValue, sizeof(rejectedValue)},
  };
  if (functions->C_SetAttributeValue(session, copy, rejectedUpdate, 2) != CKR_ATTRIBUTE_READ_ONLY)
    return 1;
  CK_BYTE readLabel[32];
  CK_ATTRIBUTE readLabelAttribute = {CKA_LABEL, readLabel, sizeof(readLabel)};
  CHECK(functions->C_GetAttributeValue(session, copy, &readLabelAttribute, 1));
  if (readLabelAttribute.ulValueLen != sizeof(copyLabel) - 1 ||
      memcmp(readLabel, copyLabel, sizeof(copyLabel) - 1) != 0)
    return 1;

  CK_BYTE updatedLabel[] = "updated-copy";
  CK_ATTRIBUTE validUpdate[] = {
      {CKA_LABEL, updatedLabel, sizeof(updatedLabel) - 1},
      {CKA_VERIFY, &trueValue, sizeof(trueValue)},
  };
  CHECK(functions->C_SetAttributeValue(session, copy, validUpdate, 2));

  CK_BYTE digestFromKey[32], digestFromValue[32];
  CK_ULONG digestLen = sizeof(digestFromKey);
  mechanism.mechanism = CKM_SHA256;
  CHECK(functions->C_DigestInit(session, &mechanism));
  CHECK(functions->C_DigestKey(session, generated));
  CHECK(functions->C_DigestFinal(session, digestFromKey, &digestLen));
  digestLen = sizeof(digestFromValue);
  CHECK(functions->C_DigestInit(session, &mechanism));
  CHECK(functions->C_Digest(session, value, sizeof(value), digestFromValue, &digestLen));
  if (memcmp(digestFromKey, digestFromValue, sizeof(digestFromKey)) != 0)
    return 1;

  CK_KEY_TYPE aesType = CKK_AES;
  CK_ATTRIBUTE sensitiveTemplate[] = {
      {CKA_CLASS, &secretClass, sizeof(secretClass)}, {CKA_KEY_TYPE, &aesType, sizeof(aesType)},
      {CKA_VALUE_LEN, &valueLen, sizeof(valueLen)},   {CKA_TOKEN, &falseValue, sizeof(falseValue)},
      {CKA_PRIVATE, &trueValue, sizeof(trueValue)},   {CKA_SENSITIVE, &trueValue, sizeof(trueValue)},
  };
  mechanism.mechanism = CKM_AES_KEY_GEN;
  CK_OBJECT_HANDLE sensitive;
  CHECK(functions->C_GenerateKey(session, &mechanism, sensitiveTemplate,
                                 sizeof(sensitiveTemplate) / sizeof(sensitiveTemplate[0]), &sensitive));
  mechanism.mechanism = CKM_SHA256;
  CHECK(functions->C_DigestInit(session, &mechanism));
  if (functions->C_DigestKey(session, sensitive) != CKR_KEY_INDIGESTIBLE)
    return 1;
  CHECK(functions->C_SessionCancel(session, CKF_DIGEST));

  CHECK(functions->C_DestroyObject(session, generated));
  CHECK(functions->C_DestroyObject(session, copy));
  CHECK(functions->C_DestroyObject(session, sensitive));
  CK_ATTRIBUTE destroyedAttribute = {CKA_KEY_TYPE, &genericType, sizeof(genericType)};
  if (functions->C_GetAttributeValue(session, generated, &destroyedAttribute, 1) != CKR_OBJECT_HANDLE_INVALID)
    return 1;
  return 0;
}

static int testFunctionListAndSessions(CK_FUNCTION_LIST_3_2_PTR functions, CK_SLOT_ID slot, const char *pin) {
#define CK_PKCS11_FUNCTION_INFO(name)                                                                                  \
  if (functions->name == NULL) {                                                                                       \
    fprintf(stderr, "3.2 function pointer is NULL: %s\n", #name);                                                      \
    return 1;                                                                                                          \
  }
#include "pkcs11f.h"
#undef CK_PKCS11_FUNCTION_INFO

  CK_ULONG mechanismCount = 0;
  CHECK(functions->C_GetMechanismList(slot, NULL, &mechanismCount));
  CK_MECHANISM_TYPE mechanisms[256];
  if (mechanismCount + 2 > sizeof(mechanisms) / sizeof(mechanisms[0]))
    return 1;
  mechanisms[mechanismCount] = CK_UNAVAILABLE_INFORMATION;
  mechanisms[mechanismCount + 1] = CK_UNAVAILABLE_INFORMATION;
  CK_ULONG exactCount = mechanismCount;
  CHECK(functions->C_GetMechanismList(slot, mechanisms, &exactCount));
  if (exactCount != mechanismCount || mechanisms[mechanismCount] != CK_UNAVAILABLE_INFORMATION ||
      mechanisms[mechanismCount + 1] != CK_UNAVAILABLE_INFORMATION) {
    return 1;
  }
  for (CK_ULONG i = 0; i < mechanismCount; i++) {
    CK_MECHANISM_INFO mechanismInfo;
    CHECK(functions->C_GetMechanismInfo(slot, mechanisms[i], &mechanismInfo));
  }

  CK_SESSION_HANDLE sessions[16];
  for (CK_ULONG i = 0; i < 16; i++)
    CHECK(functions->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &sessions[i]));
  CK_TOKEN_INFO tokenInfo;
  CHECK(functions->C_GetTokenInfo(slot, &tokenInfo));
  if (tokenInfo.ulSessionCount < 16 || tokenInfo.ulRwSessionCount < 16)
    return 1;

  CK_MECHANISM digestMechanism = {CKM_SHA256, NULL, 0};
  CHECK(functions->C_DigestInit(sessions[0], &digestMechanism));
  if (functions->C_DigestInit(sessions[0], &digestMechanism) != CKR_OPERATION_ACTIVE)
    return 1;
  CHECK(functions->C_SessionCancel(sessions[0], CKF_DIGEST));
  CK_ULONG digestLen = 32;
  CK_BYTE digest[32];
  if (functions->C_DigestFinal(sessions[0], digest, &digestLen) != CKR_OPERATION_NOT_INITIALIZED)
    return 1;
  CHECK(functions->C_DigestInit(sessions[0], &digestMechanism));
  digestLen = 99;
  CHECK(functions->C_DigestFinal(sessions[0], NULL, &digestLen));
  if (digestLen != 32)
    return 1;
  digestLen = 1;
  if (functions->C_DigestFinal(sessions[0], digest, &digestLen) != CKR_BUFFER_TOO_SMALL || digestLen != 32)
    return 1;
  CHECK(functions->C_DigestFinal(sessions[0], digest, &digestLen));

  CHECK(functions->C_FindObjectsInit(sessions[0], NULL, 0));
  if (functions->C_FindObjectsInit(sessions[0], NULL, 0) != CKR_OPERATION_ACTIVE)
    return 1;
  CHECK(functions->C_SessionCancel(sessions[0], CKF_FIND_OBJECTS));
  if (functions->C_FindObjectsFinal(sessions[0]) != CKR_OPERATION_NOT_INITIALIZED)
    return 1;
  if (functions->C_MessageSignInit(sessions[0], NULL, 0) != CKR_FUNCTION_NOT_SUPPORTED)
    return 1;
  CK_UTF8CHAR username[] = "unsupported";
  if (functions->C_LoginUser(sessions[0], CKU_USER, (CK_UTF8CHAR_PTR)pin, (CK_ULONG)strlen(pin), username,
                             sizeof(username) - 1) != CKR_ARGUMENTS_BAD)
    return 1;

  CHECK(functions->C_LoginUser(sessions[0], CKU_USER, (CK_UTF8CHAR_PTR)pin, (CK_ULONG)strlen(pin), NULL, 0));
  CK_SESSION_INFO info;
  CHECK(functions->C_GetSessionInfo(sessions[1], &info));
  if (info.state != CKS_RW_USER_FUNCTIONS)
    return 1;
  if (testSessionSecretLifecycle(functions, sessions[0]) != 0)
    return 1;

  CK_SESSION_HANDLE readOnlySession;
  CHECK(functions->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, &readOnlySession));
  CHECK(functions->C_GetSessionInfo(readOnlySession, &info));
  if (info.state != CKS_RO_USER_FUNCTIONS)
    return 1;
  CHECK(functions->C_Logout(sessions[1]));
  CHECK(functions->C_GetSessionInfo(sessions[0], &info));
  if (info.state != CKS_RW_PUBLIC_SESSION)
    return 1;

  CK_BYTE managementKey[24] = {0}; // Preflight rejection must precede card authentication.
  if (functions->C_Login(sessions[0], CKU_SO, managementKey, sizeof(managementKey)) != CKR_SESSION_READ_ONLY_EXISTS)
    return 1;
  CHECK(functions->C_CloseSession(readOnlySession));
  if (functions->C_Login(readOnlySession, CKU_SO, managementKey, sizeof(managementKey)) != CKR_SESSION_HANDLE_INVALID)
    return 1;

  CK_SESSION_HANDLE anotherReadOnly;
  CHECK(functions->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, &anotherReadOnly));
  if (functions->C_Login(anotherReadOnly, CKU_SO, managementKey, sizeof(managementKey)) != CKR_SESSION_READ_ONLY)
    return 1;
  CHECK(functions->C_CloseSession(anotherReadOnly));

  for (CK_ULONG i = 0; i < 16; i++)
    CHECK(functions->C_CloseSession(sessions[i]));
  return 0;
}

static int selectConfiguredSlot(CK_FUNCTION_LIST_3_2_PTR functions, CK_SLOT_ID_PTR selectedSlot) {
  const char *slotText = getenv("CNK_PIV_SLOT_ID");
  const char *expectedSerial = getenv("CNK_PIV_SERIAL");
  if (slotText == NULL || expectedSerial == NULL || expectedSerial[0] == '\0') {
    fprintf(stderr, "%s and %s are required to select the hardware token explicitly\n", "CNK_PIV_SLOT_ID",
            "CNK_PIV_SERIAL");
    return 1;
  }
  char *end = NULL;
  unsigned long requested = strtoul(slotText, &end, 0);
  if (end == slotText || *end != '\0') {
    fprintf(stderr, "Invalid %s value: %s\n", "CNK_PIV_SLOT_ID", slotText);
    return 1;
  }

  CK_ULONG slotCount = 0;
  CHECK(functions->C_GetSlotList(CK_TRUE, NULL, &slotCount));
  if (slotCount == 0)
    return 1;
  CK_SLOT_ID *slots = calloc(slotCount, sizeof(*slots));
  if (slots == NULL)
    return 1;
  CK_ULONG capacity = slotCount;
  CK_RV rv = functions->C_GetSlotList(CK_TRUE, slots, &capacity);
  if (rv != CKR_OK) {
    free(slots);
    fprintf(stderr, "C_GetSlotList failed: 0x%lx\n", rv);
    return 1;
  }

  int found = 0;
  for (CK_ULONG i = 0; i < capacity; i++) {
    if (slots[i] != (CK_SLOT_ID)requested)
      continue;
    CK_TOKEN_INFO info;
    rv = functions->C_GetTokenInfo(slots[i], &info);
    if (rv != CKR_OK)
      break;
    char serial[sizeof(info.serialNumber) + 1];
    memcpy(serial, info.serialNumber, sizeof(info.serialNumber));
    serial[sizeof(info.serialNumber)] = '\0';
    for (size_t j = sizeof(info.serialNumber); j > 0 && (serial[j - 1] == ' ' || serial[j - 1] == '\0'); j--)
      serial[j - 1] = '\0';
    if (strcmp(serial, expectedSerial) != 0) {
      fprintf(stderr, "Slot %lu serial mismatch: expected %s, found %s\n", slots[i], expectedSerial, serial);
      break;
    }
    *selectedSlot = slots[i];
    found = 1;
    printf("Selected slot %lu with serial %s\n", slots[i], serial);
    break;
  }
  free(slots);
  if (!found)
    fprintf(stderr, "Requested slot %lu with serial %s is not present\n", requested, expectedSerial);
  return found ? 0 : 1;
}

static int run(CK_FUNCTION_LIST_3_2_PTR functions, const char *pin) {
  CK_SLOT_ID eventSlot = CK_UNAVAILABLE_INFORMATION;
  if (functions->C_WaitForSlotEvent(CKF_DONT_BLOCK << 1, &eventSlot, NULL) != CKR_ARGUMENTS_BAD ||
      functions->C_WaitForSlotEvent(CKF_DONT_BLOCK, NULL, NULL) != CKR_ARGUMENTS_BAD ||
      functions->C_WaitForSlotEvent(CKF_DONT_BLOCK, &eventSlot, &eventSlot) != CKR_ARGUMENTS_BAD)
    return 1;
  CK_SLOT_ID slot;
  if (selectConfiguredSlot(functions, &slot))
    return 1;
  return testFunctionListAndSessions(functions, slot, pin);
}

int main(int argc, char **argv) {
  const char *pin = getenv("CNK_PIV_PIN");
  if (argc != 2 || pin == NULL) {
    fprintf(stderr, "usage: test_abi <pkcs11-library>; set CNK_PIV_PIN, CNK_PIV_SLOT_ID and CNK_PIV_SERIAL\n");
    return 2;
  }
#ifdef _WIN32
  HMODULE library = LoadLibraryA(argv[1]);
  if (library == NULL)
    return 1;
  CK_C_GetInterface getInterface = (CK_C_GetInterface)GetProcAddress(library, "C_GetInterface");
#else
  void *library = dlopen(argv[1], RTLD_NOW);
  if (library == NULL)
    return 1;
  CK_C_GetInterface getInterface = (CK_C_GetInterface)dlsym(library, "C_GetInterface");
#endif
  int failed = 1;
  CK_VERSION version = {3, 2};
  CK_INTERFACE_PTR selected = NULL;
  if (getInterface && getInterface((CK_UTF8CHAR_PTR) "PKCS 11", &version, &selected, 0) == CKR_OK) {
    CK_FUNCTION_LIST_3_2_PTR functions = selected->pFunctionList;
    if (functions->C_Initialize(NULL) == CKR_OK) {
      failed = run(functions, pin);
      // Finalization also closes sessions and secrets after any failed assertion.
      if (functions->C_Finalize(NULL) != CKR_OK)
        failed = 1;
    }
  }
#ifdef _WIN32
  FreeLibrary(library);
#else
  dlclose(library);
#endif
  puts(failed ? "FAIL native ABI/session contracts" : "PASS native ABI/session contracts");
  return failed;
}
