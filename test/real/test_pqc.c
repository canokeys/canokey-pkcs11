#include "pkcs11.h"

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
      fprintf(stderr, "%s failed: 0x%lx\n", #call, checkRv);                                                           \
      return 1;                                                                                                        \
    }                                                                                                                  \
  } while (0)

static void makeKeyTemplates(CK_BYTE *id, CK_KEY_TYPE *keyType, CK_ULONG *parameterSet, CK_ATTRIBUTE publicTemplate[5],
                             CK_ATTRIBUTE privateTemplate[7]) {
  static CK_OBJECT_CLASS publicClass = CKO_PUBLIC_KEY, privateClass = CKO_PRIVATE_KEY;
  static CK_BBOOL trueValue = CK_TRUE;
  publicTemplate[0] = (CK_ATTRIBUTE){CKA_CLASS, &publicClass, sizeof(publicClass)};
  publicTemplate[1] = (CK_ATTRIBUTE){CKA_TOKEN, &trueValue, sizeof(trueValue)};
  publicTemplate[2] = (CK_ATTRIBUTE){CKA_KEY_TYPE, keyType, sizeof(*keyType)};
  publicTemplate[3] = (CK_ATTRIBUTE){CKA_ID, id, sizeof(*id)};
  publicTemplate[4] = (CK_ATTRIBUTE){CKA_PARAMETER_SET, parameterSet, sizeof(*parameterSet)};
  privateTemplate[0] = (CK_ATTRIBUTE){CKA_CLASS, &privateClass, sizeof(privateClass)};
  privateTemplate[1] = (CK_ATTRIBUTE){CKA_TOKEN, &trueValue, sizeof(trueValue)};
  privateTemplate[2] = (CK_ATTRIBUTE){CKA_PRIVATE, &trueValue, sizeof(trueValue)};
  privateTemplate[3] = (CK_ATTRIBUTE){CKA_KEY_TYPE, keyType, sizeof(*keyType)};
  privateTemplate[4] = (CK_ATTRIBUTE){CKA_ID, id, sizeof(*id)};
  privateTemplate[5] =
      (CK_ATTRIBUTE){*keyType == CKK_ML_DSA ? CKA_SIGN : CKA_DECAPSULATE, &trueValue, sizeof(trueValue)};
  privateTemplate[6] = (CK_ATTRIBUTE){CKA_PARAMETER_SET, parameterSet, sizeof(*parameterSet)};
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: test_pqc <pkcs11-library>\n");
    return 2;
  }
  const char *pin = getenv("CNK_PIV_PIN");
  if (pin == NULL) {
    fprintf(stderr, "CNK_PIV_PIN is required\n");
    return 2;
  }
#ifdef _WIN32
  HMODULE library = LoadLibraryA(argv[1]);
  CK_C_GetInterface getInterface = (CK_C_GetInterface)GetProcAddress(library, "C_GetInterface");
#else
  void *library = dlopen(argv[1], RTLD_NOW);
  CK_C_GetInterface getInterface = (CK_C_GetInterface)dlsym(library, "C_GetInterface");
#endif
  if (library == NULL || getInterface == NULL)
    return 1;

  CK_VERSION version = {3, 2};
  CK_INTERFACE_PTR selectedInterface = NULL;
  CHECK(getInterface((CK_UTF8CHAR_PTR) "PKCS 11", &version, &selectedInterface, 0));
  CK_FUNCTION_LIST_3_2_PTR functions = selectedInterface->pFunctionList;
  CHECK(functions->C_Initialize(NULL));

  CK_ULONG slotCount = 1;
  CK_SLOT_ID slot;
  CHECK(functions->C_GetSlotList(CK_TRUE, &slot, &slotCount));
  CK_SESSION_HANDLE session;
  CHECK(functions->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session));
  CK_BYTE managementKey[] = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
  CHECK(functions->C_Login(session, CKU_SO, managementKey, sizeof(managementKey)));

  CK_OBJECT_HANDLE mldsaPublic, mldsaPrivate, mlkemPublic, mlkemPrivate;
  CK_ATTRIBUTE publicTemplate[5], privateTemplate[7];
  CK_BYTE id = 23;
  CK_KEY_TYPE keyType = CKK_ML_DSA;
  CK_ULONG parameterSet = CKP_ML_DSA_65;
  makeKeyTemplates(&id, &keyType, &parameterSet, publicTemplate, privateTemplate);
  CK_MECHANISM mechanism = {CKM_ML_DSA_KEY_PAIR_GEN, NULL, 0};
  CHECK(functions->C_GenerateKeyPair(session, &mechanism, publicTemplate, 5, privateTemplate, 7, &mldsaPublic,
                                     &mldsaPrivate));

  id = 24;
  keyType = CKK_ML_KEM;
  parameterSet = CKP_ML_KEM_768;
  makeKeyTemplates(&id, &keyType, &parameterSet, publicTemplate, privateTemplate);
  mechanism.mechanism = CKM_ML_KEM_KEY_PAIR_GEN;
  CHECK(functions->C_GenerateKeyPair(session, &mechanism, publicTemplate, 5, privateTemplate, 7, &mlkemPublic,
                                     &mlkemPrivate));
  CHECK(functions->C_Logout(session));
  CHECK(functions->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)pin, (CK_ULONG)strlen(pin)));

  CK_BYTE message[] = "CanoKey PKCS11 3.2 ML-DSA streaming test";
  CK_BYTE signature[3309];
  CK_ULONG signatureLen = sizeof(signature);
  mechanism.mechanism = CKM_ML_DSA;
  CHECK(functions->C_SignInit(session, &mechanism, mldsaPrivate));
  CHECK(functions->C_SignUpdate(session, message, 13));
  CHECK(functions->C_SignUpdate(session, message + 13, sizeof(message) - 1 - 13));
  CHECK(functions->C_SignFinal(session, signature, &signatureLen));
  if (signatureLen != sizeof(signature))
    return 1;

  CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
  CK_KEY_TYPE secretType = CKK_GENERIC_SECRET;
  CK_BBOOL extractable = CK_TRUE;
  CK_ATTRIBUTE secretTemplate[] = {{CKA_CLASS, &secretClass, sizeof(secretClass)},
                                   {CKA_KEY_TYPE, &secretType, sizeof(secretType)},
                                   {CKA_EXTRACTABLE, &extractable, sizeof(extractable)}};
  CK_BYTE ciphertext[1088];
  CK_ULONG ciphertextLen = sizeof(ciphertext);
  CK_OBJECT_HANDLE encapsulatedSecret, decapsulatedSecret;
  mechanism.mechanism = CKM_ML_KEM;
  CHECK(functions->C_EncapsulateKey(session, &mechanism, mlkemPublic, secretTemplate, 3, ciphertext, &ciphertextLen,
                                    &encapsulatedSecret));
  CHECK(functions->C_DecapsulateKey(session, &mechanism, mlkemPrivate, secretTemplate, 3, ciphertext, ciphertextLen,
                                    &decapsulatedSecret));
  CK_BYTE secretA[32], secretB[32];
  CK_ATTRIBUTE secretAValue = {CKA_VALUE, secretA, sizeof(secretA)};
  CK_ATTRIBUTE secretBValue = {CKA_VALUE, secretB, sizeof(secretB)};
  CHECK(functions->C_GetAttributeValue(session, encapsulatedSecret, &secretAValue, 1));
  CHECK(functions->C_GetAttributeValue(session, decapsulatedSecret, &secretBValue, 1));
  if (secretAValue.ulValueLen != 32 || secretBValue.ulValueLen != 32 || memcmp(secretA, secretB, 32) != 0)
    return 1;

  printf("PKCS#11 3.2 ML-DSA-65 and ML-KEM-768 hardware test passed\n");
  CHECK(functions->C_CloseSession(session));
  CHECK(functions->C_Finalize(NULL));
  return 0;
}
