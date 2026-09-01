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
      fprintf(stderr, "%s:%d: %s failed: 0x%lx\n", __FILE__, __LINE__, #call, checkRv);                                \
      return 1;                                                                                                        \
    }                                                                                                                  \
  } while (0)

typedef CK_RV (*CNK_LOGIN_PIN_MANAGED)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);

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

static int exercisePqcPrivateOperations(CK_FUNCTION_LIST_3_2_PTR functions, CK_SESSION_HANDLE session,
                                        CK_OBJECT_HANDLE mldsaPublic, CK_OBJECT_HANDLE mldsaPrivate,
                                        CK_OBJECT_HANDLE mlkemPublic, CK_OBJECT_HANDLE mlkemPrivate, const char *pin,
                                        CK_BBOOL contextSpecific) {
  CK_MECHANISM mechanism = {CKM_ML_DSA, NULL, 0};
  CK_BYTE message[] = "CanoKey PKCS11 3.2 ML-DSA streaming test";
  CK_BYTE signature[3309];
  CK_ULONG signatureLen = sizeof(signature);
  CHECK(functions->C_SignInit(session, &mechanism, mldsaPrivate));
  if (contextSpecific) {
    CHECK(functions->C_SessionCancel(session, CKF_SIGN));
    if (functions->C_Login(session, CKU_CONTEXT_SPECIFIC, (CK_UTF8CHAR_PTR)pin, (CK_ULONG)strlen(pin)) !=
        CKR_OPERATION_NOT_INITIALIZED)
      return 1;
    CHECK(functions->C_SignInit(session, &mechanism, mldsaPrivate));
    signatureLen = 123;
    CHECK(functions->C_Sign(session, message, sizeof(message) - 1, NULL, &signatureLen));
    if (signatureLen != sizeof(signature))
      return 1;
    if (functions->C_Sign(session, message, sizeof(message) - 1, signature, &signatureLen) != CKR_USER_NOT_LOGGED_IN)
      return 1;
    CHECK(functions->C_Login(session, CKU_CONTEXT_SPECIFIC, (CK_UTF8CHAR_PTR)pin, (CK_ULONG)strlen(pin)));
    signatureLen = 1;
    if (functions->C_Sign(session, message, sizeof(message) - 1, signature, &signatureLen) != CKR_BUFFER_TOO_SMALL ||
        signatureLen != sizeof(signature))
      return 1;
    CHECK(functions->C_Sign(session, message, sizeof(message) - 1, signature, &signatureLen));
    if (functions->C_Login(session, CKU_CONTEXT_SPECIFIC, (CK_UTF8CHAR_PTR)pin, (CK_ULONG)strlen(pin)) !=
        CKR_OPERATION_NOT_INITIALIZED)
      return 1;
  } else {
    CHECK(functions->C_SignUpdate(session, message, 13));
    CHECK(functions->C_SignUpdate(session, message + 13, sizeof(message) - 1 - 13));
    CHECK(functions->C_SignFinal(session, signature, &signatureLen));
  }
  if (signatureLen != sizeof(signature))
    return 1;

  CHECK(functions->C_VerifyInit(session, &mechanism, mldsaPublic));
  CHECK(functions->C_VerifyUpdate(session, message, 11));
  CHECK(functions->C_VerifyUpdate(session, message + 11, sizeof(message) - 1 - 11));
  CHECK(functions->C_VerifyFinal(session, signature, signatureLen));
  CHECK(functions->C_VerifyInit(session, &mechanism, mldsaPublic));
  CHECK(functions->C_VerifyUpdate(session, message, sizeof(message) - 1));
  CHECK(functions->C_SessionCancel(session, CKF_VERIFY));
  if (functions->C_VerifyFinal(session, signature, signatureLen) != CKR_OPERATION_NOT_INITIALIZED)
    return 1;
  signature[0] ^= 1;
  CHECK(functions->C_VerifyInit(session, &mechanism, mldsaPublic));
  if (functions->C_Verify(session, message, sizeof(message) - 1, signature, signatureLen) != CKR_SIGNATURE_INVALID)
    return 1;
  signature[0] ^= 1;
  CHECK(functions->C_VerifyInit(session, &mechanism, mldsaPublic));
  if (functions->C_Verify(session, message, sizeof(message) - 1, signature, signatureLen - 1) !=
      CKR_SIGNATURE_LEN_RANGE)
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
  return 0;
}

// Exercise the mutable surface of host-resident session keys without changing
// any additional PIV slots. A rejected update also checks transactional
// rollback.
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

static int testTokenRandom(CK_FUNCTION_LIST_3_2_PTR functions, CK_SLOT_ID slot, CK_SESSION_HANDLE session) {
  CK_TOKEN_INFO tokenInfo;
  CHECK(functions->C_GetTokenInfo(slot, &tokenInfo));
  if ((tokenInfo.flags & CKF_RNG) == 0)
    return 1;

  if (functions->C_GenerateRandom(session, NULL, 1) != CKR_ARGUMENTS_BAD)
    return 1;
  CHECK(functions->C_GenerateRandom(session, NULL, 0));

  CK_BYTE first[602], second[600];
  memset(first, 0, sizeof(first));
  first[600] = 0xA5;
  first[601] = 0x5A;
  CHECK(functions->C_GenerateRandom(session, first, 600));
  CHECK(functions->C_GenerateRandom(session, second, sizeof(second)));
  if (first[600] != 0xA5 || first[601] != 0x5A || memcmp(first, second, sizeof(second)) == 0)
    return 1;

  CK_BYTE seed = 0x42;
  if (functions->C_SeedRandom(session, &seed, sizeof(seed)) != CKR_RANDOM_SEED_NOT_SUPPORTED)
    return 1;
  return 0;
}

static CK_RV findKeyPair(CK_FUNCTION_LIST_3_2_PTR functions, CK_SESSION_HANDLE session, CK_KEY_TYPE keyType,
                         CK_ATTRIBUTE_TYPE usage, CK_OBJECT_HANDLE_PTR publicKey, CK_OBJECT_HANDLE_PTR privateKey) {
  CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
  CK_BBOOL trueValue = CK_TRUE;
  CK_ATTRIBUTE privateTemplate[] = {
      {CKA_CLASS, &privateClass, sizeof(privateClass)},
      {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
      {usage, &trueValue, sizeof(trueValue)},
  };
  CK_RV rv = functions->C_FindObjectsInit(session, privateTemplate, 3);
  if (rv != CKR_OK)
    return rv;
  CK_ULONG count = 0;
  rv = functions->C_FindObjects(session, privateKey, 1, &count);
  CK_RV finalRv = functions->C_FindObjectsFinal(session);
  if (rv != CKR_OK)
    return rv;
  if (finalRv != CKR_OK)
    return finalRv;
  if (count == 0)
    return CKR_KEY_HANDLE_INVALID;

  CK_BYTE id;
  CK_ATTRIBUTE idAttribute = {CKA_ID, &id, sizeof(id)};
  rv = functions->C_GetAttributeValue(session, *privateKey, &idAttribute, 1);
  if (rv != CKR_OK)
    return rv;
  CK_OBJECT_CLASS publicClass = CKO_PUBLIC_KEY;
  CK_ATTRIBUTE publicTemplate[] = {
      {CKA_CLASS, &publicClass, sizeof(publicClass)},
      {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
      {CKA_ID, &id, sizeof(id)},
  };
  rv = functions->C_FindObjectsInit(session, publicTemplate, 3);
  if (rv != CKR_OK)
    return rv;
  count = 0;
  rv = functions->C_FindObjects(session, publicKey, 1, &count);
  finalRv = functions->C_FindObjectsFinal(session);
  if (rv != CKR_OK)
    return rv;
  if (finalRv != CKR_OK)
    return finalRv;
  return count == 1 ? CKR_OK : CKR_KEY_HANDLE_INVALID;
}

// Sign on-card and verify on-host across raw, combined-hash, and streaming APIs.
static int exerciseVerify(CK_FUNCTION_LIST_3_2_PTR functions, CK_SESSION_HANDLE session) {
  CK_OBJECT_HANDLE rsaPublic, rsaPrivate;
  CHECK(findKeyPair(functions, session, CKK_RSA, CKA_SIGN, &rsaPublic, &rsaPrivate));
  CK_BYTE message[] = "host verify regression";
  CK_BYTE signature[512];
  CK_ULONG signatureLen = sizeof(signature);
  CK_MECHANISM mechanism = {CKM_SHA256_RSA_PKCS, NULL, 0};

  CHECK(functions->C_SignInit(session, &mechanism, rsaPrivate));
  CHECK(functions->C_SessionCancel(session, CKF_SIGN));
  if (functions->C_SignFinal(session, signature, &signatureLen) != CKR_OPERATION_NOT_INITIALIZED)
    return 1;
  CK_MECHANISM digestMechanism = {CKM_SHA256, NULL, 0};
  CHECK(functions->C_DigestInit(session, &digestMechanism));
  CHECK(functions->C_SessionCancel(session, CKF_DIGEST));

  CHECK(functions->C_VerifyInit(session, &mechanism, rsaPublic));
  CHECK(functions->C_SessionCancel(session, CKF_VERIFY));
  if (functions->C_VerifyFinal(session, signature, signatureLen) != CKR_OPERATION_NOT_INITIALIZED)
    return 1;
  CHECK(functions->C_DigestInit(session, &digestMechanism));
  CHECK(functions->C_SessionCancel(session, CKF_DIGEST));

  CHECK(functions->C_SignInit(session, &mechanism, rsaPrivate));
  CHECK(functions->C_Sign(session, message, sizeof(message) - 1, signature, &signatureLen));

  // A combined-hash Verify owns a separate digest context and must coexist
  // with the session's independent Digest operation.
  CHECK(functions->C_DigestInit(session, &digestMechanism));
  CHECK(functions->C_VerifyInit(session, &mechanism, rsaPublic));
  CHECK(functions->C_Verify(session, message, sizeof(message) - 1, signature, signatureLen));
  CHECK(functions->C_DigestUpdate(session, message, sizeof(message) - 1));
  CK_BYTE independentDigest[32];
  CK_ULONG independentDigestLen = sizeof(independentDigest);
  CHECK(functions->C_DigestFinal(session, independentDigest, &independentDigestLen));

  CHECK(functions->C_VerifyInit(session, &mechanism, rsaPublic));
  CHECK(functions->C_VerifyUpdate(session, message, 5));
  CHECK(functions->C_VerifyUpdate(session, message + 5, sizeof(message) - 1 - 5));
  CHECK(functions->C_VerifyFinal(session, signature, signatureLen));
  signature[signatureLen - 1] ^= 1;
  CHECK(functions->C_VerifyInit(session, &mechanism, rsaPublic));
  if (functions->C_Verify(session, message, sizeof(message) - 1, signature, signatureLen) != CKR_SIGNATURE_INVALID)
    return 1;
  signature[signatureLen - 1] ^= 1;

  CK_RSA_PKCS_PSS_PARAMS pss = {CKM_SHA256, CKG_MGF1_SHA256, 32};
  mechanism = (CK_MECHANISM){CKM_SHA256_RSA_PKCS_PSS, &pss, sizeof(pss)};
  signatureLen = sizeof(signature);
  CHECK(functions->C_SignInit(session, &mechanism, rsaPrivate));
  CHECK(functions->C_Sign(session, message, sizeof(message) - 1, signature, &signatureLen));
  CHECK(functions->C_VerifyInit(session, &mechanism, rsaPublic));
  CHECK(functions->C_Verify(session, message, sizeof(message) - 1, signature, signatureLen));

  mechanism = (CK_MECHANISM){CKM_RSA_PKCS, NULL, 0};
  signatureLen = sizeof(signature);
  CHECK(functions->C_SignInit(session, &mechanism, rsaPrivate));
  CHECK(functions->C_Sign(session, message, sizeof(message) - 1, signature, &signatureLen));
  CHECK(functions->C_VerifyInit(session, &mechanism, rsaPublic));
  CHECK(functions->C_Verify(session, message, sizeof(message) - 1, signature, signatureLen));

  CHECK(functions->C_DigestInit(session, &digestMechanism));
  CHECK(functions->C_VerifyInit(session, &mechanism, rsaPublic));
  CHECK(functions->C_Verify(session, message, sizeof(message) - 1, signature, signatureLen));
  CK_BYTE digest[32];
  CK_ULONG digestLen = sizeof(digest);
  CHECK(functions->C_DigestFinal(session, digest, &digestLen));

  digestLen = sizeof(digest);
  CHECK(functions->C_DigestInit(session, &digestMechanism));
  CHECK(functions->C_Digest(session, message, sizeof(message) - 1, digest, &digestLen));
  mechanism = (CK_MECHANISM){CKM_RSA_PKCS_PSS, &pss, sizeof(pss)};
  signatureLen = sizeof(signature);
  CHECK(functions->C_SignInit(session, &mechanism, rsaPrivate));
  CHECK(functions->C_Sign(session, digest, digestLen, signature, &signatureLen));
  CHECK(functions->C_VerifyInit(session, &mechanism, rsaPublic));
  CHECK(functions->C_Verify(session, digest, digestLen, signature, signatureLen));

  CK_OBJECT_HANDLE ecPublic, ecPrivate;
  CHECK(findKeyPair(functions, session, CKK_EC, CKA_SIGN, &ecPublic, &ecPrivate));
  mechanism = (CK_MECHANISM){CKM_ECDSA_SHA256, NULL, 0};
  signatureLen = sizeof(signature);
  CHECK(functions->C_SignInit(session, &mechanism, ecPrivate));
  CHECK(functions->C_Sign(session, message, sizeof(message) - 1, signature, &signatureLen));
  CHECK(functions->C_VerifyInit(session, &mechanism, ecPublic));
  CHECK(functions->C_VerifyUpdate(session, message, 7));
  CHECK(functions->C_VerifyUpdate(session, message + 7, sizeof(message) - 1 - 7));
  CHECK(functions->C_VerifyFinal(session, signature, signatureLen));
  signature[0] ^= 1;
  CHECK(functions->C_VerifyInit(session, &mechanism, ecPublic));
  if (functions->C_Verify(session, message, sizeof(message) - 1, signature, signatureLen) != CKR_SIGNATURE_INVALID)
    return 1;
  mechanism = (CK_MECHANISM){CKM_ECDSA, NULL, 0};
  signatureLen = sizeof(signature);
  CHECK(functions->C_SignInit(session, &mechanism, ecPrivate));
  CHECK(functions->C_Sign(session, digest, digestLen, signature, &signatureLen));
  CHECK(functions->C_VerifyInit(session, &mechanism, ecPublic));
  CHECK(functions->C_Verify(session, digest, digestLen, signature, signatureLen));
  return 0;
}

static int encryptDecryptRoundTrip(CK_FUNCTION_LIST_3_2_PTR functions, CK_SESSION_HANDLE session,
                                   CK_OBJECT_HANDLE publicKey, CK_OBJECT_HANDLE privateKey, CK_MECHANISM *mechanism,
                                   CK_BYTE *plaintext, CK_ULONG plaintextLen) {
  CK_BYTE ciphertext[512], recovered[512];
  CK_ULONG ciphertextLen = 0;
  CHECK(functions->C_EncryptInit(session, mechanism, publicKey));
  CHECK(functions->C_Encrypt(session, plaintext, plaintextLen, NULL, &ciphertextLen));
  CK_ULONG smallLen = 1;
  if (functions->C_Encrypt(session, plaintext, plaintextLen, ciphertext, &smallLen) != CKR_BUFFER_TOO_SMALL ||
      smallLen != ciphertextLen)
    return 1;
  CHECK(functions->C_Encrypt(session, plaintext, plaintextLen, ciphertext, &ciphertextLen));

  CHECK(functions->C_DecryptInit(session, mechanism, privateKey));
  CK_ULONG recoveredLen = 0;
  CHECK(functions->C_Decrypt(session, ciphertext, ciphertextLen, NULL, &recoveredLen));
  if (recoveredLen > sizeof(recovered))
    return 1;
  CHECK(functions->C_Decrypt(session, ciphertext, ciphertextLen, recovered, &recoveredLen));
  return recoveredLen == plaintextLen && memcmp(recovered, plaintext, plaintextLen) == 0 ? 0 : 1;
}

// Host encryption must round-trip through the corresponding on-card private
// operation; OAEP also checks that C_EncryptInit deep-copies its label.
static int exerciseEncrypt(CK_FUNCTION_LIST_3_2_PTR functions, CK_SESSION_HANDLE session) {
  CK_OBJECT_HANDLE publicKey, privateKey;
  CHECK(findKeyPair(functions, session, CKK_RSA, CKA_DECRYPT, &publicKey, &privateKey));
  CK_BYTE plaintext[] = "host encrypt regression";
  CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL, 0};
  if (encryptDecryptRoundTrip(functions, session, publicKey, privateKey, &mechanism, plaintext,
                              sizeof(plaintext) - 1) != 0)
    return 1;

  CK_BYTE label[] = "oaep-label";
  CK_RSA_PKCS_OAEP_PARAMS oaep = {CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, label, sizeof(label) - 1};
  mechanism = (CK_MECHANISM){CKM_RSA_PKCS_OAEP, &oaep, sizeof(oaep)};
  CHECK(functions->C_EncryptInit(session, &mechanism, publicKey));
  CK_BYTE originalFirst = label[0];
  label[0] ^= 1;
  CK_BYTE ciphertext[512], recovered[512];
  CK_ULONG ciphertextLen = sizeof(ciphertext);
  CHECK(functions->C_Encrypt(session, plaintext, sizeof(plaintext) - 1, ciphertext, &ciphertextLen));
  label[0] = originalFirst;
  CHECK(functions->C_DecryptInit(session, &mechanism, privateKey));
  CK_ULONG recoveredLen = sizeof(recovered);
  CHECK(functions->C_Decrypt(session, ciphertext, ciphertextLen, recovered, &recoveredLen));
  if (recoveredLen != sizeof(plaintext) - 1 || memcmp(recovered, plaintext, recoveredLen) != 0)
    return 1;

  CK_ULONG modulusLen = 0;
  CK_ATTRIBUTE modulus = {CKA_MODULUS, NULL, 0};
  CHECK(functions->C_GetAttributeValue(session, publicKey, &modulus, 1));
  modulusLen = modulus.ulValueLen;
  if (modulusLen > sizeof(recovered))
    return 1;
  memset(recovered, 0, modulusLen);
  memcpy(recovered + modulusLen - sizeof(plaintext) + 1, plaintext, sizeof(plaintext) - 1);
  mechanism = (CK_MECHANISM){CKM_RSA_X_509, NULL, 0};
  return encryptDecryptRoundTrip(functions, session, publicKey, privateKey, &mechanism, recovered, modulusLen);
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
  CK_MECHANISM_TYPE *mechanisms = calloc(mechanismCount + 2, sizeof(*mechanisms));
  if (mechanisms == NULL)
    return 1;
  mechanisms[mechanismCount] = CK_UNAVAILABLE_INFORMATION;
  mechanisms[mechanismCount + 1] = CK_UNAVAILABLE_INFORMATION;
  CK_ULONG exactCount = mechanismCount;
  CHECK(functions->C_GetMechanismList(slot, mechanisms, &exactCount));
  if (exactCount != mechanismCount || mechanisms[mechanismCount] != CK_UNAVAILABLE_INFORMATION ||
      mechanisms[mechanismCount + 1] != CK_UNAVAILABLE_INFORMATION) {
    free(mechanisms);
    return 1;
  }
  for (CK_ULONG i = 0; i < mechanismCount; i++) {
    CK_MECHANISM_INFO mechanismInfo;
    CHECK(functions->C_GetMechanismInfo(slot, mechanisms[i], &mechanismInfo));
  }
  free(mechanisms);

  CK_SESSION_HANDLE sessions[16];
  for (CK_ULONG i = 0; i < 16; i++)
    CHECK(functions->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &sessions[i]));
  if (testTokenRandom(functions, slot, sessions[0]) != 0)
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

  CK_BYTE managementKey[] = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
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
  CNK_LOGIN_PIN_MANAGED loginPinManaged = (CNK_LOGIN_PIN_MANAGED)GetProcAddress(library, "C_CNK_LoginPinManaged");
#else
  void *library = dlopen(argv[1], RTLD_NOW);
  CK_C_GetInterface getInterface = (CK_C_GetInterface)dlsym(library, "C_GetInterface");
  CNK_LOGIN_PIN_MANAGED loginPinManaged = (CNK_LOGIN_PIN_MANAGED)dlsym(library, "C_CNK_LoginPinManaged");
#endif
  if (library == NULL || getInterface == NULL || loginPinManaged == NULL)
    return 1;

  CK_VERSION version = {3, 2};
  CK_INTERFACE_PTR selectedInterface = NULL;
  CHECK(getInterface((CK_UTF8CHAR_PTR) "PKCS 11", &version, &selectedInterface, 0));
  CK_FUNCTION_LIST_3_2_PTR functions = selectedInterface->pFunctionList;
  CHECK(functions->C_Initialize(NULL));

  CK_SLOT_ID eventSlot = CK_UNAVAILABLE_INFORMATION;
  if (functions->C_WaitForSlotEvent(CKF_DONT_BLOCK, &eventSlot, NULL) != CKR_NO_EVENT)
    return 1;
  if (functions->C_WaitForSlotEvent(CKF_DONT_BLOCK << 1, &eventSlot, NULL) != CKR_ARGUMENTS_BAD)
    return 1;
  if (functions->C_WaitForSlotEvent(CKF_DONT_BLOCK, NULL, NULL) != CKR_ARGUMENTS_BAD)
    return 1;
  if (functions->C_WaitForSlotEvent(CKF_DONT_BLOCK, &eventSlot, &eventSlot) != CKR_ARGUMENTS_BAD)
    return 1;

  CK_ULONG slotCount = 1;
  CK_SLOT_ID slot;
  CHECK(functions->C_GetSlotList(CK_TRUE, &slot, &slotCount));
  CK_SESSION_HANDLE pinManagedSession;
  CHECK(functions->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &pinManagedSession));
  CK_RV pinManagedRv = loginPinManaged(pinManagedSession, (CK_UTF8CHAR_PTR)pin, (CK_ULONG)strlen(pin));
  if (pinManagedRv != CKR_OK && pinManagedRv != CKR_ACTION_PROHIBITED)
    return 1;
  if (pinManagedRv == CKR_ACTION_PROHIBITED) {
    printf("PIN-managed login correctly rejected an active PUK\n");
    CK_SESSION_INFO info;
    CHECK(functions->C_GetSessionInfo(pinManagedSession, &info));
    if (info.state != CKS_RW_PUBLIC_SESSION || functions->C_Logout(pinManagedSession) != CKR_USER_NOT_LOGGED_IN)
      return 1;
  } else {
    CHECK(functions->C_Logout(pinManagedSession));
  }
  CHECK(functions->C_CloseSession(pinManagedSession));
  if (testFunctionListAndSessions(functions, slot, pin) != 0)
    return 1;
  CK_SESSION_HANDLE session;
  CHECK(functions->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session));
  CK_BYTE managementKey[] = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
  CHECK(functions->C_Login(session, CKU_SO, managementKey, sizeof(managementKey)));

  CK_OBJECT_HANDLE mldsaPublic, mldsaPrivate, mlkemPublic, mlkemPrivate;
  CK_ATTRIBUTE publicTemplate[5], privateTemplate[8];
  CK_BYTE id = 23;
  CK_KEY_TYPE keyType = CKK_ML_DSA;
  CK_ULONG parameterSet = CKP_ML_DSA_65;
  makeKeyTemplates(&id, &keyType, &parameterSet, publicTemplate, privateTemplate);
  CK_BBOOL trueValue = CK_TRUE;
  privateTemplate[7] = (CK_ATTRIBUTE){CKA_ALWAYS_AUTHENTICATE, &trueValue, sizeof(trueValue)};
  CK_MECHANISM mechanism = {CKM_ML_DSA_KEY_PAIR_GEN, NULL, 0};
  CHECK(functions->C_GenerateKeyPair(session, &mechanism, publicTemplate, 5, privateTemplate, 8, &mldsaPublic,
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

  if (exercisePqcPrivateOperations(functions, session, mldsaPublic, mldsaPrivate, mlkemPublic, mlkemPrivate, pin,
                                   CK_TRUE) != 0)
    return 1;

  CHECK(functions->C_CloseSession(session));
  CHECK(functions->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session));
  CHECK(functions->C_Login(session, CKU_SO, managementKey, sizeof(managementKey)));

  CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
  CK_BYTE mldsaSeed[32], mlkemSeed[64];
  for (CK_ULONG i = 0; i < sizeof(mldsaSeed); i++)
    mldsaSeed[i] = (CK_BYTE)(0x20 + i);
  for (CK_ULONG i = 0; i < sizeof(mlkemSeed); i++)
    mlkemSeed[i] = (CK_BYTE)(0x60 + i);

  id = 23;
  keyType = CKK_ML_DSA;
  parameterSet = CKP_ML_DSA_65;
  CK_ATTRIBUTE mldsaImportTemplate[] = {
      {CKA_CLASS, &privateClass, sizeof(privateClass)},
      {CKA_TOKEN, &trueValue, sizeof(trueValue)},
      {CKA_PRIVATE, &trueValue, sizeof(trueValue)},
      {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
      {CKA_ID, &id, sizeof(id)},
      {CKA_SIGN, &trueValue, sizeof(trueValue)},
      {CKA_PARAMETER_SET, &parameterSet, sizeof(parameterSet)},
      {CKA_SEED, mldsaSeed, sizeof(mldsaSeed)},
  };
  CHECK(functions->C_CreateObject(session, mldsaImportTemplate,
                                  sizeof(mldsaImportTemplate) / sizeof(mldsaImportTemplate[0]), &mldsaPrivate));

  id = 24;
  keyType = CKK_ML_KEM;
  parameterSet = CKP_ML_KEM_768;
  CK_ATTRIBUTE mlkemImportTemplate[] = {
      {CKA_CLASS, &privateClass, sizeof(privateClass)},
      {CKA_TOKEN, &trueValue, sizeof(trueValue)},
      {CKA_PRIVATE, &trueValue, sizeof(trueValue)},
      {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
      {CKA_ID, &id, sizeof(id)},
      {CKA_DECAPSULATE, &trueValue, sizeof(trueValue)},
      {CKA_PARAMETER_SET, &parameterSet, sizeof(parameterSet)},
      {CKA_SEED, mlkemSeed, sizeof(mlkemSeed)},
  };
  CHECK(functions->C_CreateObject(session, mlkemImportTemplate,
                                  sizeof(mlkemImportTemplate) / sizeof(mlkemImportTemplate[0]), &mlkemPrivate));

  CK_ATTRIBUTE seedQuery = {CKA_SEED, NULL, 0};
  if (functions->C_GetAttributeValue(session, mldsaPrivate, &seedQuery, 1) != CKR_ATTRIBUTE_SENSITIVE)
    return 1;

  CHECK(functions->C_Logout(session));
  CHECK(functions->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)pin, (CK_ULONG)strlen(pin)));
  if (exercisePqcPrivateOperations(functions, session, mldsaPublic, mldsaPrivate, mlkemPublic, mlkemPrivate, pin,
                                   CK_FALSE) != 0)
    return 1;
  if (exerciseVerify(functions, session) != 0)
    return 1;
  if (exerciseEncrypt(functions, session) != 0)
    return 1;

  printf("PKCS#11 3.2 ML-DSA-65 and ML-KEM-768 generation/import hardware test passed\n");
  CHECK(functions->C_CloseSession(session));
  CHECK(functions->C_Finalize(NULL));
  return 0;
}
