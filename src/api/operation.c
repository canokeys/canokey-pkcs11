#include "api/operation.h"

#include "backend/pcsc.h"

#include <mbedtls/platform_util.h>
#include <string.h>

void cnk_reset_digesting_context(CNK_PKCS11_SESSION *session) {
  if (session == NULL)
    return;
  if (session->digestingContext.mechanismType != 0)
    mbedtls_md_free(&session->digestingContext.context);
  memset(&session->digestingContext, 0, sizeof(session->digestingContext));
}

void cnk_reset_signing_context(CNK_PKCS11_SESSION *session) {
  if (session == NULL)
    return;
  CK_BBOOL ownsDigestContext = session->signingContext.ownsDigestContext;
  ck_free(session->signingContext.mechanism.pParameter);
  if (session->signingContext.message != NULL) {
    mbedtls_platform_zeroize(session->signingContext.message, session->signingContext.messageCapacity);
    ck_free(session->signingContext.message);
  }
  mbedtls_platform_zeroize(session->signingContext.contextPin, sizeof(session->signingContext.contextPin));
  memset(&session->signingContext, 0, sizeof(session->signingContext));
  if (ownsDigestContext)
    cnk_reset_digesting_context(session);
}

void cnk_reset_verifying_context(CNK_PKCS11_SESSION *session) {
  if (session == NULL)
    return;
  CK_BBOOL ownsDigestContext = session->verifyingContext.ownsDigestContext;
  ck_free(session->verifyingContext.mechanism.pParameter);
  if (session->verifyingContext.message != NULL) {
    mbedtls_platform_zeroize(session->verifyingContext.message, session->verifyingContext.messageCapacity);
    ck_free(session->verifyingContext.message);
  }
  memset(&session->verifyingContext, 0, sizeof(session->verifyingContext));
  if (ownsDigestContext)
    cnk_reset_digesting_context(session);
}

void cnk_reset_encrypting_context(CNK_PKCS11_SESSION *session) {
  if (session == NULL)
    return;
  ck_free(session->encryptingContext.mechanism.pParameter);
  memset(&session->encryptingContext, 0, sizeof(session->encryptingContext));
}

void cnk_reset_decrypting_context(CNK_PKCS11_SESSION *session) {
  if (session == NULL)
    return;
  ck_free(session->decryptingContext.mechanism.pParameter);
  mbedtls_platform_zeroize(session->decryptingContext.contextPin, sizeof(session->decryptingContext.contextPin));
  memset(&session->decryptingContext, 0, sizeof(session->decryptingContext));
}
