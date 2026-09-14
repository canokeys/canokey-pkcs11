#ifndef CNK_API_OPERATION_H
#define CNK_API_OPERATION_H

#include "api/session.h"

void cnk_reset_digesting_context(CNK_PKCS11_SESSION *session);
void cnk_reset_signing_context(CNK_PKCS11_SESSION *session);
void cnk_reset_verifying_context(CNK_PKCS11_SESSION *session);
void cnk_reset_encrypting_context(CNK_PKCS11_SESSION *session);
void cnk_reset_decrypting_context(CNK_PKCS11_SESSION *session);

#endif // CNK_API_OPERATION_H
