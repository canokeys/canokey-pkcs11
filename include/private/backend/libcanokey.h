#ifndef CNK_BACKEND_LIBCANOKEY_H
#define CNK_BACKEND_LIBCANOKEY_H

#include "pkcs11.h"
#include <libcanokey/canokey.h>

struct CNK_PKCS11_SESSION;
CK_RV cnk_ensure_libcanokey_profile(struct CNK_PKCS11_SESSION *session);

#endif
