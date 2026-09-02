#ifndef CNK_INTERNAL_LIFECYCLE_H
#define CNK_INTERNAL_LIFECYCLE_H

#include "pkcs11.h"

void cnk_lifecycle_lock(void);
void cnk_lifecycle_unlock(void);

// True while a previous initialize/finalize attempt still owns resources that
// must be cleaned up before the process-wide binding can change.
CK_BBOOL cnk_cleanup_is_pending(void);

#endif
