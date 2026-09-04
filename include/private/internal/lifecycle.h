#ifndef CNK_INTERNAL_LIFECYCLE_H
#define CNK_INTERNAL_LIFECYCLE_H

#include "pkcs11.h"

void cnk_lifecycle_lock(void);
void cnk_lifecycle_unlock(void);
typedef struct {
  CK_BBOOL active;
} CNK_API_ADMISSION_GUARD;
CK_RV cnk_api_admission_begin(CNK_API_ADMISSION_GUARD *guard);
void cnk_api_admission_end(CNK_API_ADMISSION_GUARD *guard);

// True while a previous initialize/finalize attempt still owns resources that
// must be cleaned up before the process-wide binding can change.
CK_BBOOL cnk_cleanup_is_pending(void);

#endif
