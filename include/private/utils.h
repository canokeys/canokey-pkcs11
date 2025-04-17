#ifndef UTILS_H
#define UTILS_H

#include "logging.h"

#define N_VA_ARGS_(_8,_7,_6,_5,_4,_3,_2,_1, N, ...) N
#define N_VA_ARGS(...) N_VA_ARGS_(__VA_ARGS__ __VA_OPT__(,) 8,7,6,5,4,3,2,1,0)
#define FOREACH_0(FN, ...) 
#define FOREACH_1(FN, E, ...) FN(E) 
#define FOREACH_2(FN, E, ...) FN(E) FOREACH_1(FN, __VA_ARGS__)
#define FOREACH_3(FN, E, ...) FN(E) FOREACH_2(FN, __VA_ARGS__)
#define FOREACH_4(FN, E, ...) FN(E) FOREACH_3(FN, __VA_ARGS__)
#define FOREACH_5(FN, E, ...) FN(E) FOREACH_4(FN, __VA_ARGS__)
#define FOREACH_6(FN, E, ...) FN(E) FOREACH_5(FN, __VA_ARGS__)
#define FOREACH_7(FN, E, ...) FN(E) FOREACH_6(FN, __VA_ARGS__)
#define FOREACH_8(FN, E, ...) FN(E) FOREACH_7(FN, __VA_ARGS__)
#define FOREACH__(FN, NARGS, ...) FOREACH_##NARGS(FN, __VA_ARGS__) 
#define FOREACH_(FN, NARGS, ...) FOREACH__(FN, NARGS, __VA_ARGS__)
#define FOREACH(FN, ...) FOREACH_(FN, N_VA_ARGS(__VA_ARGS__), __VA_ARGS__)

#define CNK_RET_OK CNK_RETURN(CKR_OK, "Success")

#define CNK_RET_UNIMPL CNK_RETURN(CKR_FUNCTION_NOT_SUPPORTED, "Not implemented")

#define CNK_RET_FWD(EXP) CNK_RETURN(EXP, "Directly forwarded")

#define CNK_ENSURE_EQUAL_REASON(EXP, EXPECTED, REASON)                                                                 \
  if ((EXP) != (EXPECTED)) {                                                                                           \
    CNK_RETURN(CKR_ARGUMENTS_BAD, REASON);                                                                             \
  }

#define CNK_ENSURE_EQUAL(EXP, EXPECTED) CNK_ENSURE_EQUAL_REASON(EXP, EXPECTED, #EXP " != " #EXPECTED)

#define CNK_ENSURE_NONNULL_(PTR)                                                                                       \
  do {                                                                                                                 \
    __typeof__((PTR)) _ptr = (PTR);                                                                                        \
    if (_ptr == NULL) {                                                                                                \
      CNK_RETURN(CKR_ARGUMENTS_BAD, #PTR " is NULL");                                                                  \
    }                                                                                                                  \
    __builtin_assume(_ptr != NULL);                                                                                    \
  } while (0);

#define CNK_ENSURE_NONNULL(...) FOREACH(CNK_ENSURE_NONNULL_, __VA_ARGS__)

#define CNK_ENSURE_NULL_(PTR)                                                                                          \
  do {                                                                                                                 \
    __typeof__((PTR)) _ptr = (PTR);                                                                                        \
    if (_ptr != NULL) {                                                                                                \
      CNK_RETURN(CKR_ARGUMENTS_BAD, #PTR " is not NULL");                                                              \
    }                                                                                                                  \
    __builtin_assume(_ptr == NULL);                                                                                    \
  } while (0);

#define CNK_ENSURE_NULL(...) FOREACH(CNK_ENSURE_NULL_, __VA_ARGS__)

#define CNK_ENSURE_OK(EXP)                                                                                             \
  ({                                                                                                                   \
    CK_RV _rv = (EXP);                                                                                                 \
    if (_rv != CKR_OK)                                                                                                 \
      CNK_RETURN(_rv, #EXP " failed");                                                                                 \
    CKR_OK;                                                                                                            \
  })

#define CNK_MARK_UNUSED(VAR) (void) VAR;

#define CNK_UNUSED(...)                                                                                                \
  do {                                                                                                                 \
    FOREACH(CNK_MARK_UNUSED, __VA_ARGS__)                                                                              \
  } while (0);

char *ck_strcasestr(const char *str, const char *pattern);

#endif // UTILS_H
