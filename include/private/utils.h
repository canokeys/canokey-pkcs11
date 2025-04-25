#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>

#define N_VA_ARGS_(_8, _7, _6, _5, _4, _3, _2, _1, N, ...) N
#define N_VA_ARGS(...) N_VA_ARGS_(__VA_ARGS__ __VA_OPT__(, ) 8, 7, 6, 5, 4, 3, 2, 1, 0)
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

#if defined(__has_builtin)
#define CNK_HAS_BUILTIN(x) __has_builtin(x)
#else
#define CNK_HAS_BUILTIN(x) 0
#endif

#if CNK_HAS_BUILTIN(__builtin_expect)
#define CNK_LIKELY(x) __builtin_expect(!!(x), 1)
#define CNK_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define CNK_LIKELY(x) x
#define CNK_UNLIKELY(x) x
#endif

#if CNK_HAS_BUILTIN(__builtin_assume)
#define CNK_ASSUME(x) __builtin_assume(x)
#elif CNK_HAS_BUILTIN(__builtin_unreachable)
#define CNK_ASSUME(x)                                                                                                  \
  do {                                                                                                                 \
    if (!(x))                                                                                                          \
      __builtin_unreachable();                                                                                         \
  } while (0)
#elif defined(_MSC_VER)
#define CNK_ASSUME(x) __assume(x)
#else
#define CNK_ASSUME(x)                                                                                                  \
  do {                                                                                                                 \
  } while (0)
#endif

#if CNK_HAS_BUILTIN(typeof) || __STDC_VERSION__ >= 202311L
#define CNK_TYPEOF(x) typeof(x)
#else
#define CNK_TYPEOF(x) __typeof__(x)
#endif

#define CNK_ENSURE_EQUAL_REASON(EXP, EXPECTED, REASON)                                                                 \
  if ((EXP) != (EXPECTED)) {                                                                                           \
    CNK_RETURN(CKR_ARGUMENTS_BAD, REASON);                                                                             \
  }

#define CNK_ENSURE_EQUAL(EXP, EXPECTED) CNK_ENSURE_EQUAL_REASON(EXP, EXPECTED, #EXP " != " #EXPECTED)

#define CNK_ENSURE_NONNULL_(PTR)                                                                                       \
  do {                                                                                                                 \
    const CNK_TYPEOF((PTR)) _ptr = (PTR);                                                                              \
    if (_ptr == NULL) {                                                                                                \
      CNK_RETURN(CKR_ARGUMENTS_BAD, #PTR " is NULL");                                                                  \
    }                                                                                                                  \
    CNK_ASSUME(_ptr != NULL);                                                                                          \
  } while (0);

#define CNK_ENSURE_NONNULL(...) FOREACH(CNK_ENSURE_NONNULL_, __VA_ARGS__)

#define CNK_ENSURE_NULL_(PTR)                                                                                          \
  do {                                                                                                                 \
    const CNK_TYPEOF((PTR)) _ptr = (PTR);                                                                              \
    if (_ptr != NULL) {                                                                                                \
      CNK_RETURN(CKR_ARGUMENTS_BAD, #PTR " is not NULL");                                                              \
    }                                                                                                                  \
    CNK_ASSUME(_ptr == NULL);                                                                                          \
  } while (0);

#define CNK_ENSURE_NULL(...) FOREACH(CNK_ENSURE_NULL_, __VA_ARGS__)

#define CNK_ENSURE_OK(EXP)                                                                                             \
  ({                                                                                                                   \
    const CK_RV _rv = (EXP);                                                                                           \
    if (_rv != CKR_OK)                                                                                                 \
      CNK_RETURN(_rv, #EXP " failed");                                                                                 \
    CKR_OK;                                                                                                            \
  })

#define CNK_MARK_UNUSED(VAR) (void)VAR;

#define CNK_UNUSED(...)                                                                                                \
  do {                                                                                                                 \
    FOREACH(CNK_MARK_UNUSED, __VA_ARGS__)                                                                              \
  } while (0);

char *ck_strcasestr(const char *str, const char *pattern);

/**
 * Parse the length field in TLV (Tag-Length-Value) format according to ASN.1 DER rules.
 *
 * @param data Pointer to the start of the length field
 * @param len Total available length of the data buffer
 * @param fail Pointer to an int that will be set to 1 if parsing fails, 0 otherwise
 * @param length_size Pointer to a size_t that will be set to the number of bytes used for length encoding
 *
 * @return The parsed length value as a uint16_t
 */
uint16_t tlv_get_length_safe(const uint8_t *data, const size_t len, int *fail, size_t *length_size);

#endif // UTILS_H
