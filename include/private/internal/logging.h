#ifndef CNK_INTERNAL_LOGGING_H
#define CNK_INTERNAL_LOGGING_H

#pragma clang diagnostic ignored "-Wlanguage-extension-token"
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#pragma clang diagnostic ignored "-Wgnu-statement-expression-from-macro-expansion"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>

#include "internal/util.h"

enum CNK_LOG_LEVEL {
  CNK_LOG_LEVEL_TRACE = 0,
  CNK_LOG_LEVEL_DEBUG,
  CNK_LOG_LEVEL_INFO,
  CNK_LOG_LEVEL_WARN,
  CNK_LOG_LEVEL_ERROR,
  CNK_LOG_LEVEL_FATAL,
  CNK_LOG_LEVEL_NONE,
  CNK_LOG_LEVEL_SIZE,
};

extern atomic_int g_cnk_log_level;
extern atomic_bool g_cnk_unsafe_log_apdu;

extern CK_RV cnk_config_logging(const int level, FILE *file, CK_BBOOL unsafe_log_apdu);
extern void cnk_reset_logging(void);
extern void cnk_config_logging_from_env(void);

extern void cnk_printlogf(const int level, const char *function, const char *file, const int line, const char *format,
                          ...);

#define CNK_PRINTLOGF_IMPL(level, format, ...)                                                                         \
  cnk_printlogf((level), __FUNCTION__, __FILE__, __LINE__, format, ##__VA_ARGS__)
#define CNK_PRINTLOGF(level, format, ...)                                                                              \
  do {                                                                                                                 \
    const int _cnk_log_level = (level);                                                                                \
    if (CNK_LIKELY(_cnk_log_level < atomic_load(&g_cnk_log_level))) {                                                  \
      break;                                                                                                           \
    }                                                                                                                  \
    CNK_PRINTLOGF_IMPL(_cnk_log_level, format, ##__VA_ARGS__);                                                         \
  } while (0)
#define CNK_TRACE(format, ...) CNK_PRINTLOGF(CNK_LOG_LEVEL_TRACE, format, ##__VA_ARGS__)
#define CNK_DEBUG(format, ...) CNK_PRINTLOGF(CNK_LOG_LEVEL_DEBUG, format, ##__VA_ARGS__)
#define CNK_INFO(format, ...) CNK_PRINTLOGF(CNK_LOG_LEVEL_INFO, format, ##__VA_ARGS__)
#define CNK_WARN(format, ...) CNK_PRINTLOGF(CNK_LOG_LEVEL_WARN, format, ##__VA_ARGS__)
#define CNK_ERROR(format, ...) CNK_PRINTLOGF(CNK_LOG_LEVEL_ERROR, format, ##__VA_ARGS__)
#define CNK_FATAL(format, ...) CNK_PRINTLOGF(CNK_LOG_LEVEL_FATAL, format, ##__VA_ARGS__)

#ifdef CNK_VERBOSE
// #define FUNC_TRACE(CALL) dbg(CALL)
#define CNK_RETURN(ARG, REASON)                                                                                        \
  do {                                                                                                                 \
    CNK_TYPEOF((ARG)) _cnk_return_value = (ARG);                                                                       \
    CNK_DEBUG("Returning %s = 0x%lx: \"%s\"", #ARG, (unsigned long)_cnk_return_value, REASON);                         \
    return _cnk_return_value;                                                                                          \
  } while (0)
#define CNK_LOG_FUNC(...) CNK_DEBUG("Called" __VA_ARGS__)
#else
// #define FUNC_TRACE(CALL) CALL
#define CNK_RETURN(ARG, ...)                                                                                           \
  do {                                                                                                                 \
    return (ARG);                                                                                                      \
  } while (0)
#define CNK_LOG_FUNC(...)
#endif // CNK_VERBOSE

#define CNK_RET_OK CNK_RETURN(CKR_OK, "Success")

// Use this for features that are plausible for this module but not wired up yet.
#define CNK_RET_NOT_IMPLEMENTED CNK_RETURN(CKR_FUNCTION_NOT_SUPPORTED, "Not implemented yet")

// Use this for functions that are outside the module's intended feature set.
#define CNK_RET_UNSUPPORTED CNK_RETURN(CKR_FUNCTION_NOT_SUPPORTED, "Intentionally unsupported")

#define CNK_RET_FWD(EXP) CNK_RETURN(EXP, "Directly forwarded")

// Function to log APDU commands in a formatted way
void cnk_log_apdu_command(const unsigned char *command, unsigned long command_len);

// Function to log APDU responses in a formatted way
void cnk_log_apdu_response(const unsigned char *response, unsigned long response_len);

// Macros to call the APDU logging functions only if the log level is appropriate
#define CNK_LOG_APDU_COMMAND(command, command_len)                                                                     \
  do {                                                                                                                 \
    if (atomic_load(&g_cnk_unsafe_log_apdu) && atomic_load(&g_cnk_log_level) <= CNK_LOG_LEVEL_DEBUG) {                 \
      cnk_log_apdu_command((command), (command_len));                                                                  \
    }                                                                                                                  \
  } while (0)

#define CNK_LOG_APDU_RESPONSE(response, response_len)                                                                  \
  do {                                                                                                                 \
    if (atomic_load(&g_cnk_unsafe_log_apdu) && atomic_load(&g_cnk_log_level) <= CNK_LOG_LEVEL_DEBUG) {                 \
      cnk_log_apdu_response((response), (response_len));                                                               \
    }                                                                                                                  \
  } while (0)

#endif // CNK_INTERNAL_LOGGING_H
