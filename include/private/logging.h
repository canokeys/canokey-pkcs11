#ifndef LOGGING_H
#define LOGGING_H

#pragma clang diagnostic ignored "-Wlanguage-extension-token"
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#pragma clang diagnostic ignored "-Wgnu-statement-expression-from-macro-expansion"

#include <stdbool.h>
#include <stdio.h>
#include <stdatomic.h>

enum CNK_LOG_LEVEL {
  CNK_LOG_LEVEL_TRACE = 0,
  CNK_LOG_LEVEL_DEBUG,
  CNK_LOG_LEVEL_INFO,
  CNK_LOG_LEVEL_WARNING,
  CNK_LOG_LEVEL_ERROR,
  CNK_LOG_LEVEL_FATAL,
  CNK_LOG_LEVEL_NONE,
  CNK_LOG_LEVEL_SIZE,
};

extern const char *g_cnk_log_level_name[CNK_LOG_LEVEL_SIZE];

extern FILE *g_cnk_log_file; // not using atomic variable deliberately
extern atomic_int g_cnk_log_level;

extern void cnk_printf(const int level, const bool prepend_date, const char *format, ...);

#define CNK_PRINTLOGF_IMPL(level, format, ...)                                                                         \
  cnk_printf(level, true, "%-20s(%-20s:L%03d)[%-5s]: ", __FUNCTION__, __FILE__, __LINE__,                              \
             g_cnk_log_level_name[level]);                                                                             \
  cnk_printf(level, false, format "\n", ##__VA_ARGS__);
#define CNK_PRINTLOGF(level, format, ...)                                                                              \
  do {                                                                                                                 \
    int _level = atomic_load(&g_cnk_log_level);                                                                        \
    if (__builtin_expect(_level < g_cnk_log_level, true)) {                                                            \
      break;                                                                                                           \
    }                                                                                                                  \
    CNK_PRINTLOGF_IMPL(_level, format, ##__VA_ARGS__);                                                                 \
  } while (0)
#define CNK_TRACE(format, ...) CNK_PRINTLOGF(CNK_LOG_LEVEL_TRACE, format, ##__VA_ARGS__)
#define CNK_DEBUG(format, ...) CNK_PRINTLOGF(CNK_LOG_LEVEL_DEBUG, format, ##__VA_ARGS__)
#define CNK_INFO(format, ...) CNK_PRINTLOGF(CNK_LOG_LEVEL_INFO, format, ##__VA_ARGS__)
#define CNK_WARN(format, ...) CNK_PRINTLOGF(CNK_LOG_LEVEL_WARNING, format, ##__VA_ARGS__)
#define CNK_ERROR(format, ...) CNK_PRINTLOGF(CNK_LOG_LEVEL_ERROR, format, ##__VA_ARGS__)
#define CNK_FATAL(format, ...) CNK_PRINTLOGF(CNK_LOG_LEVEL_FATAL, format, ##__VA_ARGS__)

#ifdef CNK_VERBOSE
// #define FUNC_TRACE(CALL) dbg(CALL)
#define CNK_RETURN(ARG, REASON)                                                                                        \
  do {                                                                                                                 \
    __typeof__((ARG)) _ret = (ARG);                                                                                        \
    CNK_DEBUG("Returning %s = %d: \"%s\"", #ARG, _ret, REASON);                                             \
    return _ret;                                                                                                       \
  } while (0)
#define CNK_LOG_FUNC(...) CNK_DEBUG("Called" __VA_ARGS__)
#else
// #define FUNC_TRACE(CALL) CALL
#define CNK_RETURN(ARG, ...) return (ARG);
#define CNK_LOG_FUNC(...)
#endif // CNK_VERBOSE

// Function to log APDU commands in a formatted way
void cnk_log_apdu_command(const unsigned char *command, unsigned long command_len);

// Function to log APDU responses in a formatted way
void cnk_log_apdu_response(const unsigned char *response, unsigned long response_len);

// Macros to call the APDU logging functions only if the log level is appropriate
#define CNK_LOG_APDU_COMMAND(command, command_len)                                                                     \
  if (g_cnk_log_level <= CNK_LOG_LEVEL_DEBUG) {                                                                        \
    cnk_log_apdu_command(command, command_len);                                                                        \
  }

#define CNK_LOG_APDU_RESPONSE(response, response_len)                                                                  \
  if (g_cnk_log_level <= CNK_LOG_LEVEL_DEBUG) {                                                                        \
    cnk_log_apdu_response(response, response_len);                                                                     \
  }

#endif // LOGGING_H
