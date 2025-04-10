#ifndef __LOGGING__H__
#define __LOGGING__H__

#define _CRT_SECURE_NO_WARNINGS // make MSVC happy
#include <stdio.h>

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

extern FILE *g_cnk_log_file;
extern int g_cnk_log_level;

extern void cnk_printf(const int level, const char *format, ...);

#define CNK_PRINTLOGF(level, format, ...)                                                                              \
  cnk_printf(level, "%-20s(%-20s:%03d)[%-5s]: ", __FUNCTION__, __FILE__, __LINE__, g_cnk_log_level_name[level]);       \
  cnk_printf(level, format, ##__VA_ARGS__);
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
    int ret = (ARG);                                                                                                   \
    CNK_DEBUG("Returning value %s = %d with reason \"%s\"\n", #ARG, ret, REASON);                                      \
    return ret;                                                                                                        \
  } while (0)
#define CNK_LOG_FUNC(name, ...) CNK_DEBUG(#name " called" __VA_ARGS__)
#else
// #define FUNC_TRACE(CALL) CALL
#define CNK_RETURN(ARG, ...) return (ARG);
#define CNK_LOG_FUNC(name, ...)
#endif // CNK_VERBOSE

#define CNK_RET_OK CNK_RETURN(CKR_OK, "Success")
#define CNK_RET_UNIMPL CNK_RETURN(CKR_FUNCTION_NOT_SUPPORTED, "Not implemented")
#define CNK_ENSURE_EQUAL_REASON(EXP, EXPECTED, REASON)                                                                 \
  if ((EXP) != (EXPECTED)) {                                                                                           \
    CNK_RETURN(CKR_ARGUMENTS_BAD, REASON);                                                                             \
  }
#define CNK_ENSURE_EQUAL(EXP, EXPECTED) CNK_ENSURE_EQUAL_REASON(EXP, EXPECTED, #EXP " != " #EXPECTED)
#define CNK_ENSURE_NONNULL(PTR) CNK_ENSURE_EQUAL_REASON(!!(PTR), !NULL, #PTR " is NULL")
#define CHK_ENSURE_NULL(PTR) CNK_ENSURE_EQUAL_REASON(!!(PTR), !!NULL, #PTR " is not NULL")
#define CNK_ENSURE_OK(EXP)                                                                                             \
  ({                                                                                                                   \
    CK_RV rv = (EXP);                                                                                                  \
    if (rv != CKR_OK)                                                                                                  \
      CNK_RETURN(rv, #EXP " failed");                                                                                  \
    CKR_OK;                                                                                                            \
  })

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

#endif // __LOGGING__H__