#include "logging.h"

#include <assert.h>
#include <stdarg.h>
#include <time.h>

const char *g_cnk_log_level_name[CNK_LOG_LEVEL_SIZE] = {
    "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "NONE",
};

// default values
int g_cnk_log_level = CNK_LOG_LEVEL_WARNING;
FILE* g_cnk_log_file = NULL;

void cnk_printf(const int level, const char *const format, ...) {
  if (level < g_cnk_log_level) {
    return;
  }
  FILE *out = g_cnk_log_file;
  if (out == NULL) {
    out = stderr;
  }
  // print current time at the beginning of the log line
  char time[16];
  struct timespec ts;
  timespec_get(&ts, TIME_UTC);
  strftime(time, sizeof(time), "%H:%M:%S", localtime(&ts.tv_sec));
  sprintf(time + 8, ".%03ld", ts.tv_nsec / 1000000);
  fprintf(out, "%s - ", time);
  // print the log line
  va_list args;
  va_start(args, format);
  vfprintf(out, format, args);
  va_end(args);
  fflush(out);
}

