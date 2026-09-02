#include "internal/logging.h"

#include <nsync_mu.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *const g_cnk_log_level_name[CNK_LOG_LEVEL_SIZE] = {
    "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "NONE",
};

// default values
atomic_int g_cnk_log_level = CNK_LOG_LEVEL_WARN;
atomic_bool g_cnk_unsafe_log_apdu = false;
static FILE *g_cnk_log_file = NULL;
static nsync_mu g_cnk_log_mutex = NSYNC_MU_INIT;

static int cnk_ascii_tolower(int ch) {
  if (ch >= 'A' && ch <= 'Z')
    return ch - 'A' + 'a';
  return ch;
}

static CK_BBOOL cnk_ascii_equals_ignore_case(const char *lhs, const char *rhs) {
  if (lhs == NULL || rhs == NULL)
    return CK_FALSE;

  while (*lhs != '\0' && *rhs != '\0') {
    if (cnk_ascii_tolower((unsigned char)*lhs) != cnk_ascii_tolower((unsigned char)*rhs))
      return CK_FALSE;
    lhs++;
    rhs++;
  }

  return *lhs == '\0' && *rhs == '\0';
}

static CK_BBOOL cnk_parse_log_level(const char *value, int *level) {
  if (value == NULL || level == NULL)
    return CK_FALSE;

  char *end = NULL;
  long numeric = strtol(value, &end, 10);
  if (end != value && *end == '\0' && numeric >= 0 && numeric < CNK_LOG_LEVEL_SIZE) {
    *level = (int)numeric;
    return CK_TRUE;
  }

  for (int i = 0; i < CNK_LOG_LEVEL_SIZE; i++) {
    if (cnk_ascii_equals_ignore_case(value, g_cnk_log_level_name[i])) {
      *level = i;
      return CK_TRUE;
    }
  }

  return CK_FALSE;
}

static CK_BBOOL cnk_parse_bool(const char *value, CK_BBOOL *result) {
  if (value == NULL || result == NULL)
    return CK_FALSE;

  if (cnk_ascii_equals_ignore_case(value, "1") || cnk_ascii_equals_ignore_case(value, "true") ||
      cnk_ascii_equals_ignore_case(value, "yes") || cnk_ascii_equals_ignore_case(value, "on")) {
    *result = CK_TRUE;
    return CK_TRUE;
  }

  if (cnk_ascii_equals_ignore_case(value, "0") || cnk_ascii_equals_ignore_case(value, "false") ||
      cnk_ascii_equals_ignore_case(value, "no") || cnk_ascii_equals_ignore_case(value, "off")) {
    *result = CK_FALSE;
    return CK_TRUE;
  }

  return CK_FALSE;
}

CK_RV cnk_config_logging(const int level, FILE *file, CK_BBOOL unsafe_log_apdu) {
  if (level >= 0 && level < CNK_LOG_LEVEL_SIZE) {
    atomic_store(&g_cnk_log_level, level);
  } else if (level != -1) {
    return CKR_ARGUMENTS_BAD;
  }

  if (file != NULL) {
    nsync_mu_lock(&g_cnk_log_mutex);
    g_cnk_log_file = file;
    nsync_mu_unlock(&g_cnk_log_mutex);
  }

  atomic_store(&g_cnk_unsafe_log_apdu, unsafe_log_apdu ? true : false);

  return CKR_OK;
}

void cnk_reset_logging(void) {
  nsync_mu_lock(&g_cnk_log_mutex);
  g_cnk_log_file = NULL;
  nsync_mu_unlock(&g_cnk_log_mutex);
  atomic_store(&g_cnk_log_level, CNK_LOG_LEVEL_WARN);
  atomic_store(&g_cnk_unsafe_log_apdu, false);
}

void cnk_config_logging_from_env(void) {
  atomic_store(&g_cnk_log_level, CNK_LOG_LEVEL_WARN);
  atomic_store(&g_cnk_unsafe_log_apdu, false);

  int level;
  const char *level_env = getenv("CNK_LOG_LEVEL");
  if (cnk_parse_log_level(level_env, &level)) {
    atomic_store(&g_cnk_log_level, level);
  }

  CK_BBOOL unsafe_log_apdu;
  const char *apdu_env = getenv("CNK_UNSAFE_LOG_APDU");
  if (cnk_parse_bool(apdu_env, &unsafe_log_apdu)) {
    atomic_store(&g_cnk_unsafe_log_apdu, unsafe_log_apdu ? true : false);
  }
}

static void print_time(FILE *out) {
  struct timespec ts;
  if (timespec_get(&ts, TIME_UTC) == TIME_UTC) {
    char time[16];
    strftime(time, sizeof(time), "%H:%M:%S", localtime(&ts.tv_sec));
    sprintf(time + 8, ".%03ld", ts.tv_nsec / 1000000);
    fprintf(out, "%s - ", time);
  } else {
    fprintf(out, "!!:!!:!!.!!! - ");
  }
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"

void cnk_printlogf(const int level, const char *const function, const char *const file, const int line,
                   const char *const format, ...) {
  if (level < atomic_load(&g_cnk_log_level)) {
    return;
  }

  nsync_mu_lock(&g_cnk_log_mutex);

  FILE *out = g_cnk_log_file;
  if (out == NULL) {
    out = stderr;
  }
  print_time(out);
  fprintf(out, "%-20s(%-20s:L%03d)[%-5s]: ", function, file, line, g_cnk_log_level_name[level]);

  va_list args;
  va_start(args, format);
  vfprintf(out, format, args);
  va_end(args);
  fprintf(out, "\n");
  fflush(out);

  nsync_mu_unlock(&g_cnk_log_mutex);
}

#pragma clang diagnostic pop

/**
 * Log an APDU command in a formatted way.
 * Format: CLA INS P1 P2 [Lc] [Data] [Le]
 * For extended APDUs: CLA INS P1 P2 00 [Lc_h Lc_l] [Data] [00 Le_h Le_l]
 *
 * @param command The APDU command buffer
 * @param command_len The length of the command buffer
 */
void cnk_log_apdu_command(const unsigned char *command, unsigned long command_len) {
  if (command == NULL || command_len == 0) {
    return;
  }

  nsync_mu_lock(&g_cnk_log_mutex);

  FILE *out = g_cnk_log_file;
  if (out == NULL) {
    out = stderr;
  }

  print_time(out);

  // Print APDU command header
  fprintf(out, "APDU Command: ");

  // Always print CLA, INS, P1, P2
  if (command_len >= 4) {
    fprintf(out, "%02X %02X %02X %02X", command[0], command[1], command[2], command[3]);
  } else {
    // Incomplete APDU
    fprintf(out, "Incomplete APDU Command: ");
    for (unsigned long i = 0; i < command_len; i++) {
      fprintf(out, "%02X ", command[i]);
    }
    fprintf(out, "\n");
    fflush(out);
    nsync_mu_unlock(&g_cnk_log_mutex);
    return;
  }

  // Check if there's Lc (data length)
  if (command_len > 4) {
    // Check if it's an extended APDU (5th byte is 0x00)
    if (command[4] == 0x00 && command_len >= 7) {
      // Extended APDU format
      unsigned long ext_lc = (command[5] << 8) | command[6];
      fprintf(out, " %02X %02X %02X", command[4], command[5], command[6]);

      // Print data if present
      if (ext_lc > 0 && command_len > 7) {
        fprintf(out, " ");
        unsigned long data_len = (command_len > (7 + ext_lc)) ? ext_lc : (command_len - 7);
        for (unsigned long i = 0; i < data_len; i++) {
          fprintf(out, "%02X", command[7 + i]);
        }

        // Print Le if present (extended format)
        if (command_len > (7 + ext_lc) && command_len >= (7 + ext_lc + 3)) {
          fprintf(out, " %02X %02X %02X", command[7 + ext_lc], command[7 + ext_lc + 1], command[7 + ext_lc + 2]);
        } else if (command_len > (7 + ext_lc)) {
          // Partial Le field
          for (unsigned long i = 7 + ext_lc; i < command_len; i++) {
            fprintf(out, " %02X", command[i]);
          }
        }
      }
    } else {
      // Standard APDU format
      unsigned char lc = command[4];
      fprintf(out, " %02X", lc);

      // Print data if present
      if (lc > 0 && command_len > 5) {
        fprintf(out, " ");
        unsigned long data_len = (command_len > (5ul + lc)) ? lc : (command_len - 5);
        for (unsigned long i = 0; i < data_len; i++) {
          fprintf(out, "%02X", command[5ul + i]);
        }

        // Print Le if present
        if (command_len > (5ul + lc)) {
          fprintf(out, " %02X", command[5ul + lc]);
        }
      }
    }
  }

  fprintf(out, "\n");
  fflush(out);
  nsync_mu_unlock(&g_cnk_log_mutex);
}

/**
 * Log an APDU response in a formatted way.
 * Format: [Response data] SW1 SW2
 *
 * @param response The APDU response buffer
 * @param response_len The length of the response buffer
 */
void cnk_log_apdu_response(const unsigned char *response, unsigned long response_len) {
  if (response == NULL || response_len == 0) {
    return;
  }

  nsync_mu_lock(&g_cnk_log_mutex);

  FILE *out = g_cnk_log_file;
  if (out == NULL) {
    out = stderr;
  }

  print_time(out);

  // Print APDU response header
  fprintf(out, "APDU Response: ");

  // Check if we have at least status words (SW1 SW2)
  if (response_len < 2) {
    fprintf(out, "Incomplete APDU Response: ");
    for (unsigned long i = 0; i < response_len; i++) {
      fprintf(out, "%02X ", response[i]);
    }
  } else {
    // Print response data if present
    if (response_len > 2) {
      for (unsigned long i = 0; i < response_len - 2; i++) {
        fprintf(out, "%02X", response[i]);
      }
      fprintf(out, " ");
    }

    // Print status words (SW1 SW2)
    fprintf(out, "%02X%02X", response[response_len - 2], response[response_len - 1]);
  }

  fprintf(out, "\n");
  fflush(out);
  nsync_mu_unlock(&g_cnk_log_mutex);
}
