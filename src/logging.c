#include "logging.h"

#include <stdarg.h>
#include <time.h>

const char *g_cnk_log_level_name[CNK_LOG_LEVEL_SIZE] = {
    "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "NONE",
};

// default values
int g_cnk_log_level = CNK_LOG_LEVEL_WARNING;
FILE *g_cnk_log_file = NULL;

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

  FILE *out = g_cnk_log_file;
  if (out == NULL) {
    out = stderr;
  }

  // Print current time at the beginning of the log line
  char time[16];
  struct timespec ts;
  timespec_get(&ts, TIME_UTC);
  strftime(time, sizeof(time), "%H:%M:%S", localtime(&ts.tv_sec));
  sprintf(time + 8, ".%03ld", ts.tv_nsec / 1000000);
  fprintf(out, "%s - ", time);

  // Print APDU command header
  fprintf(out, "APDU Command: ");

  // Always print CLA, INS, P1, P2
  if (command_len >= 4) {
    fprintf(out, "%02X %02X %02X %02X", command[0], command[1], command[2], command[3]);
  } else {
    // Incomplete APDU
    fprintf(out, "Incomplete APDU: ");
    for (unsigned long i = 0; i < command_len; i++) {
      fprintf(out, "%02X ", command[i]);
    }
    fprintf(out, "\n");
    fflush(out);
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
        unsigned long data_len = (command_len > (5 + lc)) ? lc : (command_len - 5);
        for (unsigned long i = 0; i < data_len; i++) {
          fprintf(out, "%02X", command[5 + i]);
        }

        // Print Le if present
        if (command_len > (5 + lc)) {
          fprintf(out, " %02X", command[5 + lc]);
        }
      }
    }
  }

  fprintf(out, "\n");
  fflush(out);
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

  FILE *out = g_cnk_log_file;
  if (out == NULL) {
    out = stderr;
  }

  // Print current time at the beginning of the log line
  char time[16];
  struct timespec ts;
  timespec_get(&ts, TIME_UTC);
  strftime(time, sizeof(time), "%H:%M:%S", localtime(&ts.tv_sec));
  sprintf(time + 8, ".%03ld", ts.tv_nsec / 1000000);
  fprintf(out, "%s - ", time);

  // Print APDU response header
  fprintf(out, "APDU Response: ");

  // Check if we have at least status words (SW1 SW2)
  if (response_len < 2) {
    fprintf(out, "Incomplete response: ");
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
}
