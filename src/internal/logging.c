#include "internal/logging.h"

#include <ctype.h>
#include <nsync_mu.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <process.h>
#include <windows.h>
#define CNK_PATH_SEPARATOR '\\'
#define CNK_PROCESS_ID _getpid
#else
#include <unistd.h>
#define CNK_PROCESS_ID getpid
#define CNK_PATH_SEPARATOR '/'
#endif

#define CNK_LOG_PATH_MAX 1024
#define CNK_PROCESS_NAME_MAX 64

static const char *const g_cnk_log_level_name[CNK_LOG_LEVEL_SIZE] = {
    "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "NONE",
};

// default values
atomic_int g_cnk_log_level = CNK_LOG_LEVEL_WARN;
atomic_bool g_cnk_unsafe_log_apdu = false;
static FILE *g_cnk_log_file = NULL;
static CK_BBOOL g_cnk_log_file_owned = CK_FALSE;
static nsync_mu g_cnk_log_mutex = NSYNC_MU_INIT;
static char g_cnk_process_name[CNK_PROCESS_NAME_MAX] = "canokey-pkcs11";

typedef struct {
  int level;
  CK_BBOOL level_set;
  CK_BBOOL unsafe_log_apdu;
  CK_BBOOL unsafe_log_apdu_set;
  char path[CNK_LOG_PATH_MAX];
  CK_BBOOL path_set;
  CK_BBOOL path_is_directory;
} CNK_LOG_SETTINGS;

static void cnk_sanitize_process_name(void) {
  // Keep the process identity useful in a filename without allowing path
  // separators or other platform-specific characters to escape the log dir.
  for (size_t i = 0; g_cnk_process_name[i] != '\0'; i++) {
    unsigned char ch = (unsigned char)g_cnk_process_name[i];
    if (!isalnum(ch) && ch != '.' && ch != '-' && ch != '_')
      g_cnk_process_name[i] = '_';
  }
}

static void cnk_capture_process_name(void) {
  const char *path = NULL;
#if defined(_WIN32)
  char executable_path[CNK_LOG_PATH_MAX];
  DWORD executable_length = GetModuleFileNameA(NULL, executable_path, sizeof(executable_path));
  if (executable_length > 0 && executable_length < sizeof(executable_path))
    path = executable_path;
#elif defined(__APPLE__) || defined(__MACH__)
  path = getprogname();
#elif defined(__linux__)
  FILE *process_file = fopen("/proc/self/comm", "rb");
  if (process_file != NULL) {
    if (fgets(g_cnk_process_name, sizeof(g_cnk_process_name), process_file) != NULL) {
      char *newline = strpbrk(g_cnk_process_name, "\r\n");
      if (newline != NULL)
        *newline = '\0';
    }
    fclose(process_file);
    if (g_cnk_process_name[0] != '\0') {
      cnk_sanitize_process_name();
      return;
    }
  }
#endif

  if (path != NULL && path[0] != '\0') {
    const char *basename = strrchr(path, '/');
    const char *windows_basename = strrchr(path, '\\');
    if (windows_basename != NULL && (basename == NULL || windows_basename > basename))
      basename = windows_basename;
    if (basename != NULL)
      basename++;
    else
      basename = path;
    snprintf(g_cnk_process_name, sizeof(g_cnk_process_name), "%s", basename);
  }

  cnk_sanitize_process_name();
}

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

static char *cnk_trim_ascii(char *value) {
  if (value == NULL)
    return NULL;

  while (*value != '\0' && isspace((unsigned char)*value))
    value++;

  char *end = value + strlen(value);
  while (end > value && isspace((unsigned char)end[-1]))
    *--end = '\0';
  return value;
}

static void cnk_set_log_path(CNK_LOG_SETTINGS *settings, const char *value, CK_BBOOL is_directory) {
  if (settings == NULL || value == NULL || value[0] == '\0')
    return;
  size_t length = strlen(value);
  if (length >= sizeof(settings->path))
    return;
  memcpy(settings->path, value, length + 1);
  settings->path_set = CK_TRUE;
  settings->path_is_directory = is_directory;
}

static void cnk_apply_log_setting(CNK_LOG_SETTINGS *settings, const char *key, const char *value) {
  if (settings == NULL || key == NULL || value == NULL)
    return;

  if (cnk_ascii_equals_ignore_case(key, "log_level")) {
    int level;
    if (cnk_parse_log_level(value, &level)) {
      settings->level = level;
      settings->level_set = CK_TRUE;
    }
  } else if (cnk_ascii_equals_ignore_case(key, "unsafe_log_apdu")) {
    CK_BBOOL unsafe_log_apdu;
    if (cnk_parse_bool(value, &unsafe_log_apdu)) {
      settings->unsafe_log_apdu = unsafe_log_apdu;
      settings->unsafe_log_apdu_set = CK_TRUE;
    }
  } else if (cnk_ascii_equals_ignore_case(key, "log_path")) {
    cnk_set_log_path(settings, value, CK_FALSE);
  } else if (cnk_ascii_equals_ignore_case(key, "log_dir")) {
    cnk_set_log_path(settings, value, CK_TRUE);
  }
}

static void cnk_read_log_config_file(CNK_LOG_SETTINGS *settings, const char *config_path) {
  if (settings == NULL || config_path == NULL || config_path[0] == '\0')
    return;

  FILE *config = fopen(config_path, "rb");
  if (config == NULL)
    return;

  char line[CNK_LOG_PATH_MAX];
  while (fgets(line, sizeof(line), config) != NULL) {
    char *comment = strpbrk(line, "#;");
    if (comment != NULL)
      *comment = '\0';
    char *entry = cnk_trim_ascii(line);
    // PowerShell and several editors emit a UTF-8 BOM. Treat it as file
    // encoding metadata so the first setting follows the same rules as all
    // subsequent key/value entries.
    if (entry != NULL && strlen(entry) >= 3 && (unsigned char)entry[0] == 0xef && (unsigned char)entry[1] == 0xbb &&
        (unsigned char)entry[2] == 0xbf)
      entry = cnk_trim_ascii(entry + 3);
    if (entry == NULL || entry[0] == '\0')
      continue;
    char *separator = strchr(entry, '=');
    if (separator == NULL)
      continue;
    *separator = '\0';
    cnk_apply_log_setting(settings, cnk_trim_ascii(entry), cnk_trim_ascii(separator + 1));
  }
  fclose(config);
}

static CK_BBOOL cnk_build_default_config_path(char *path, size_t path_size) {
  if (path == NULL || path_size == 0)
    return CK_FALSE;

#if defined(_WIN32)
  const char *config_root = getenv("APPDATA");
  if (config_root == NULL || config_root[0] == '\0')
    config_root = getenv("USERPROFILE");
  if (config_root == NULL || config_root[0] == '\0')
    return CK_FALSE;
  int written = snprintf(path, path_size, "%s%cCanokeys%ccanokey-pkcs11.conf", config_root, CNK_PATH_SEPARATOR,
                         CNK_PATH_SEPARATOR);
#elif defined(__APPLE__) || defined(__MACH__)
  const char *config_root = getenv("XDG_CONFIG_HOME");
  int written;
  if (config_root != NULL && config_root[0] != '\0') {
    written = snprintf(path, path_size, "%s%ccanokey-pkcs11.conf", config_root, CNK_PATH_SEPARATOR);
  } else {
    config_root = getenv("HOME");
    if (config_root == NULL || config_root[0] == '\0')
      return CK_FALSE;
    written = snprintf(path, path_size, "%s%cLibrary%cApplication Support%ccanokey-pkcs11.conf", config_root,
                       CNK_PATH_SEPARATOR, CNK_PATH_SEPARATOR, CNK_PATH_SEPARATOR);
  }
#else
  const char *config_root = getenv("XDG_CONFIG_HOME");
  int written;
  if (config_root != NULL && config_root[0] != '\0') {
    written = snprintf(path, path_size, "%s%ccanokey-pkcs11.conf", config_root, CNK_PATH_SEPARATOR);
  } else {
    config_root = getenv("HOME");
    if (config_root == NULL || config_root[0] == '\0')
      return CK_FALSE;
    written = snprintf(path, path_size, "%s%c.config%ccanokey-pkcs11.conf", config_root, CNK_PATH_SEPARATOR,
                       CNK_PATH_SEPARATOR);
  }
#endif

  return written >= 0 && (size_t)written < path_size;
}

static void cnk_read_user_log_config(CNK_LOG_SETTINGS *settings) {
  const char *explicit_path = getenv("CNK_LOG_CONFIG");
  if (explicit_path != NULL && explicit_path[0] != '\0') {
    cnk_read_log_config_file(settings, explicit_path);
    return;
  }

  char default_path[CNK_LOG_PATH_MAX];
  if (cnk_build_default_config_path(default_path, sizeof(default_path)))
    cnk_read_log_config_file(settings, default_path);
}

static void cnk_replace_log_file(FILE *file, CK_BBOOL owned) {
  FILE *old_file;
  CK_BBOOL old_owned;
  nsync_mu_lock(&g_cnk_log_mutex);
  old_file = g_cnk_log_file;
  old_owned = g_cnk_log_file_owned;
  g_cnk_log_file = file;
  g_cnk_log_file_owned = owned;
  nsync_mu_unlock(&g_cnk_log_mutex);

  // Loggers hold the same mutex while using the stream, so it is safe to
  // close an environment-owned stream after detaching it from the global.
  if (old_owned && old_file != NULL)
    fclose(old_file);
}

static FILE *cnk_open_configured_log(const CNK_LOG_SETTINGS *settings, char *resolved_path, size_t resolved_path_size) {
  if (settings == NULL || !settings->path_set || resolved_path == NULL || resolved_path_size == 0)
    return NULL;

  int written;
  if (settings->path_is_directory) {
    size_t path_length = strlen(settings->path);
    if (path_length > 0 && settings->path[path_length - 1] != CNK_PATH_SEPARATOR)
      written = snprintf(resolved_path, resolved_path_size, "%s%ccanokey_pkcs11_%s_%lu.log", settings->path,
                         CNK_PATH_SEPARATOR, g_cnk_process_name, (unsigned long)CNK_PROCESS_ID());
    else
      written = snprintf(resolved_path, resolved_path_size, "%scanokey_pkcs11_%s_%lu.log", settings->path,
                         g_cnk_process_name, (unsigned long)CNK_PROCESS_ID());
  } else {
    written = snprintf(resolved_path, resolved_path_size, "%s", settings->path);
  }
  if (written < 0 || (size_t)written >= resolved_path_size)
    return NULL;

  return fopen(resolved_path, "ab");
}

CK_RV cnk_config_logging(const int level, FILE *file, CK_BBOOL unsafe_log_apdu) {
  if (level >= 0 && level < CNK_LOG_LEVEL_SIZE) {
    atomic_store(&g_cnk_log_level, level);
  } else if (level != -1) {
    return CKR_ARGUMENTS_BAD;
  }

  if (file != NULL)
    cnk_replace_log_file(file, CK_FALSE);

  cnk_capture_process_name();
  atomic_store(&g_cnk_unsafe_log_apdu, unsafe_log_apdu ? true : false);

  return CKR_OK;
}

void cnk_reset_logging(void) {
  cnk_replace_log_file(NULL, CK_FALSE);
  atomic_store(&g_cnk_log_level, CNK_LOG_LEVEL_WARN);
  atomic_store(&g_cnk_unsafe_log_apdu, false);
}

void cnk_config_logging_from_env(void) {
  CNK_LOG_SETTINGS settings = {0};
  cnk_capture_process_name();
#if defined(CNK_VERBOSE)
  settings.level = CNK_LOG_LEVEL_DEBUG;
  settings.level_set = CK_TRUE;
  const char *temp_dir = getenv("TMPDIR");
  if (temp_dir == NULL || temp_dir[0] == '\0')
    temp_dir = getenv("TEMP");
  if (temp_dir == NULL || temp_dir[0] == '\0')
    temp_dir = getenv("TMP");
  cnk_set_log_path(&settings, temp_dir, CK_TRUE);
#else
  settings.level = CNK_LOG_LEVEL_WARN;
#endif

  // A user config file is discovered automatically; CNK_LOG_CONFIG remains an
  // explicit override for isolated tests or non-standard deployment paths.
  cnk_read_user_log_config(&settings);

  int level;
  if (cnk_parse_log_level(getenv("CNK_LOG_LEVEL"), &level)) {
    settings.level = level;
    settings.level_set = CK_TRUE;
  }

  CK_BBOOL unsafe_log_apdu;
  if (cnk_parse_bool(getenv("CNK_UNSAFE_LOG_APDU"), &unsafe_log_apdu)) {
    settings.unsafe_log_apdu = unsafe_log_apdu;
    settings.unsafe_log_apdu_set = CK_TRUE;
  }

  // An exact file path takes precedence over a directory from either source.
  const char *log_dir = getenv("CNK_LOG_DIR");
  const char *log_path = getenv("CNK_LOG_PATH");
  if (log_dir != NULL)
    cnk_set_log_path(&settings, log_dir, CK_TRUE);
  if (log_path != NULL)
    cnk_set_log_path(&settings, log_path, CK_FALSE);

  cnk_reset_logging();
  atomic_store(&g_cnk_log_level, settings.level_set ? settings.level : CNK_LOG_LEVEL_WARN);
  atomic_store(&g_cnk_unsafe_log_apdu, settings.unsafe_log_apdu_set && settings.unsafe_log_apdu ? true : false);

  char resolved_path[CNK_LOG_PATH_MAX];
  FILE *log_file = cnk_open_configured_log(&settings, resolved_path, sizeof(resolved_path));
  if (log_file != NULL) {
    cnk_replace_log_file(log_file, CK_TRUE);
    CNK_INFO("Standalone logging enabled at %s", resolved_path);
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
