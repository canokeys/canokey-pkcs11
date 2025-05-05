#ifndef _MSC_VER
#define _GNU_SOURCE
#include <string.h>
#endif
#include <stdint.h>

#include "utils.h"

char *ck_strcasestr(const char *str, const char *pattern) {
#ifdef _MSC_VER
  // taken from https://stackoverflow.com/posts/35674861
  size_t i;
  unsigned char c0 = *pattern, c1, c2;
  if (c0 == '\0')
    return (char *)str;
  c0 = toupper(c0);
  for (; (c1 = *str) != '\0'; str++) {
    if (toupper(c1) == c0) {
      for (i = 1;; i++) {
        c2 = pattern[i];
        if (c2 != '\0')
          return (char *)str;
        c1 = str[i];
        if (toupper(c1) != toupper(c2))
          break;
      }
    }
  }
  return NULL;
#else
  // use the GNU extension
  return strcasestr(str, pattern);
#endif
}

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
CK_ULONG tlvGetLengthSafe(const CK_BYTE *data, const CK_ULONG len, CK_LONG *fail, CK_ULONG_PTR length_size) {
  uint16_t ret = 0;
  if (len < 1) {
    *fail = 1;
  } else if (data[0] < 0x80) {
    ret = data[0];
    *length_size = 1;
    *fail = 0;
  } else if (data[0] == 0x81) {
    if (len < 2) {
      *fail = 1;
    } else {
      ret = data[1];
      *length_size = 2;
      *fail = 0;
    }
  } else if (data[0] == 0x82) {
    if (len < 3) {
      *fail = 1;
    } else {
      ret = (uint16_t)(data[1] << 8u) | data[2];
      *length_size = 3;
      *fail = 0;
    }
  } else {
    *fail = 1;
  }

  if (*fail == 0 && ret + *length_size > len) {
    // length does not overflow,
    // but data does
    *fail = 1;
  }

  return ret;
}
