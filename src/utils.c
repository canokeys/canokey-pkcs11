#ifndef _MSC_VER
#define _GNU_SOURCE
#include <string.h>
#endif
#include <ctype.h>
#include <stdlib.h>

char* ck_strcasestr(const char* str, const char* pattern) {
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