#ifdef __linux__

#ifndef BSD_STRING_H
#define BSD_STRING_H

#include <sys/types.h>

#define DEF_WEAK(fn) __attribute__((weak)) fn
size_t strlcat(char *dst, const char *src, size_t dsize);
size_t strlcpy(char *dst, const char *src, size_t dsize);
#endif

#endif