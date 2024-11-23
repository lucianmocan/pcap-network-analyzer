

#ifndef BSD_STRING_H
#define BSD_STRING_H

#include <sys/types.h>

#ifdef NEED_STRLCAT
size_t strlcat(char *dst, const char *src, size_t dsize);
#endif

#ifdef NEED_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t dsize);
#endif

#endif
