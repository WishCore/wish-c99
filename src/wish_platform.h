#ifndef WISH_PLATFORM_H
#define WISH_PLATFORM_H

/* Porting layer functions */

#include <stddef.h>
#include <stdarg.h>


void wish_platform_set_malloc(void* (*fn)(size_t size));

void wish_platform_set_realloc(void* (*fn)(void *, size_t size));

void wish_platform_set_free(void (*fn)(void *ptr));

void wish_platform_set_realloc(void* (*fn)(void *, size_t size));

void* wish_platform_malloc(size_t size);

void* wish_platform_realloc(void *ptr, size_t new_size);

void wish_platform_free(void* ptr);


int wish_platform_fill_random(void* dummy, unsigned char* buffer, size_t len);


long wish_platform_rng(void);

void wish_platform_set_rng(long (*fn)(void));

/* Set the platform-dependent sprintf function.
 * Note: You should provide the version which takes a va_list as
 * arguemnt.
 */
void wish_platform_set_vsprintf(int (*fn)(char* str, const char* format, va_list args)); 


#ifndef COMPILING_FOR_ESP8266
int wish_platform_sprintf(char* str, const char* format, ...);
#define wish_platform_snprintf snprintf
#else
int ets_sprintf(char *str, const char *format, ...)  __attribute__ ((format (printf, 2, 3)));
#define wish_platform_sprintf ets_sprintf
#endif

/* Set the platform-dependent printf function.
 * Note: You should provide the version which takes a va_list as
 * argument.
 */
void wish_platform_set_vprintf(int (*fn)(const char* format, va_list args));

int wish_platform_printf(const char* format, ...);

#endif
