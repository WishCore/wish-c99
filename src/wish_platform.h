#pragma once

/* Porting layer functions */

#include <stddef.h>
#include <stdarg.h>


void wish_platform_set_malloc(void* (*fn)(size_t size));

void wish_platform_set_realloc(void* (*fn)(void *, size_t size));

void wish_platform_set_free(void (*fn)(void *ptr));

void wish_platform_set_realloc(void* (*fn)(void *, size_t size));

void* wish_platform_malloc(size_t size);

void* wish_platform_realloc(void *ptr, size_t new_size);

void wish_platform_free(const void* ptr);


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
#define wish_platform_snprintf(str, size, format, ...) ets_sprintf(str, format, __VA_ARGS__)
#endif

/* Set the platform-dependent printf function.
 * Note: You should provide the version which takes a va_list as
 * argument.
 */
void wish_platform_set_vprintf(int (*fn)(const char* format, va_list args));

int wish_platform_printf(const char* format, ...);

/**
 * Duplicate string. 
 *
 * Allocates memory from the heap for the duplicate, and copies the
 * string there. The copy must be de-allocated with wish_platform_free
 * after you are done with it.
 * 
 * This is needed to wrap the C library function strdup, which is unavailable on some platforms.
 *
 * @param str pointer to the string to be duplicated
 * @return the duplicate string, or NULL if fail
 */
char* wish_platform_strdup(const char* str);