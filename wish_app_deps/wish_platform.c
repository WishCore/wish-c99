#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
//#include "wish_io.h"
#include "wish_platform.h"

/* Variables for saving the function pointers set via wish_platform_set_* */
void* (*my_malloc)(size_t size);
void* (*my_realloc)(void *ptr, size_t size);
void (*my_free)(void *ptr);
int (*my_vsprintf)(char* str, const char* format, va_list args);
int (*my_vprintf)(const char* format, va_list args);
long (*my_random)(void);


int wish_platform_fill_random(void* dummy, unsigned char* buffer, size_t len) {
    int i = 0;
    for (i = 0; i < len; i++) {
        buffer[i] = my_random();
    }
    return 0;
}

long wish_platform_rng(void) {
    return my_random();
}

void wish_platform_set_rng(long (*fn)(void)) {
    my_random = fn;
}


void wish_platform_set_malloc(void* (*fn)(size_t size)) {
    my_malloc = fn;
}

void wish_platform_set_realloc(void* (*fn)(void *, size_t size)) {
    my_realloc = fn;
}


void wish_platform_set_free(void (*fn)(void *ptr)) {
    my_free = fn;
}

void* wish_platform_malloc(size_t size) {
    return my_malloc(size);
}

void* wish_platform_realloc(void *ptr, size_t size) {
    return my_realloc(ptr, size);
}



void wish_platform_free(void* ptr) {
    my_free(ptr);
}

void wish_platform_set_vsprintf(int (*fn)(char* str, const char* format, va_list args)) {
    my_vsprintf = fn;
}

void wish_platform_set_vprintf(int (*fn)(const char* format, va_list args)) {
    my_vprintf = fn;
}

#ifndef COMPILING_FOR_ESP8266
/* For "normal" platforms, we use this function taking a variable
 * argument list. For ESP8266, we just re-define wish_platform_sprintf
 * to a platform-specific sprintf function */
int wish_platform_sprintf(char* str, const char* format, ...) {
    if (my_vsprintf == NULL) {
        return 0;
    }
    va_list argptr;
    va_start(argptr, format);
    int retval = my_vsprintf(str, format, argptr);
    va_end(argptr);
    return retval;
}
#endif


int wish_platform_printf(const char* format, ...) {
    if (my_vprintf == NULL) {
        return 0;
    }
    va_list argptr;
    va_start(argptr, format);
    int retval = my_vprintf(format, argptr);
    va_end(argptr);
    return retval;
}


