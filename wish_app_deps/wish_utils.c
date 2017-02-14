#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "wish_platform.h"

/* A private implementation of the C library "strdup" function, which is
 * unavailable on the current ESP SDK
 *
 */
char* my_strdup(char* str) {
    /* Length of the string, plus null byte */
    int len = strlen(str) + 1;
    char* copy = (char*) wish_platform_malloc(len);
    if (copy) {
        memset(copy, 0, len);
        memcpy(copy, str, len);
    }
    return copy;
}


