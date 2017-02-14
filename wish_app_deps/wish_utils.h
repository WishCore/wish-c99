#ifndef WISH_UTILS_H
#define WISH_UTILS_H

#include <stdint.h>
#include <stddef.h>

/**
 * Duplicate string. 
 *
 * Allocates memory from the heap for the duplicate, and copies the
 * string there. The copy must be de-allocated with wish_platform_free
 * after you are done with it.
 *
 * @param str pointer to the string to be duplicated
 * @return the duplicate string, or NULL if fail
 */
char* my_strdup(char* str);

#endif  // WISH_UTILS_H

