#ifndef WISH_UTILS_H
#define WISH_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include "wish_ip_addr.h"

/**
 * Parse a TCP port from "wish URL" such as the ones typically found in 
 * transports.
 *
 * @return 0, if parsing was succesful and yeilded results. 1 for
 * errors, then the parameter port is not valid.
 */
int wish_parse_transport_port(char *url, size_t url_len, uint16_t *port);

/**
 * Parse a IP address from a "wish URL"
 * @return 0 if the parsing was successful and yeilded results. Any
 * other return value signifies failure.
 */
int wish_parse_transport_ip(char *url, size_t url_len, wish_ip_addr_t *ip);

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

