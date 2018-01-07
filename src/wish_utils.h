#pragma once

#include <stdint.h>
#include <stddef.h>
#include "wish_ip_addr.h"

int wish_parse_transport_ip_port(const char *url, size_t url_len, wish_ip_addr_t *ip, uint16_t *port);

/**
 * Parse a TCP port from "wish URL" such as the ones typically found in 
 * transports.
 *
 * @return 0, if parsing was succesful and yeilded results. 1 for
 * errors, then the parameter port is not valid.
 */
int wish_parse_transport_port(const char *url, size_t url_len, uint16_t *port);

/**
 * Parse a IP address from a "wish URL"
 * @return 0 if the parsing was successful and yeilded results. Any
 * other return value signifies failure.
 */
int wish_parse_transport_ip(const char *url, size_t url_len, wish_ip_addr_t *ip);


