#pragma once

#include "wish_core.h"

#define PING_INTERVAL 10    /* seconds */
#define PING_TIMEOUT (PING_INTERVAL + 30) /* seconds, must be larger than PING_INTERVAL */

#define CONNECTION_TIMEOUT 30 /* seconds */

/** Timeout of connection in making */
#define CONNECTION_SETUP_TIMEOUT PING_TIMEOUT

/** Timeout of a friend request connection */
#define FRIEND_REQ_TIMEOUT 300 /* Seconds */

/* Wish connection manager interface.
 * These functions will usually be implemented in port-specific code */

void wish_connections_init(wish_core_t* core);

/* Initiate a wish connection to specified ip and port, and associate
 * the wish_context ctx to the connection */
int wish_open_connection(wish_core_t* core, wish_connection_t* connection, wish_ip_addr_t *ip, uint16_t port, bool via_relay);
    
int wish_send_advertizement(wish_core_t* core, uint8_t *ad, size_t ad_len);

/* Gracefully initiate a TCP socket close */
void wish_close_connection(wish_core_t* core, wish_connection_t* connection);

void wish_close_all_connections(wish_core_t* core);

void wish_connections_check(wish_core_t* core);

void check_connection_liveliness(wish_core_t* core, void* ctx);

/**
 * Get the local host IP addr formatted as a C string. The retuned
 * address should be the one which is the subnet having the host's
 * default route
 *
 * @param addr_str the pointer where the address should be stored
 * @param addr_str_len the maximum allowed length of the address
 * @return Returns value 0 if all went well.
 */
int wish_get_host_ip_str(wish_core_t* core, char* addr_str, size_t addr_str_len);

/** Get the local TCP port where the Wish core accepts incoming connections 
 * @return the local TCP server port
 */
int wish_get_host_port(wish_core_t* core);
void wish_set_host_port(wish_core_t* core, uint16_t port);


return_t wish_connections_connect_tcp(wish_core_t* core, uint8_t *luid, uint8_t *ruid, wish_ip_addr_t *ip, uint16_t port);

void wish_close_parallel_connections(wish_core_t* core, void *connection);
