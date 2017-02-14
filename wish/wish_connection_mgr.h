#ifndef WISH_CONNECTION_MGR_H
#define WISH_CONNECTION_MGR_H


/* Wish connection manager interface.
 * These functions will usually be implemented in port-specific code */

/* Initiate a wish connection to specified ip and port, and associate
 * the wish_context ctx to the connection */
int wish_open_connection(wish_context_t *ctx, wish_ip_addr_t *ip, uint16_t port, bool via_relay);
    
int wish_send_advertizement(uint8_t *ad, size_t ad_len);

/* Gracefully initiate a TCP socket close */
void wish_close_connection(wish_context_t *ctx);

void wish_close_all_connections(void);

void wish_connections_check(void);

/**
 * Get the local host IP addr formatted as a C string. The retuned
 * address should be the one which is the subnet having the host's
 * default route
 *
 * @param addr_str the pointer where the address should be stored
 * @param addr_str_len the maximum allowed length of the address
 * @return Returns value 0 if all went well.
 */
int wish_get_host_ip_str(char* addr_str, size_t addr_str_len);

/** Get the local TCP port where the Wish core accepts incoming connections 
 * @return the local TCP server port
 */
int wish_get_host_port(void);
void wish_set_host_port(uint16_t port);


void wish_connections_connect_tcp(uint8_t *luid, uint8_t *ruid, wish_ip_addr_t *ip, uint16_t port);

#endif
