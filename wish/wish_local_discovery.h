#ifndef WISH_LOCAL_DISCOVERY_H
#define WISH_LOCAL_DISCOVERY_H

/* 
 * Wish local UDP discovery functionality
 */

#include <stddef.h>
#include "wish_io.h"
#include "wish_identity.h"
#include "wish_port_config.h"


typedef struct {
    /* This field is used for identifying occupied/vacant app contexts.
     * Has value false if context is vacant */
    bool occupied;
    /* The service IF of the app */
    uint8_t ruid[WISH_ID_LEN];
    uint8_t rhid[WISH_ID_LEN];
    uint8_t pubkey[WISH_PUBKEY_LEN];
    uint8_t alias[WISH_MAX_ALIAS_LEN];
    uint32_t timestamp;
    /* FIXME support support multiple transports, and IPv6, and..  */
    wish_ip_addr_t transport_ip;
    uint16_t transport_port;
} wish_ldiscover_t;

/* Start accepting local discovery messages */
void wish_ldiscover_enable_recv(void);

/* Stop accepting local discovery messages */
void wish_ldiscover_disable_recv(void);

/* Start advertizing using local discovery messages */
void wish_ldiscover_enable_bcast(void);

/* Stop advertizing using local discovery messages */
void wish_ldiscover_disable_bcast(void);

/* Feed local discovery message data into Wish core for processing.
 * ip[4], the originating IPv4 address
 * port, the originating UDP port (in host byte order)
 */
void wish_ldiscover_feed(wish_core_t* core, wish_ip_addr_t *ip, uint16_t port, uint8_t *buffer, 
size_t buffer_len);

/* Send out one "advertizement" message for wish identity my_uid */
void wish_ldiscover_advertize(wish_core_t* core, uint8_t *my_uid);

/* Clear the table */
void wish_ldiscover_clear(void);

wish_ldiscover_t *wish_ldiscover_get(void);

#endif //WISH_LOCAL_DISCOVERY_H
