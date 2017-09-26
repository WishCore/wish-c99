#pragma once

/* 
 * Wish local UDP discovery functionality
 */

#include <stddef.h>
#include "wish_connection.h"
#include "wish_identity.h"
#include "wish_port_config.h"

typedef enum {
    DISCOVER_TYPE_NONE,
    DISCOVER_TYPE_LOCAL,
    DISCOVER_TYPE_REMOTE,
    DISCOVER_TYPE_FRIEND_REQ,
    DISCOVER_TYPE_DIRECTORY
} ldiscover_type;

typedef struct wish_ldiscover_t {
    /* This field is used for identifying occupied/vacant app contexts.
     * Has value false if context is vacant */
    bool occupied;
    /**  */
    ldiscover_type type;
    /* The service IF of the app */
    uint8_t luid[WISH_ID_LEN];
    uint8_t ruid[WISH_ID_LEN];
    uint8_t rhid[WISH_ID_LEN];
    uint8_t rsid[WISH_ID_LEN];
    uint8_t pubkey[WISH_PUBKEY_LEN];
    uint8_t alias[WISH_ALIAS_LEN];
    bool claim;
    uint32_t timestamp;
    /* FIXME support support multiple transports, and IPv6, and..  */
    wish_ip_addr_t transport_ip;
    uint16_t transport_port;
    const char* meta;
} wish_ldiscover_t;

void wish_ldiscover_init(wish_core_t* core);

/** Make announcements for all identities */
void wish_ldiscover_announce_all(wish_core_t* core);

/* Start accepting local discovery messages */
void wish_ldiscover_enable_recv(wish_core_t* core);

/* Stop accepting local discovery messages */
void wish_ldiscover_disable_recv(wish_core_t* core);

/* Start advertizing using local discovery messages */
void wish_ldiscover_enable_bcast(wish_core_t* core);

/* Stop advertizing using local discovery messages */
void wish_ldiscover_disable_bcast(wish_core_t* core);

/* Feed local discovery message data into Wish core for processing.
 * ip[4], the originating IPv4 address
 * port, the originating UDP port (in host byte order)
 */
void wish_ldiscover_feed(wish_core_t* core, wish_ip_addr_t *ip, uint16_t port, uint8_t *buffer, size_t buffer_len);

/* Send out one "advertizement" message for wish identity my_uid */
void wish_ldiscover_advertize(wish_core_t* core, uint8_t *my_uid);

/** */
void wish_ldiscover_add(wish_core_t* core, wish_ldiscover_t* entry);

/** */
//void wish_ldiscover_remove(wish_core_t* core, wish_ldiscover_t* entry);

/** Clear the table */
void wish_ldiscover_clear(wish_core_t* core);

wish_ldiscover_t *wish_ldiscover_get(wish_core_t* core);

