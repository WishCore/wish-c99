/**
 * Copyright (C) 2018, ControlThings Oy Ab
 * Copyright (C) 2018, André Kaustell
 * Copyright (C) 2018, Jan Nyman
 * Copyright (C) 2018, Jepser Lökfors
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * @license Apache-2.0
 */
#pragma once

/* Wish C - I/O functions for driving the Wish on-wire protocol */

#include "rb.h"
#include "wish_rpc.h"
#include "wish_port_config.h"

#define WISH_CORE_DECRYPT_FAIL 1

#include "wish_core.h"
#include "wish_time.h"

#include "wish_relay_client.h"

/* Constants for the third byte of the handshake */
#define WISH_WIRE_VERSION   0x1   /* High nibble: Protocol version */
#define WISH_WIRE_TYPE_NORMAL       0x1   /* low nibble: protocol type for
normal wish connections */
#define WISH_WIRE_TYPE_FRIEND_REQ   0x3   /* low nibble: protocol type for
'friend requests' */
#define WISH_WIRE_TYPE_RELAY_CONTROL 0x6    /* Low nibble: Protocol type
for relay control connection opened by relay client */
#define WISH_WIRE_TYPE_RELAY_SESSION 0x7    /* low nibble: Protocol type
for a Wish connection relayed via a relay server session */

enum transport_state {
    TRANSPORT_STATE_INITIAL,
    TRANSPORT_STATE_WAIT_FRAME_LEN,
    TRANSPORT_STATE_WAIT_PAYLOAD,
    TRANSPORT_STATE_SERVER_WAIT_INITIAL,
    /* This is the initial state of the transport when opening a Wish
     * connection to relay server for the purpose of accepting an
     * incoming relay connection */
    TRANSPORT_STATE_RELAY_CLIENT_SEND_SESSION_ID,
    TRANSPORT_STATE_CONNECTING, /* Used by Linux port */
};

enum protocol_state {
    PROTO_STATE_INITIAL,
    /* State where shared key is decided upon with DH procedure */
    PROTO_STATE_DH,
    /* State where the client hash is sent to remote server for validation */
    PROTO_STATE_ID_VERIFY_SEND_CLIENT_HASH,
    /* State where the server hash is received and checked */
    PROTO_STATE_ID_VERIFY_SERVER_HASH,
    /* State where Wish connection metadata is exchanged */
    PROTO_STATE_WISH_HANDSHAKE,
    /* State where Wish connection is open */
    PROTO_STATE_WISH_RUNNING,
    /* Server's state where DH procedure is completed using the client's input; after that, Wish handshake is sent using the new encrypted link */
    PROTO_SERVER_STATE_DH,
    /* State where the client hash is received and verified, and signature of server's own hash is sent */
    PROTO_SERVER_STATE_VERIFY_CLIENT_HASH,
    /* State where server sends handshake message */
    PROTO_SERVER_STATE_WISH_SEND_HANDSHAKE,
    /* Server's state where the handshake reply sent by client is processed */
    PROTO_SERVER_STATE_WISH_HANDSHAKE_READ_REPLY, 
};

enum tcp_event {
    TCP_CONNECTED,
    TCP_DISCONNECTED,
    TCP_CLIENT_CONNECTED,   /* in server mode, remote client has connected */
    TCP_CLIENT_DISCONNECTED, /* in server mode, remote client has disconnected */
    TCP_RELAY_SESSION_CONNECTED,
};

#define SHA256_HASH_LEN 32
#define ED25519_SIGNATURE_LEN 64

#define AES_GCM_KEY_LEN         16  /* AES 128 in use */
#define AES_GCM_IV_LEN          12
#define AES_GCM_AUTH_TAG_LEN    16

typedef struct wish_remote_service {
    uint8_t name[WISH_APP_NAME_MAX_LEN];
    uint8_t rsid[WISH_WSID_LEN];
    char protocol[10];
    struct wish_remote_service *next;
} wish_remote_app;

enum wish_context_state {
    WISH_CONTEXT_FREE,      /* Uncommitted, unused "free" wish connection */
    WISH_CONTEXT_IN_MAKING, /* The context is in use, but the connection
    is being set up and is not yet available */
    WISH_CONTEXT_CONNECTED, /* the context is in use, and actions may be
    performed with it */
    WISH_CONTEXT_CLOSING    /* The context is in use, but is currently
    closing down and is no longer available */
};

#define RX_RINGBUF_LEN (WISH_PORT_RX_RB_SZ)

#include "wish_identity.h"

typedef struct wish_context wish_connection_t;

struct wish_context {
    /* An unique connection id which is unique to a wish core
     * connection, can be used to associate the context with the underlying 
     * network transport connection, for example */
    wish_core_t* core;
    wish_connection_id_t connection_id;
    /** Connection state */
    enum wish_context_state context_state;
    /* Function used by wish core to send TCP data */
    int (*send)(wish_connection_t* connection, unsigned char*, int);
    /* Data to be supplied as first argument to wish_context.send */
    void* send_arg;
    enum transport_state curr_transport_state;
    enum protocol_state curr_protocol_state;
    int expect_bytes;
    uint8_t luid[WISH_ID_LEN];
    uint8_t ruid[WISH_ID_LEN];
    uint8_t rhid[WISH_WHID_LEN];
    unsigned char aes_gcm_key_in[AES_GCM_KEY_LEN];
    unsigned char aes_gcm_key_out[AES_GCM_KEY_LEN];
    unsigned char aes_gcm_iv_in[AES_GCM_IV_LEN]; /* The current initialisation vector */
    unsigned char aes_gcm_iv_out[AES_GCM_IV_LEN]; /* The current initialisation vector */
    /* XXX FIXME server_dhm_ctx declared as void* but should be 
     * mbedtls_dhm_context* */
    void* server_dhm_ctx;    /* FIXME Used in server mode, when
    performing DH key exchange with incoming client connection */
    /* The following information is required for distinguishing between
     * connections */
    uint16_t local_port;    /* Local TCP socket port num */
    uint16_t remote_port;   /* Remote TCP socket port num */
    uint8_t local_ip_addr[4];     /* Our IP address (Is this needed?) */
    uint8_t remote_ip_addr[4];     /* remote party's IP address */
    ring_buffer_t rx_ringbuf;
    uint8_t rx_ringbuf_backing[RX_RINGBUF_LEN];
    /* Client hash and server hash are saved here because of convenience
     * They could be "downgraded" to pointers pointing to buffers allocated from
     * heap */
    uint8_t client_hash[SHA256_HASH_LEN];
    uint8_t server_hash[SHA256_HASH_LEN];
    /* A timestamp denoting when this wish connection last saw input
     * from the remote host. Used for connection pinging. */
    wish_time_t latest_input_timestamp;
    /* A timestamp denoting when the connection ping was last sent. */
    wish_time_t ping_sent_timestamp;
    /* This timestamp is used by the ESP8266 port to keep track when the
     * connection should be aborted */
    wish_time_t close_timestamp;
    /* true when connection initiated by us, false when accepted as incoming */
    bool outgoing;
    /* True, if the connection is opened via a relay server 
     * (used when opening a connection for accepting an incoming
     * connection) */
    bool via_relay;
    /* A pointer to a the relay context, applicable only to Wish
     * contexts which are opened for accepting an incoming connection
     * via the a relay server */
    wish_relay_client_t *relay;
    /** This flag must be set to true when you open a connection to a
     * peer in order to send a friend request */
    bool friend_req_connection;
    const char* friend_req_meta;
    wish_remote_app* apps;
#ifdef WISH_CORE_DEBUG
    int bytes_in;
    int bytes_out;
#endif
};

struct wish_peer {
    uint8_t *luid;  /* Local wuid */
    uint8_t *ruid;  /* Remote wuid */
    uint8_t *rsid;  /* Remote service id */
    uint8_t *rhid;  /* Remote host id */
    char *protocol;    /* Protocol name */
};

/* Start an instance of wish communication */
wish_connection_t* wish_connection_init(wish_core_t* core, const uint8_t* luid, const uint8_t* ruid);

/* Feed raw data into wish core */
void wish_core_feed(wish_core_t* core, wish_connection_t* h, unsigned char* data, int len);

/* This function will process data saved into the ringbuffer by function
 * wish_core_feed. 
 * Returns 1 when there was data left in receive ring buffer, and futher
 * processing is possible. 
 * Returns 0 when there is no more data to be read at this time.
 */
void wish_core_process_data(wish_core_t* core, wish_connection_t* h);

/* Register a function which will be used by wish core when data is
 * to be sent.
 *
 * The send function is called with the argument given as arg */
void wish_core_register_send(wish_core_t* core, wish_connection_t* h, int (*send)(wish_connection_t*,
unsigned char*, int), void* arg);

void wish_core_signal_tcp_event(wish_core_t* core, wish_connection_t* h, enum tcp_event);

void wish_core_handle_payload(wish_core_t* core, wish_connection_t* ctx, uint8_t* payload, int len);

/* Decrypt a "Wish frame" - 
 */
int wish_core_decrypt(wish_core_t* core, wish_connection_t* ctx, uint8_t* ciphertxt, size_t 
ciphertxt_len, uint8_t* auth_tag, size_t auth_tag_len, uint8_t* plaintxt,
size_t plaintxt_len );

/**
 * Send a payload using the Wish connection.
 * 
 * Send data over wish connection. It will encrypt the payload, and construct a f
 * rame with payload length, the encrypted payload and auth_tag.
 *
 * @return 0, if sending succeeded, non-zero if fail. This is directly
 * the return value of the platform-specific sending function
 */
int wish_core_send_message(wish_core_t* core, wish_connection_t* ctx, const uint8_t* payload_clrtxt, int payload_len);
    
uint16_t uint16_native2be(uint16_t);

void wish_core_subscribe_services(wish_core_t* core, wish_connection_t* ctx);

/* Returns pointer to first element in connection pool, where there are 
 * WISH_CONTEXT_POOL_SZ elements */
wish_connection_t* wish_core_get_connection_pool(wish_core_t* core);

/* This function returns the wish context associated with the provided
 * remote IP, remote port, local IP, local port. If no matching wish
 * context is found, return NULL. */
wish_connection_t* wish_identify_context(wish_core_t* core, uint8_t rmt_ip[4], 
    uint16_t rmt_port, uint8_t local_ip[4], uint16_t local_port);

/* This function returns the pointer to the wish context corresponding
 * to the id number given as argument */
wish_connection_t* wish_core_lookup_ctx_by_connection_id(wish_core_t* core, wish_connection_id_t connection_id);

/** Check that a connection pointer actually represents a wish
 * connection in the pool.
 * @note it does check if the connection actually represents a connection between cores! */
wish_connection_t* wish_connection_is_from_pool(wish_core_t *core, wish_connection_t *connection);

/**
 * Returns wish connection matching given luid, ruid, rhid or NULL
 * 
 * This function returns a pointer to the wish context which matches the
 * specified luid, ruid, rhid identities 
 *
 * Please note: The context returned here could a countext which is not
 * yet ready for use, because it is e.g. just being created.
 */
wish_connection_t* wish_core_lookup_ctx_by_luid_ruid_rhid(wish_core_t* core, const uint8_t *luid, const uint8_t *ruid, const uint8_t *rhid);

wish_connection_t* 
wish_core_lookup_connected_ctx_by_luid_ruid_rhid(wish_core_t* core, const uint8_t *luid, const uint8_t *ruid, const uint8_t *rhid);

/* returns true if there is any connection form luid to ruid */
bool wish_core_is_connected_luid_ruid(wish_core_t* core, uint8_t *luid, uint8_t *ruid);

/**
 * This function will perform misc initting of various parts of the
 * system, mainly initting of RPC servers in the core 
 */
void wish_core_init(wish_core_t* core);

/*
 * This function returns the number of bytes free in the ring buffer 
 */
int wish_core_get_rx_buffer_free(wish_core_t* core, wish_connection_t* connection);
