#pragma once

#include "rb.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "wish_ip_addr.h"
#include "wish_time.h"
#include "wish_utils.h"

/* Define Relay server IP and port: */
#define RELAY_SERVER_HOST "193.65.54.131:40000"

#define RELAY_SERVER_TIMEOUT 45 /* Seconds */

#define RELAY_CLIENT_RECONNECT_TIMEOUT 10 /* Seconds */

#define RELAY_SESSION_ID_LEN 10

enum wish_relay_client_state {
    WISH_RELAY_CLIENT_INITIAL,  /* The initial state */
    WISH_RELAY_CLIENT_OPEN,     /* The state where the client sends the
    preamble + uid */
    WISH_RELAY_CLIENT_READ_SESSION_ID,  /* The state where the client
    waits for the session id */
    WISH_RELAY_CLIENT_WAIT, /* The state where we wait that somebody
    would like to connect via the relay server. The server sends
    keep-alives which we discard */
    WISH_RELAY_CLIENT_CLOSING,
    WISH_RELAY_CLIENT_WAIT_RECONNECT, /* temporary state for the connection for waiting a connect re-try */
};

/* Receive ring buffer length */
#define RELAY_CLIENT_RX_RB_LEN 64


typedef struct wish_relay_client_ctx {
    int sockfd;
    /* The UID for which connections are to be relayed */
    uint8_t relayed_uid[32];
    /* The Relay session id given by the relay server is stored here */
    uint8_t session_id[RELAY_SESSION_ID_LEN];
    enum wish_relay_client_state curr_state;
    /* Function used to send TCP data */
    int (*send)(int, unsigned char*, int);
    ring_buffer_t rx_ringbuf;
    uint8_t rx_ringbuf_storage[RELAY_CLIENT_RX_RB_LEN];
    /* The Relay server's IP address */
    wish_ip_addr_t ip;
    uint16_t port;
    /** This timestamp is updated every time data is fed into the relay
     * server system. User for detecting dead relay server control
     * connection */
    wish_time_t last_input_timestamp;
    /* TODO: Add here some kind of reference to the actual port-specific connection
     * object (such as file descriptor or struct espconn) so that we
     * could some day handle several relay control connections */
    struct wish_relay_client_ctx* next;
} wish_relay_client_t;


void relay_ctrl_connected_cb(wish_core_t* core, wish_relay_client_t *relay);
void relay_ctrl_connect_fail_cb(wish_core_t* core, wish_relay_client_t *relay);
void relay_ctrl_disconnect_cb(wish_core_t* core, wish_relay_client_t *relay);

void wish_core_relay_client_init(wish_core_t* core);

void wish_relay_client_add(wish_core_t* core, const char* host);

/* To be implemented in port-specific code */
void wish_relay_client_open(wish_core_t* core, wish_relay_client_t *rctx,
    uint8_t relay_uid[32]);

/* To be implemented in port-specific code */
void wish_relay_client_close(wish_core_t* core, wish_relay_client_t *rctx);

/* This function should be invoked regularly to process data received
 * from relay server and take actions accordingly */
void wish_relay_client_periodic(wish_core_t* core, wish_relay_client_t *rctx);

/* This function is used by the port-specific TCP socket read function
 * to feed data into the relay client */
void wish_relay_client_feed(wish_core_t* core, wish_relay_client_t *rctx, 
    uint8_t *data, size_t data_len);

int wish_relay_get_preferred_server_url(char *url_str, int url_str_len);

/**
 * Get relay contexts. 
 *
 * @return pointer to an array containing the relay contexts
 */
wish_relay_client_t *wish_relay_get_contexts(wish_core_t* core);

/** 
 * Check timeout status on the relay contexts 
 */
void wish_relay_check_timeout(wish_core_t* core);
