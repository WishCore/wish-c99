#ifndef WISH_RELAY_CLIENT_H
#define WISH_RELAY_CLIENT_H

#include "rb.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "wish_ip_addr.h"
#include "wish_time.h"


/* Define Relay server IP and port: */
#define RELAY_SERVER_IP0 193
#define RELAY_SERVER_IP1 65
#define RELAY_SERVER_IP2 54
#define RELAY_SERVER_IP3 131
#define RELAY_SERVER_PORT 40000

#define RELAY_SERVER_TIMEOUT 45 /* Seconds */

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


typedef struct {
    /* The UID for which connections are to be relayed */
    uint8_t relayed_uid[32];
    /* The Relay session id given by the relay server is stored here */
    uint8_t session_id[RELAY_SESSION_ID_LEN];
    enum wish_relay_client_state curr_state;
    /* Function used to send TCP data */
    int (*send)(void *, unsigned char*, int);
    /* Data to be supplied as first argument to wish_context.send */
    void* send_arg;
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
} wish_relay_client_ctx_t;

void wish_relay_client_init(wish_relay_client_ctx_t *rctx, uint8_t *relay_uid);

/* To be implemented in port-specific code */
void wish_relay_client_open(wish_relay_client_ctx_t *rctx,
    uint8_t relay_uid[32]);

/* To be implemented in port-specific code */
void wish_relay_client_close(wish_relay_client_ctx_t *rctx);

/* This function should be invoked regularly to process data received
 * from relay server and take actions accordingly */
void wish_relay_client_periodic(wish_relay_client_ctx_t *rctx);

/* This function is used by the port-specific TCP socket read function
 * to feed data into the relay client */
void wish_relay_client_feed(wish_relay_client_ctx_t *rctx, 
    uint8_t *data, size_t data_len);

int wish_relay_get_preferred_server_url(char *url_str, int url_str_len);

/**
 * Get relay contexts. 
 *
 * @return pointer to an array containing the relay contexts
 */
wish_relay_client_ctx_t *wish_relay_get_contexts(void);

/** 
 * Check timeout status on the relay contexts 
 */
void wish_relay_check_timeout(void);

#endif //WISH_RELAY_CLIENT_H
