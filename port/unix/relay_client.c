#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <time.h>
#include <arpa/inet.h>
#include <errno.h>


#include "wish_relay_client.h"
#include "wish_io.h"

/* Instantiate Relay client to a server with specied IP addr and port */
wish_relay_client_ctx_t relay_ctx = { 
    .ip = { .addr = { RELAY_SERVER_IP0, RELAY_SERVER_IP1, 
        RELAY_SERVER_IP2, RELAY_SERVER_IP3 } }, /* FIXME IP expressed in reverse! */ 
    .port = RELAY_SERVER_PORT
};

void socket_set_nonblocking(int sockfd);

void relay_ctrl_connected_cb(void) {
    //printf("Relay control connection established\n");
}

void relay_ctrl_connect_fail_cb(void) {
    printf("Relay control connection fails\n");
    relay_ctx.curr_state = WISH_RELAY_CLIENT_WAIT_RECONNECT;
}

void relay_ctrl_disconnect_cb(void) {
    printf("Relay control connection disconnected\n");
    relay_ctx.curr_state = WISH_RELAY_CLIENT_WAIT_RECONNECT;
}



/* Function used by Wish to send data over the Relay control connection
 * */
int relay_send(void *send_arg, unsigned char* buffer, int len) {
    int relay_sockfd = *((int *) send_arg);
    int n = write(relay_sockfd, buffer, len);
    //printf("Wrote %i bytes to relay\n", n);
    if (n < 0) {
        perror("ERROR writing to relay");
    }
    return 0;
}

/* FIXME move the sockfd inside the relay context, so that we can
 * support many relay server connections! */
int relay_sockfd;

void wish_relay_client_open(wish_relay_client_ctx_t *rctx, 
        uint8_t relay_uid[WISH_ID_LEN]) {
    /* FIXME this has to be split into port-specific and generic
     * components. For example, setting up the RB, next state, expect
     * byte, copying of id is generic to all ports */
    rctx->curr_state = WISH_RELAY_CLIENT_OPEN;
    ring_buffer_init(&(rctx->rx_ringbuf), rctx->rx_ringbuf_storage, 
        RELAY_CLIENT_RX_RB_LEN);
    memcpy(rctx->relayed_uid, relay_uid, WISH_ID_LEN);

    /* Linux/Unix-specific from now on */ 

    struct sockaddr_in relay_serv_addr;

    //printf("Open relay connection");
    relay_sockfd = socket(AF_INET, SOCK_STREAM, 0);

    socket_set_nonblocking(relay_sockfd);

    if (relay_sockfd < 0) {
        perror("ERROR opening socket");
    }
    relay_serv_addr.sin_family = AF_INET;
    char ip_str[12+3+1] = { 0 };
    sprintf(ip_str, "%i.%i.%i.%i", 
        relay_ctx.ip.addr[0], relay_ctx.ip.addr[1], 
        relay_ctx.ip.addr[2], relay_ctx.ip.addr[3]);

    int relay_port = relay_ctx.port;
    //printf("Connecting to relay server: %s:%d\n", ip_str, relay_port);
    inet_aton(ip_str, &relay_serv_addr.sin_addr);
    relay_serv_addr.sin_port = htons(relay_port);
    if (connect(relay_sockfd, (struct sockaddr *) &relay_serv_addr, 
            sizeof(relay_serv_addr)) == -1) {
        if (errno == EINPROGRESS) {
            //printf("Started connecting to relay server\n");
            rctx->send = relay_send;
            rctx->send_arg = &relay_sockfd;
        }
        else {
            perror("relay server connect()");
            rctx->curr_state = WISH_RELAY_CLIENT_WAIT_RECONNECT;
        }
    }
}

void wish_relay_client_close(wish_relay_client_ctx_t *rctx) {
    close(relay_sockfd);
    relay_ctrl_disconnect_cb();
}

/**
 * Get relay contexts. 
 *
 * @return pointer to an array containing the relay contexts
 */
wish_relay_client_ctx_t *wish_relay_get_contexts(void) {
    return &relay_ctx;
}


