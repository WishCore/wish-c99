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

void socket_set_nonblocking(int sockfd);

void relay_ctrl_connected_cb(wish_core_t* core, wish_relay_client_ctx_t *relay) {
    //printf("Relay control connection established\n");
}

void relay_ctrl_connect_fail_cb(wish_core_t* core, wish_relay_client_ctx_t *relay) {
    printf("Relay control connection fails\n");
    relay->curr_state = WISH_RELAY_CLIENT_WAIT_RECONNECT;
}

void relay_ctrl_disconnect_cb(wish_core_t* core, wish_relay_client_ctx_t *relay) {
    printf("Relay control connection disconnected\n");
    relay->curr_state = WISH_RELAY_CLIENT_WAIT_RECONNECT;
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

void wish_relay_client_open(wish_core_t* core, wish_relay_client_ctx_t *relay, 
        uint8_t relay_uid[WISH_ID_LEN]) {
    /* FIXME this has to be split into port-specific and generic
     * components. For example, setting up the RB, next state, expect
     * byte, copying of id is generic to all ports */
    relay->curr_state = WISH_RELAY_CLIENT_OPEN;
    ring_buffer_init(&(relay->rx_ringbuf), relay->rx_ringbuf_storage, 
        RELAY_CLIENT_RX_RB_LEN);
    memcpy(relay->relayed_uid, relay_uid, WISH_ID_LEN);

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
        relay->ip.addr[0], relay->ip.addr[1], 
        relay->ip.addr[2], relay->ip.addr[3]);

    int relay_port = relay->port;
    //printf("Connecting to relay server: %s:%d\n", ip_str, relay_port);
    inet_aton(ip_str, &relay_serv_addr.sin_addr);
    relay_serv_addr.sin_port = htons(relay_port);
    if (connect(relay_sockfd, (struct sockaddr *) &relay_serv_addr, 
            sizeof(relay_serv_addr)) == -1) {
        if (errno == EINPROGRESS) {
            //printf("Started connecting to relay server\n");
            relay->send = relay_send;
            relay->send_arg = &relay_sockfd;
        }
        else {
            perror("relay server connect()");
            relay->curr_state = WISH_RELAY_CLIENT_WAIT_RECONNECT;
        }
    }
}

void wish_relay_client_close(wish_core_t* core, wish_relay_client_ctx_t *relay) {
    close(relay_sockfd);
    relay_ctrl_disconnect_cb(core, core->relay_db);
}

/**
 * Get relay contexts. 
 *
 * @return pointer to an array containing the relay contexts
 */
wish_relay_client_ctx_t *wish_relay_get_contexts(wish_core_t* core) {
    return core->relay_db;
}


