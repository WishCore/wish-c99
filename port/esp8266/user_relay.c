#include "ets_sys.h"
#include "osapi.h"
#include "gpio.h"
#include "os_type.h"
#include "user_config.h"
#include "user_task.h"
#include "c_types.h"
#include "ip_addr.h"
#include "espconn.h"
#include "mem.h"
#include "user_interface.h"
#include "espmissingincludes.h"

#include "wish_io.h"
#include "wish_relay_client.h"
#include "user_relay.h"
#include "wish_identity.h"

/* Support only one relay connection for now. Note however that having
 * several different relay connections would not be hard, just save the
 * new relay context's pointer to espconn->reverse at connect. */
wish_relay_client_ctx_t rctx = { 
    .ip = { .addr = { RELAY_SERVER_IP0, RELAY_SERVER_IP1, 
        RELAY_SERVER_IP2, RELAY_SERVER_IP3 } },
    .port = RELAY_SERVER_PORT,
};

static struct espconn* espconn;

/* Reconnect timer expired callback function */
static void user_relay_reconnect(void) {
    os_printf("Relay client control connection reconnect attempt\r\n");
    user_start_relay_control();
}

/*
 * The relay control connection's TCP receive CB
 */
static void user_relay_tcp_recv_cb(void *arg, char *pusrdata, unsigned short length) {
//    os_printf("in relay tcp recv cb\n\r");
    wish_relay_client_feed(&rctx, (unsigned char*) pusrdata, length);
    wish_relay_client_periodic(&rctx);
}

/* The relay control connection's TCP sent callback
 */
static void user_relay_tcp_sent_cb(void *arg)
{
}

LOCAL os_timer_t reconnect_timer;

/* The relay control connection's TCP connection disconnect callback 
 */
static void user_relay_tcp_discon_cb(void *arg)
{
    os_printf("Relay TCP disconnect cb\n\r");
    rctx.curr_state = WISH_RELAY_CLIENT_INITIAL;
    
    struct espconn *espconn = arg;
    os_free(espconn->proto.tcp);
    os_free(espconn);
    memset(&rctx, 0, sizeof (wish_relay_client_ctx_t));
    /* Schedule re-connect */
    os_timer_disarm(&reconnect_timer);
    os_timer_setfn(&reconnect_timer, 
        (os_timer_func_t *) user_relay_reconnect, NULL);
    os_timer_arm(&reconnect_timer, 10000, 0);
}

/*
 * The relay control connection's TCP send data function
 */
static int user_relay_tcp_send(void *pespconn, unsigned char* data, int len) {
    struct espconn* espconn = (struct espconn*) pespconn;

    return espconn_send(espconn, data, len);
}

/* 
 * The relay control connections TCP connect error callback 
 */
static void user_relay_tcp_recon_cb(void *arg, sint8 err) {
    struct espconn *espconn = arg;
    os_free(espconn->proto.tcp);
    os_free(espconn);
    os_printf("Error when establishing relay control connection: %d\r\n", err);
    /* Schedule re-connect */
    os_timer_disarm(&reconnect_timer);
    os_timer_setfn(&reconnect_timer, 
        (os_timer_func_t *) user_relay_reconnect, NULL);
    os_timer_arm(&reconnect_timer, 10000, 0);
}


/* 
 * The Relay control connection's TCP connect callback
 */
static void user_relay_tcp_connect_cb(void *arg) {
    struct espconn *pespconn = arg;

    os_printf("Relay server control connection established \r\n");
    os_timer_disarm(&reconnect_timer);

    espconn_regist_recvcb(pespconn, user_relay_tcp_recv_cb);
    espconn_regist_sentcb(pespconn, user_relay_tcp_sent_cb);
    espconn_regist_disconcb(pespconn, user_relay_tcp_discon_cb);
    espconn_regist_reconcb(pespconn, user_relay_tcp_recon_cb);

    rctx.send = user_relay_tcp_send;
    rctx.send_arg = arg;


    wish_relay_client_periodic(&rctx);
}

int8_t user_start_relay_control() {
    wish_uid_list_elem_t uid_list[4];
    memset(uid_list, 0, sizeof (uid_list));

    int num_ids = wish_load_uid_list(uid_list, 4);
    os_printf("Number of identities in db: %d\n", num_ids);
    uint8_t *relay_uid = uid_list[0].uid;



    /* FIXME refactor these! They are port-agnostic! */
    rctx.curr_state = WISH_RELAY_CLIENT_OPEN;
    ring_buffer_init(&(rctx.rx_ringbuf), rctx.rx_ringbuf_storage,
                    RELAY_CLIENT_RX_RB_LEN);
    memcpy(rctx.relayed_uid, relay_uid, WISH_ID_LEN);

    /* ESP-specific stuff starts here */

    os_printf("Open relay control connection\n\r");

    /* Allocate the espconn structure for client use. This will be
     * de-allocated in the client disconnect callback, or the
     * reconnect callback */
    espconn = (struct espconn*) os_malloc(sizeof(struct espconn));
    memset(espconn, 0, sizeof(struct espconn));
    esp_tcp* user_tcp = (esp_tcp*) os_malloc(sizeof(esp_tcp)); 
    memset(user_tcp, 0, sizeof(esp_tcp));
    espconn->proto.tcp = user_tcp;
    espconn->type = ESPCONN_TCP;
    espconn->state = ESPCONN_NONE;

    /* Connect to a Wish system willing to relay */
    ip_addr_t relay_server_ip;
    IP4_ADDR(&relay_server_ip, rctx.ip.addr[0], rctx.ip.addr[1], rctx.ip.addr[2], rctx.ip.addr[3]);

 
    sint8 err = 0;

    if (espconn->proto.tcp == 0) {
        err = ESPCONN_ARG;
    }
    else if (espconn->type != ESPCONN_TCP) {
        err = ESPCONN_ARG;
    }
    else if (espconn->state != ESPCONN_NONE) {
        err = ESPCONN_ARG;
    }
    else {
        /* struct espconn seems acceptable */

        os_memcpy(espconn->proto.tcp->remote_ip, &relay_server_ip, 4);

        espconn->proto.tcp->remote_port = rctx.port;      // remote port

        espconn->proto.tcp->local_port = espconn_port();   //local port of ESP8266

        espconn_regist_connectcb(espconn, user_relay_tcp_connect_cb);  // register connect callback
        espconn_regist_reconcb(espconn, user_relay_tcp_recon_cb);      // register reconnect callback as error handler
        espconn_connect(espconn);
    }

    return err;
}

/**
 * Get relay contexts. 
 *
 * @return pointer to an array containing the relay contexts
 */
wish_relay_client_ctx_t *wish_relay_get_contexts(void) {
    return &rctx;
}


void wish_relay_client_close(wish_relay_client_ctx_t *rctx) {
    if (espconn_disconnect(espconn) != 0) {
        os_printf("Relay control diconnect fail");
    }
}
