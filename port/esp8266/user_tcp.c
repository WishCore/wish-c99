#include "ets_sys.h"
#include "osapi.h"
#include "gpio.h"
#include "os_type.h"
#include "user_config.h"
#include "user_task.h"

#include "driver/uart.h"

#include "c_types.h"
#include "ip_addr.h"
#include "espconn.h"
#include "mem.h"
#include "user_interface.h"
#include "espmissingincludes.h"

#include "wish_ip_addr.h"
#include "wish_io.h"
#include "wish_dispatcher.h"
#include "wish_event.h"

#include "user_tcp.h"
#include "user_wifi.h"
#include "user_relay.h"
#include "user_tcp_client.h"
#include "user_tcp_server.h"

#include "wish_event.h"
#include "wish_identity.h"
#include "wish_connection_mgr.h"
#include "wish_local_discovery.h"
#include "wish_time.h"

#include "utlist.h"


LOCAL os_timer_t test_timer;
ip_addr_t tcp_server_ip;



extern wish_context_t wish_context_pool[WISH_CONTEXT_POOL_SZ];

LOCAL void ICACHE_FLASH_ATTR user_tcp_recon_cb(void *arg, sint8 err);
static int ICACHE_FLASH_ATTR my_send_data(void *pespconn, unsigned char* data, int len);


/******************************************************************************
 * FunctionName : user_tcp_recv_cb
 * Description  : receive callback.
 * Parameters   : arg -- Additional argument to pass to the callback function
 * Returns      : none
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
user_tcp_recv_cb(void *arg, char *pusrdata, unsigned short length)
{
    struct espconn *espconn = arg;
    os_printf("IP: %d.%d.%d.%d\n\r", 
        espconn->proto.tcp->remote_ip[0],
        espconn->proto.tcp->remote_ip[1],
        espconn->proto.tcp->remote_ip[2],
        espconn->proto.tcp->remote_ip[3]);

    //received some data from tcp connection

    /* If we would have many concurrent connections, we would need to
     * first check from source ip, dst and src ports, to which wish_context
     * (which TCP connection) the data we just received pertains to. */
    wish_context_t* wish_handle 
        = wish_identify_context(espconn->proto.tcp->remote_ip,
            espconn->proto.tcp->remote_port, 
            espconn->proto.tcp->local_ip,
            espconn->proto.tcp->local_port);

    if (wish_handle == NULL) {
        return;
    }
    wish_core_feed(wish_handle, pusrdata, length);

    struct wish_event ev = { .event_type = WISH_EVENT_NEW_DATA, 
        .context = wish_handle };
    wish_message_processor_notify(&ev);

}


struct fifo_entry {
    char *data;
    int data_len;
    struct espconn *espconn;
    struct fifo_entry *next;
};

static struct fifo_entry *fifo_head = NULL;

static bool busy = false;

/* Error: TCP send function was called before the previous invocation's
 * callback was called. */
#define ESPCONN_SEND_BEFORE_CB (-1)


/******************************************************************************
 * FunctionName : user_tcp_sent_cb
 * Description  : data sent callback.
 * Parameters   : arg -- Additional argument to pass to the callback function
 * Returns      : none
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
user_tcp_sent_cb(void *arg)
{
    //data sent successfully

    //struct espconn *espconn = arg;

    if (fifo_head == NULL) {
        os_printf("fifo head is null, this is not possible!\n");
        return;
    }
    if (busy == false) {
        os_printf("Not busy, this is not possbile\n");
        return;
    }

    struct fifo_entry *e = fifo_head;   /* Cannot be NULL in this situation */
    LL_DELETE(fifo_head, e);

    os_free(e->data);
    os_free(e);

    int fifo_len = 0;
    LL_COUNT(fifo_head, e, fifo_len);
    
    if (fifo_len == 0) {
        /* No longer busy */
        busy = false;
        os_printf("Send FIFO is now empty!\n");
    }
    else {
        /* Continue with sending next buffer */
        espconn_send(fifo_head->espconn, fifo_head->data, fifo_head->data_len);
    }

}

/******************************************************************************
 * FunctionName : user_tcp_discon_cb
 * Description  : disconnect callback.
 * Parameters   : arg -- Additional argument to pass to the callback function
 * Returns      : none
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
user_tcp_discon_cb(void *arg)
{
    struct espconn *espconn = arg;

    os_free(espconn->proto.tcp);
    os_free(espconn);

    os_printf("Disconnect (outgoing) connection, IP: %d.%d.%d.%d\n\r", 
        espconn->proto.tcp->remote_ip[0],
        espconn->proto.tcp->remote_ip[1],
        espconn->proto.tcp->remote_ip[2],
        espconn->proto.tcp->remote_ip[3]);

    wish_context_t *ctx = espconn->reverse;
    if (ctx == NULL) {
        os_printf("Connection close: wish context not found!\n");
        return;
    }

    wish_core_signal_tcp_event(ctx, TCP_DISCONNECTED);
}

/******************************************************************************
 * FunctionName : user_tcp_server_discon_cb
 * Description  : disconnect callback, called when connection to the remote client has been disconnected.
 * Parameters   : arg -- Additional argument to pass to the callback function
 * Returns      : none
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
user_tcp_server_discon_cb(void *arg)
{
    //tcp disconnect successfully
    struct espconn *espconn = arg;
    os_printf("Disconnected (incoming) connection, IP: %d.%d.%d.%d\n\r", 
        espconn->proto.tcp->remote_ip[0],
        espconn->proto.tcp->remote_ip[1],
        espconn->proto.tcp->remote_ip[2],
        espconn->proto.tcp->remote_ip[3]);

    wish_context_t *ctx = espconn->reverse;
    if (ctx == NULL) {
        os_printf("Connection close: wish context not found!\n");
        return;
    }
    wish_core_signal_tcp_event(ctx, TCP_CLIENT_DISCONNECTED);
}

/******************************************************************************
 * FunctionName : user_tcp_server_connect_cb
 * Description  : A new incoming tcp connection has been connected.
 * Parameters   : arg -- Additional argument to pass to the callback function
 * Returns      : none
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
user_tcp_server_connect_cb(void *arg)
{
    struct espconn *pespconn = arg;
    uint8_t null_wuid[WISH_ID_LEN] = { 0 };
    wish_context_t* wish_handle = wish_core_start(null_wuid, null_wuid);
    if (wish_handle == NULL) {
        os_printf("We cannot accempt incoming connections right now\n");
        espconn_disconnect(pespconn);
        return;
    }
    /* Register the reverse so that we can later for example clean up
     * the context if/when the connection closes */
    pespconn->reverse = wish_handle;

    wish_core_register_send(wish_handle, my_send_data, arg);
    /* Populate Wish connection structure with IP info */
    memcpy(wish_handle->local_ip_addr, pespconn->proto.tcp->local_ip, 4);
    memcpy(wish_handle->rmt_ip_addr, pespconn->proto.tcp->remote_ip, 4);
    wish_handle->local_port = pespconn->proto.tcp->local_port;
    wish_handle->remote_port = pespconn->proto.tcp->remote_port;
 

    os_printf("incoming connect succeed (server)!!! \r\n");

    espconn_regist_recvcb(pespconn, user_tcp_recv_cb);
    espconn_regist_sentcb(pespconn, user_tcp_sent_cb);
    espconn_regist_disconcb(pespconn, user_tcp_server_discon_cb);
    wish_core_signal_tcp_event(wish_handle, TCP_CLIENT_CONNECTED);
    /* Set a 60 second inactivity timeout */
    espconn_regist_time(pespconn, 60, 1);
    /* Disable Nagle algorithm */
    if (espconn_set_opt(pespconn, ESPCONN_NODELAY) != 0) {
        os_printf("Error disabling Nagle algorithm (incoming connection)");
    }
}



/* Use this function the post data to be sent using TCP.
 *
 * Returns 0 if the data was queued, or ESPCONN_SEND_BEFORE_CB if you
 * attempted to send data before the send callback had activated */
static int ICACHE_FLASH_ATTR
my_send_data(void *pespconn, unsigned char* data, int len)
{
    struct espconn* espconn = (struct espconn*) pespconn;

    struct fifo_entry *e = (struct fifo_entry *) os_malloc(sizeof (struct fifo_entry));
    if (e == NULL) {
        os_printf("Out of memory when sending data!\n");
        return -1;
    }
    memset(e, 0, sizeof (struct fifo_entry));
    e->data = (char *) os_malloc(len);
    memcpy(e->data, data, len);
    e->data_len = len;
    e->espconn = espconn;

    LL_APPEND(fifo_head, e);

    if (busy) {
        os_printf("Send deferred!\n");
    }
    else {
        os_printf("Sending now!\n");
        espconn_send(espconn, data, len);
        busy = true;
    }

    return 0;
}


/******************************************************************************
 * FunctionName : user_tcp_connect_cb
 * Description  : A new incoming tcp connection has been connected.
 * Parameters   : arg -- Additional argument to pass to the callback function
 * Returns      : none
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
user_tcp_connect_cb(void *arg)
{
    struct espconn *pespconn = arg;

    os_printf("connect succeed !!! \r\n");

    espconn_regist_recvcb(pespconn, user_tcp_recv_cb);
    espconn_regist_sentcb(pespconn, user_tcp_sent_cb);
    espconn_regist_disconcb(pespconn, user_tcp_discon_cb);

    wish_context_t *wish_handle = (wish_context_t *) pespconn->reverse;

    wish_core_register_send(wish_handle, my_send_data, arg);
    /* Populate Wish connection structure with IP info */
    memcpy(wish_handle->local_ip_addr, pespconn->proto.tcp->local_ip, 4);
    memcpy(wish_handle->rmt_ip_addr, pespconn->proto.tcp->remote_ip, 4);
    wish_handle->local_port = pespconn->proto.tcp->local_port;
    wish_handle->remote_port = pespconn->proto.tcp->remote_port;
 
    if (wish_handle->via_relay) {
        /* For connections opened by relay client to accept an 
         * incoming connection */
        wish_core_signal_tcp_event(wish_handle, TCP_RELAY_SESSION_CONNECTED);
    }
    else {
        /* For connections opened normally */
        wish_core_signal_tcp_event(wish_handle, TCP_CONNECTED);
    }

    /* Disable Nagle algorithm */
    if (espconn_set_opt(pespconn, ESPCONN_NODELAY) != 0) {
        os_printf("Error disabling Nagle algorithm (outgoing connection)");
    }

}

/******************************************************************************
 * FunctionName : user_tcp_recon_cb
 * Description  : reconnect callback, error occured in TCP connection.
 * Parameters   : arg -- Additional argument to pass to the callback function
 * Returns      : none
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
user_tcp_recon_cb(void *arg, sint8 err)
{
    os_printf("reconnect callback, error code %d !!! \r\n", err);
    //error occured , tcp connection broke. user can try to reconnect here. 
    struct espconn *espconn = arg;
    os_printf("IP: %d.%d.%d.%d\n\r", 
        espconn->proto.tcp->remote_ip[0],
        espconn->proto.tcp->remote_ip[1],
        espconn->proto.tcp->remote_ip[2],
        espconn->proto.tcp->remote_ip[3]);
    wish_context_t* wish_handle 
        = wish_identify_context(espconn->proto.tcp->remote_ip,
            espconn->proto.tcp->remote_port, 
            espconn->proto.tcp->local_ip,
            espconn->proto.tcp->local_port);
    if (wish_handle == NULL) {
        return;
    }

    os_free(espconn->proto.tcp);
    os_free(espconn);
 

    wish_core_signal_tcp_event(wish_handle, TCP_DISCONNECTED);
}

/******************************************************************************
 * FunctionName : user_tcp_server_recon_cb
 * Description  : reconnect callback, error occured in TCP connection.
 * Parameters   : arg -- Additional argument to pass to the callback function
 * Returns      : none
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
user_tcp_server_recon_cb(void *arg, sint8 err)
{
    //error occured , tcp connection broke. user can try to reconnect here. 
    struct espconn *espconn = arg;
    os_printf("IP: %d.%d.%d.%d\n\r", 
        espconn->proto.tcp->remote_ip[0],
        espconn->proto.tcp->remote_ip[1],
        espconn->proto.tcp->remote_ip[2],
        espconn->proto.tcp->remote_ip[3]);


    os_printf("Server reconnect callback, error code %d !!! \r\n", err);
#if 0
    wish_core_signal_tcp_event(wish_handle, TCP_CLIENT_DISCONNECTED);
#endif
}



/*
 * Setup callbacks and initiate TCP connection to specified IP address.
 * The a copy is made of the ip address parameter.
 *
 * Retuns the value one of the values espconn_connect(). Note that in
 * case of badly initialised struct espconn, ESPCONN_ARG is returned 
 * before any other setup is performed.
 */
LOCAL sint8 user_connect_tcp(struct espconn* espconn, ip_addr_t* ipaddr, uint16_t port) {
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
    else if (ipaddr == 0) {
        err = ESPCONN_ARG;
    }
    else {
        /* struct espconn seems acceptable */

        os_memcpy(espconn->proto.tcp->remote_ip, ipaddr, 4);

        espconn->proto.tcp->remote_port = port;       // remote port

        espconn->proto.tcp->local_port = espconn_port();   //local port of ESP8266

        espconn_regist_connectcb(espconn, user_tcp_connect_cb);  // register connect callback
        espconn_regist_reconcb(espconn, user_tcp_recon_cb);      // register reconnect callback as error handler
        espconn_connect(espconn);
    }

    return err;
}

#ifdef DNS_ENABLE
/******************************************************************************
 * FunctionName : user_dns_found
 * Description  : dns found callback
 * Parameters   : name -- pointer to the name that was looked up.
 *                ipaddr -- pointer to an ip_addr_t containing the IP address of
 *                the hostname, or NULL if the name could not be found (or on any
 *                other error).
 *                callback_arg -- a user-specified callback argument passed to
 *                dns_gethostbyname
 * Returns      : none
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
user_dns_found(const char *name, ip_addr_t * ipaddr, void *arg)
{
    struct espconn *pespconn = (struct espconn *) arg;

    if (ipaddr == NULL) {
        os_printf("user_dns_found NULL \r\n");
        return;
    }

    //dns got ip
    os_printf("user_dns_found %d.%d.%d.%d \r\n",
              *((uint8 *) & ipaddr->addr), *((uint8 *) & ipaddr->addr + 1),
              *((uint8 *) & ipaddr->addr + 2),
              *((uint8 *) & ipaddr->addr + 3));

    if (tcp_server_ip.addr == 0 && ipaddr->addr != 0) {
        // dns succeed, create tcp connection
        os_timer_disarm(&test_timer);
        user_connect_tcp(pespconn, ipaddr);

    }
}

/******************************************************************************
 * FunctionName : user_esp_platform_dns_check_cb
 * Description  : 1s time callback to check dns found
 * Parameters   : arg -- Additional argument to pass to the callback function
 * Returns      : none
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
user_dns_check_cb(void *arg)
{
    struct espconn *pespconn = arg;

    espconn_gethostbyname(pespconn, TEST_HOSTNAME, &tcp_server_ip, user_dns_found);     // recall DNS function

    os_timer_arm(&test_timer, 1000, 0);
}


#endif

/******************************************************************************
 *
 * FunctionName : user_check_ip
 * Description  : check whether get ip addr or not
 * Parameters   : none
 * Returns      : none
*******************************************************************************/
void ICACHE_FLASH_ATTR
user_check_ip(void)
{
    os_printf(__func__);
    os_printf("\n\r");
    struct ip_info ipconfig;

    //disarm timer first
    os_timer_disarm(&test_timer);

    //get ip info of ESP8266 station
    wifi_get_ip_info(STATION_IF, &ipconfig);
    os_printf("wifi connect status = %d\n\r", 
        wifi_station_get_connect_status());
    if (wifi_station_get_connect_status() == STATION_GOT_IP
        && ipconfig.ip.addr != 0) {
        os_printf("got ip !!! \r\n");

        static bool server_started = false;
        if (!server_started) {
            /* Only start the server once */
            user_start_server();
            server_started = true;

#if 1
            /* Start broadcasting 'advertizements' for our identity */
            wish_ldiscover_enable_bcast();
#endif

#if 0
            /* Setup autodiscvoery UDP listening */
            wish_ldiscover_enable_recv();
#endif
            /* Only start the relay control connection once */
            user_start_relay_control();
       }


    }
    else {

        if ((wifi_station_get_connect_status() == STATION_WRONG_PASSWORD ||
             wifi_station_get_connect_status() == STATION_NO_AP_FOUND ||
             wifi_station_get_connect_status() == STATION_CONNECT_FAIL)) {
            os_printf("connect fail !!! \r\n");
        }
        else {

            //re-arm timer to check ip
            os_timer_setfn(&test_timer,
                           (os_timer_func_t *) user_check_ip, NULL);
            os_timer_arm(&test_timer, 100, 0);
        }
    }
}


void ICACHE_FLASH_ATTR user_tcp_setup_dhcp_check(void) {
    //set a timer to check whether got ip from router succeed or not.
    os_timer_disarm(&test_timer);
    os_timer_setfn(&test_timer, (os_timer_func_t *) user_check_ip, NULL);
    os_timer_arm(&test_timer, 100, 0);
}

/* TCP connection structures for the server */
struct espconn server_espconn;
esp_tcp server_esp_tcp;

/*
 * See http://bbs.espressif.com/viewtopic.php?f=31&t=763
 * for an extended server example */
void user_start_server(void) {

    server_espconn.proto.tcp = &server_esp_tcp;
    server_espconn.type = ESPCONN_TCP;
    server_espconn.state = ESPCONN_NONE;

    server_espconn.proto.tcp->local_port = wish_get_host_port();

    espconn_regist_connectcb(&server_espconn, user_tcp_server_connect_cb);  // register connect callback
    espconn_regist_reconcb(&server_espconn, user_tcp_server_recon_cb);      // register reconnect callback as error handler
    espconn_accept(&server_espconn); 
    espconn_tcp_set_max_con_allow(&server_espconn, 1);
}

void user_stop_server(void) {
    if (espconn_delete(&server_espconn)) {
        os_printf("Could not stop server correctly\n");
    }
}


int wish_open_connection(wish_context_t *ctx, wish_ip_addr_t *ip, uint16_t port, bool via_relay) {
    os_printf("Open connection\n\r");

    /* Allocate the espconn structure for client use. This will be
     * de-allocated in the client disconnect callback, or the
     * reconnect callback */
    struct espconn* espconn = (struct espconn*) os_malloc(sizeof(struct espconn));
    memset(espconn, 0, sizeof(struct espconn));
    esp_tcp* user_tcp = (esp_tcp*) os_malloc(sizeof(esp_tcp)); 
    memset(user_tcp, 0, sizeof(esp_tcp));
    espconn->proto.tcp = user_tcp;
    espconn->type = ESPCONN_TCP;
    espconn->state = ESPCONN_NONE;

    /* Save the Wish context in the 'reverse' pointer of the espconn
     * struct. This is especially reserved for user-specified stuff */
    espconn->reverse = (void *) ctx;

    ctx->via_relay = via_relay;

    /* Connect to a Wish system */
    ip_addr_t esp_tcp_server_ip;
    IP4_ADDR(&esp_tcp_server_ip, ip->addr[0], ip->addr[1], ip->addr[2], ip->addr[3]);

    user_connect_tcp(espconn, &esp_tcp_server_ip, port);


    return 0;
}


void wish_close_connection(wish_context_t *ctx) {
    if (ctx->context_state != WISH_CONTEXT_CLOSING) {
        ctx->context_state = WISH_CONTEXT_CLOSING;
        ctx->close_timestamp = wish_time_get_relative();
    }

    /* XXX Please note, that on ESP8266 we should *not* close a connection, if
     * we still have enqueued data in our send fifo (defined elsewhere
     * in this file). If we do that, we will block sending for ever,
     * because of the busy flag will never be cleared.
     *
     * In stead, we check busy flag, and if busy flag is true, we just
     * enqueue a request that this connection must be closed later */

    if (busy) {
        /* FIXME Actually, we should check that if and only if this ctx
         * has enqueued data, deferred closing is requested. If no
         * enqueued data exists, then we could close immediately. */


        if (wish_time_get_relative() > (ctx->close_timestamp + 5)) {
            /* We have postponed closing for too long. Now really close
             * connection */
            os_printf("Closing connection, even though enqueued data exits!\n");

           /* Delete the data fragements related to this connection
             * from the send fifo */
            struct fifo_entry *tmp;
            struct fifo_entry *e;
            LL_FOREACH_SAFE(fifo_head, e, tmp) {
                if (e->espconn->reverse == ctx) {
                    LL_DELETE(fifo_head, e);
                    os_free(e->data);
                    os_free(e);
                }
            }
            int fifo_len = 0;
            LL_COUNT(fifo_head, e, fifo_len);

            int8_t ret = espconn_disconnect(ctx->send_arg);
            if (ret != 0) {
                os_printf("Disconnect fail\n\r");
            }
 
            if (fifo_len == 0) {
                /* There is no enqueued data */
                busy = false;
            }
            else {
                /* There is queued data, continue sending */
                espconn_send(fifo_head->espconn, fifo_head->data, fifo_head->data_len);
            }
        }
        else {
            //os_printf("Not closing connection, enqueued data exits!\n");
            struct wish_event new_evt = {
                .event_type = WISH_EVENT_REQUEST_CONNECTION_CLOSING,
                .context = ctx,
            };
            wish_message_processor_notify(&new_evt);
        }

        return;
    }

    if (ctx->send_arg != NULL) {
        os_printf("Explicit connection disconnect\n\r");
        int8_t ret = espconn_disconnect(ctx->send_arg);
        if (ret != 0) {
            os_printf("Disconnect fail\n\r");
        }
    }
    else {
        /* espconn is null. Perhaps this occurs because the connection was never properly
         * started? */
        os_printf("Skipping espconn disconnect espconn struct is null.");
        /* The connection is not really opened anyway, so it should be safe to just discard the connection. */
        wish_core_signal_tcp_event(ctx, TCP_DISCONNECTED);
    }
}

int wish_get_host_ip_str(char* addr_str, size_t addr_str_len) {
    if (addr_str_len < 4*3+3+1) {
        os_printf("IP addr buffer too small\n\r");
    }
    struct ip_info info;

    if (user_wifi_get_mode() == USER_WIFI_MODE_SETUP) {
        wifi_get_ip_info(0x01, &info);  /* Get for softAP interface */
    }
    else {
        wifi_get_ip_info(0x00, &info);  /* Get for station interface */
    }
    os_sprintf(addr_str, IPSTR, IP2STR(&info.ip));
    return 0;


}


int wish_get_host_port(void) {
    return 37008;
}
