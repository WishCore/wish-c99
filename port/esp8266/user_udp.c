/* 
 * ESP8266 UDP functions, (mostly) related to the Wish local discovery
 * system 
 */

#include <stddef.h>
#include <string.h>

#include "c_types.h"
#include "ip_addr.h"
#include "espconn.h"
#include "espmissingincludes.h"
#include "mem.h"
#include "user_interface.h"
#include "osapi.h"

#include "wish_io.h"
#include "wish_connection_mgr.h"
#include "wish_debug.h"
#include "wish_local_discovery.h"
#include "wish_identity.h"

#include "user_wifi.h"

#define LOCAL_DISCOVERY_BCAST_PORT 9090
#define LOCAL_DISCOVERY_BCAST_INTERVAL (5*1000)    /* Milliseconds */

/* NB: udp_client_espconn and udp_server_epconn could be the same
 * struct! This could save memory. */
struct espconn *udp_client_espconn = NULL;
esp_udp *udp_client_info = NULL;

/* Timer for sending out local discovery 'adverts' */
os_timer_t bcast_timer;


/* Local discovery 'advert' timer expired call-back function. This sends
 * out one advertizement for the node's identity. */
static void bcast_timeout_cb(void *arg) {
    /* Send autodiscovery UDP bcast */
    /* FIXME find a better place for these inits */
    /* FIXME this uses suspicously much memory! */
    wish_uid_list_elem_t uid_list[4];
    memset(uid_list, 0, sizeof (uid_list));

    int num_ids = wish_load_uid_list(uid_list, 1);
    //os_printf("Loaded %d wuids from db\n\r", num_ids);
    if (num_ids > 0) {
        wish_ldiscover_advertize(uid_list[0].uid);
    }
    else {
        os_printf("Error! Loaded %d wuids from db\n\r", num_ids);
    }
}

static void udp_client_sent_cb(void *arg) {
    WISHDEBUG(LOG_DEBUG, "UDP sent cb\n\r");
}


/* Start advertizing using local discovery messages */
void wish_ldiscover_enable_bcast(void) {
    udp_client_espconn = (struct espconn *)os_malloc(sizeof(struct espconn));
    udp_client_info = (esp_udp *) os_malloc(sizeof(esp_udp));
    if (udp_client_espconn == NULL || udp_client_info == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Out of memory?");
        return;
    }
    memset(udp_client_espconn, 0, sizeof(struct espconn));
    memset(udp_client_info, 0, sizeof(esp_udp));

    udp_client_info->remote_ip[0] = 255;
    udp_client_info->remote_ip[1] = 255;
    udp_client_info->remote_ip[2] = 255;
    udp_client_info->remote_ip[3] = 255;
    udp_client_info->local_port = espconn_port();
    udp_client_info->remote_port = LOCAL_DISCOVERY_BCAST_PORT;

    udp_client_espconn->proto.udp = udp_client_info;

    udp_client_espconn->type = ESPCONN_UDP;
    udp_client_espconn->state = ESPCONN_NONE;

    int ret = espconn_create(udp_client_espconn);
    if (ret != 0) {
        /* non zero return, error */
        WISHDEBUG(LOG_CRITICAL, "UDP create error (bcast) %d", ret);
        return;
    }
    espconn_regist_sentcb(udp_client_espconn, udp_client_sent_cb);

    /* Set broadcast interfacace to station+soft-ap */
    uint8_t bcast_if = 1;   /* uint8 interface : 1:station; 2:soft-AP,
    3:station+soft-AP */

    if (user_wifi_get_mode() == USER_WIFI_MODE_SETUP) {
        bcast_if = 2;
    }
    else {
        bcast_if = 1;
    }

    if (!wifi_set_broadcast_if(bcast_if)) {
        WISHDEBUG(LOG_CRITICAL, "Could not set UDP bcast if to %d", bcast_if);
        //return -1;
    }



    os_timer_setfn(&bcast_timer, (os_timer_func_t*) bcast_timeout_cb, NULL);
    os_timer_arm(&bcast_timer, LOCAL_DISCOVERY_BCAST_INTERVAL, true);
}

/* Stop advertizing using local discovery messages */
void wish_ldiscover_disable_bcast(void) {
    os_timer_disarm(&bcast_timer);
    int ret = espconn_delete(udp_client_espconn);
    if (ret != 0) {
        WISHDEBUG(LOG_CRITICAL, "UDP clean up fail %d", ret );
    }


    os_free(udp_client_espconn);
    os_free(udp_client_info);
    udp_client_espconn = NULL;
    udp_client_info = NULL;

}



int wish_send_advertizement(uint8_t *ad_msg, size_t ad_len) {
    int ret = espconn_sendto(udp_client_espconn, ad_msg, ad_len);
    if (ret != 0) {
        WISHDEBUG(LOG_CRITICAL, "UDP sendto fail %d", ret );
        return -1;
    }

    return 0;
}


static void udp_server_recv_cb(void *arg, char *pdata, unsigned short len) {
    WISHDEBUG(LOG_CRITICAL, "UDP receive %d bytes\n\r", len);
    struct espconn *espconn = (struct espconn*) arg;

    remot_info *r_info = NULL;
    if (espconn_get_connection_info(espconn, &r_info, 0)) {
        os_printf("Error espconn_get_connection_info\n\r");

    }
    wish_ip_addr_t ip;
    memcpy(&ip, r_info->remote_ip, 4);
    wish_ldiscover_feed(&ip, r_info->remote_port, pdata, len);


}

struct espconn *udp_server_espconn = NULL;
esp_udp *udp_server_conn_info = NULL;



/* Start accepting local discovery messages */
void wish_ldiscover_enable_recv(void) {
    udp_server_espconn = (struct espconn *)os_malloc(sizeof(struct espconn));
    udp_server_conn_info = (esp_udp *) os_malloc(sizeof(esp_udp));
    if (udp_server_conn_info == NULL || udp_server_espconn == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Out of memory!");
        return;
    }

    udp_server_espconn->proto.udp = udp_server_conn_info;

    udp_server_espconn->type = ESPCONN_UDP;
    udp_server_espconn->state = ESPCONN_NONE;

    udp_server_conn_info->local_port = LOCAL_DISCOVERY_BCAST_PORT;

    udp_server_espconn->proto.udp = udp_server_conn_info;

    udp_server_espconn->type = ESPCONN_UDP;
    udp_server_espconn->state = ESPCONN_NONE;

    int ret = espconn_create(udp_server_espconn);
    if (ret != 0) {
        /* non zero return, error */
        WISHDEBUG(LOG_CRITICAL, "UDP create error %d (when listening)", ret);
        return;
    }
    espconn_regist_recvcb(udp_server_espconn, udp_server_recv_cb);

}

/* Stop accepting local discovery messages */
void wish_ldiscover_disable_recv(void) {
    int ret = espconn_delete(udp_server_espconn);
    if (ret != 0) {
        /* non zero return, error */
        WISHDEBUG(LOG_CRITICAL, "UDP delete error %d (when listening)", ret);
    }
    os_free(udp_server_conn_info);
    os_free(udp_server_espconn);
}


