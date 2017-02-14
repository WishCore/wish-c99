/* C lib and other "standard" includes */
#include <stdint.h>
#include <string.h>

/* ESP8266 SDK includes */
#include "ets_sys.h"
#include "osapi.h"
#include "gpio.h"
#include "user_interface.h"
#include "mem.h"
#include "osapi.h"
#include "espmissingincludes.h"


/* Wish & Mist includes */
#include "mist_app.h"
#include "mist_model.h"
#include "mist_model.h"
#include "mist_handler.h"
#include "wish_debug.h"
#include "bson.h"
#include "wish_io.h"
#include "wish_connection_mgr.h"
#include "wish_local_discovery.h"
#include "bson_visitor.h"

/* Mist app includes */
#include "mist_config.h"

/* App includes which are ESP8266 specific */
#include "user_wifi.h"
#include "user_tcp.h"
#include "user_support.h"

static mist_app_t* mist_app;
static os_timer_t reboot_timer;

static void reboot_timer_cb(void) {
    user_reboot();
}

/** Endpoint name for MistCommissioning device (type) */
#define MIST_TYPE_EP "mistType"
/** Endpoint name for MistCommissioning device (version) */
#define MIST_VERSION_EP "mistVersion"
/** Endpoint name for MistCommissioning device (Endpoint for listing
 * wifi) */
#define MIST_WIFI_LIST_AVAILABLE_EP "mistWifiListAvailable"
/** Endpoint name for MistCommissioning device (Configuration endpoint) */
#define MIST_WIFI_COMMISSIONING_EP "mistWifiCommissioning"

static enum mist_error wifi_write(mist_ep* ep, void* value) {
    WISHDEBUG(LOG_CRITICAL, "in wifi_write");
    return MIST_NO_ERROR;
}

static enum mist_error wifi_read(mist_ep* ep, void* result) {
    WISHDEBUG(LOG_CRITICAL, "in wifi_read");
    if (strcmp(ep->id, MIST_TYPE_EP) == 0) {
        memcpy(result, "WifiCommissioning", MIST_STRING_EP_MAX_LEN);
    }
    else if (strcmp(ep->id, MIST_VERSION_EP) == 0) {
        memcpy(result, "1.0.1", MIST_STRING_EP_MAX_LEN);
    }

    return MIST_NO_ERROR;
}

/* See here what the Invoke should return
 * https://gist.github.com/akaustel/1f7efeb791d156ea98099fe7b6e63ae7
 *
 * To connect the ESP8266 to a wifi network, invoke endpoint 
 * mistWifiCommissioning with this argument:
 *
 * { "wifi_Credentials":"password", "ssid":"ssid-name" }
 *
 * For example for our office network:
 * { "wifi_Credentials":"19025995", "ssid":"Buffalo-G-12DA" }
 * In Mist UI, remember to check "JSON" checkbox! 
 *
 */
static enum mist_error wifi_invoke(mist_ep* ep, mist_buf args) {
    /* The stuff that comes in to this function in args.base has following structure: 
     
        epid: 'mistWifiCommissioning'           <---- added by handle_control_model on local side
        id: 8                                   <---- idem  
        args: {                                 <---- this is arguments from remote side
            ssid: 'Buffalo-G-12DA'
            wifi_Credentials: '19025995'
        }

     */
   
    char *ep_id = ep->id;
    int32_t result_max_len = WISH_PORT_RPC_BUFFER_SZ;
    uint8_t result[result_max_len];
 
    WISHDEBUG(LOG_CRITICAL, "in wifi_invoke ep: %s %p", ep_id, args.base);
    
    bson_visit(args.base, elem_visitor);
    int32_t rpc_id = 0;
    bson_iterator it;
    bson_find_from_buffer(&it, args.base, "id");
     
    if (bson_iterator_type(&it) == BSON_INT) {
        rpc_id = bson_iterator_int(&it);
    } else {
        WISHDEBUG(LOG_CRITICAL, "Cannot get invoke RPC id");
        return MIST_ERROR;
    }
    WISHDEBUG(LOG_DEBUG, "Control.invoke rpc %d", rpc_id);
    
    bson bs;
    bson_init_buffer(&bs, result, result_max_len);
    char ** ssid_str_ptrs = user_wifi_get_ssids();
    int8_t *ssid_rssis = user_wifi_get_rssis();
    if (strcmp(ep_id, MIST_WIFI_LIST_AVAILABLE_EP) == 0) {
        bson_append_start_object(&bs, "data");
        int i = 0;
        for (i = 0; i < MAX_NUM_SSIDS; i++) {
            if (ssid_str_ptrs[i] == NULL) {
                continue;
            }
            
            /* FIXME terrible array index hack */
            char arr_index[2];
            arr_index[0] = '0'+i;
            arr_index[1] = 0;
            WISHDEBUG(LOG_DEBUG, "encoding %s %d", ssid_str_ptrs[i], ssid_rssis[i]);
            bson_append_start_object(&bs, arr_index);
            bson_append_string(&bs, "ssid", ssid_str_ptrs[i]);
            bson_append_int(&bs, "rssi", ssid_rssis[i]);
            bson_append_finish_object(&bs);
            if (bs.err) {
                WISHDEBUG(LOG_CRITICAL, "BSON error while adding ssid/rssi");
                return MIST_ERROR;
            }
        }
        WISHDEBUG(LOG_DEBUG, "finished appending");
        bson_append_finish_object(&bs);
        bson_finish(&bs);
        if (bs.err) {
            WISHDEBUG(LOG_CRITICAL, "There was an BSON error");
            return MIST_ERROR;
        } else {
            /* Send away the control.invoke response */
            mist_invoke_response(&(mist_app->device_rpc_server), rpc_id, (uint8_t*) bson_data(&bs));
        }
    }
    else if (strcmp(ep_id, MIST_WIFI_COMMISSIONING_EP) == 0) {
        char* ssid = NULL;
        char* password = NULL;
        
        bson_find_from_buffer(&it, args.base, "args");
        bson_iterator sit;
        bson_iterator_subiterator(&it, &sit);
        bson_find_fieldpath_value("wifi_Credentials", &sit);
        if (bson_iterator_type(&sit) == BSON_STRING) {
            password = (char *) bson_iterator_string(&sit);
        } else {
            WISHDEBUG(LOG_CRITICAL, "element wifi_Credentials is missing or not a string");
            return MIST_ERROR;
        }
         /* Sub-iterator must be re-set in order to guarantee that the order in which we take out the elems do not depend on the order of elems in 'args' document! */
        bson_iterator_subiterator(&it, &sit);
        bson_find_fieldpath_value("ssid", &sit);
        if (bson_iterator_type(&sit) == BSON_STRING) {
            ssid = (char *) bson_iterator_string(&sit);
        } else {
            WISHDEBUG(LOG_CRITICAL, "element ssid is missing or not a string");
            return MIST_ERROR;
        }
        
        
        WISHDEBUG(LOG_CRITICAL, "Will switch to SSID: %s password %s", ssid, password);
        
        bson_finish(&bs);
        if (bs.err) {
            WISHDEBUG(LOG_CRITICAL, "There was an BSON error");
            return MIST_ERROR;
        } else {
            /* Send away the control.invoke response */
            mist_invoke_response(&(mist_app->device_rpc_server), rpc_id, (uint8_t*) bson_data(&bs));
        }
        
        /* Stop broadcasting local discovery messages */
        wish_close_all_connections();
        user_stop_server();
        wish_ldiscover_disable_bcast();
        /* The Wish server and Wish local discovery should be started
         * automatically when we detect we have obtained IP */
        user_wifi_set_station_mode();
        user_set_station_config(ssid, password);
        /* FIXME Find a way to make connections work *without* needing a
         * reboot */

        /* Schedule a reboot via timer. This is because we would like to
         * give the TCP stack possibility to send the "ack" message of
         * this invoke function */
        os_timer_disarm(&reboot_timer);
        os_timer_setfn(&reboot_timer, (os_timer_func_t *) reboot_timer_cb, NULL);
        os_timer_arm(&reboot_timer, 1000, 0);
    }

    WISHDEBUG(LOG_DEBUG, "Exiting");
    return MIST_NO_ERROR;
}



void mist_config_init(void) {
    WISHDEBUG(LOG_CRITICAL, "entering config init");
    char *name = "MistConfig";
    wish_app_t *app;
    mist_app = start_mist_app();
    if (mist_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Failed creating wish app");
        return;
    }

    WISHDEBUG(LOG_CRITICAL, "here");
    mist_set_name(mist_app, name);
    WISHDEBUG(LOG_CRITICAL, "here2");
    app = wish_app_create(name);

   if (app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Failed creating wish app");
        return; 
    }
    WISHDEBUG(LOG_CRITICAL, "here3");
    wish_app_add_protocol(app, &(mist_app->ucp_handler));
    mist_app->app = app;
    WISHDEBUG(LOG_CRITICAL, "About to login");
    wish_app_login(app);
    WISHDEBUG(LOG_CRITICAL, "Adding EPs");
    mist_add_endpoint(&(mist_app->model), MIST_TYPE_EP, MIST_TYPE_EP, MIST_TYPE_STRING, "", wifi_read, NULL, NULL);
    mist_add_endpoint(&(mist_app->model), MIST_VERSION_EP, MIST_VERSION_EP, MIST_TYPE_STRING, "", wifi_read, NULL, NULL);
    mist_add_endpoint(&(mist_app->model), MIST_WIFI_LIST_AVAILABLE_EP, MIST_WIFI_LIST_AVAILABLE_EP, MIST_TYPE_INVOKE, "", wifi_read, wifi_write, wifi_invoke);
    mist_add_endpoint(&(mist_app->model), MIST_WIFI_COMMISSIONING_EP, MIST_WIFI_COMMISSIONING_EP, MIST_TYPE_INVOKE, "", wifi_read, wifi_write, wifi_invoke);
    WISHDEBUG(LOG_CRITICAL, "exiting config init"); 
}
