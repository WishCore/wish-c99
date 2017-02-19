
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

#include "user_tcp.h"
#include "user_wifi.h"
#include "espmissingincludes.h"
#include "user_tcp_client.h"

#include "mist_follow.h"
#include "mist_app.h"
#include "bson.h"

#include "wish_io.h"
#include "wish_connection_mgr.h"
#include "wish_local_discovery.h"

#include "user_support.h"

#include "mist_config.h"

static enum user_wifi_mode user_wifi_mode;

enum user_wifi_mode user_wifi_get_mode(void) {
    return user_wifi_mode;
}

/******************************************************************************
 * FunctionName : user_set_station_config
 * Description  : set the router info which ESP8266 station will connect to 
 * Parameters   : none
 * Returns      : none
*******************************************************************************/
void ICACHE_FLASH_ATTR user_set_station_config(char *ssid, char *password) {
    struct station_config stationConf;

    os_memset(stationConf.ssid, 0, 32);
    os_memset(stationConf.password, 0, 64);

    //need not mac address
    stationConf.bssid_set = 0;

    //Set ap settings 
    size_t ssid_len = strnlen(ssid, 32);
    size_t password_len = strnlen(password, 64);
    os_memcpy(&stationConf.ssid, ssid, ssid_len);
    os_memcpy(&stationConf.password, password, password_len);
    wifi_station_set_config(&stationConf);

    /* Setup a timer to periodically check if DHCP has completed */
    user_tcp_setup_dhcp_check();
    wifi_station_set_reconnect_policy(true);
}


/** This array holds pointers to heap-allocated SSID strings. Updated
 * after every AP scan */
static char *ssid_str_ptrs[MAX_NUM_SSIDS];

char ** user_wifi_get_ssids(void) {
    return ssid_str_ptrs;
}

static int8_t ssid_rssis[MAX_NUM_SSIDS];

int8_t *user_wifi_get_rssis(void) {
    return ssid_rssis;
}


static os_timer_t reboot_timer;


static void reboot_timer_cb(void) {
    user_reboot();
}

void user_wifi_schedule_reboot(void) {
        os_timer_disarm(&reboot_timer);
        os_timer_setfn(&reboot_timer, (os_timer_func_t *) reboot_timer_cb, NULL);
        os_timer_arm(&reboot_timer, 1000, 0);
}


/** This callback is called by the system when the system is ready -
 * In this function we can call things that you cannot call in
 * user_init() */
void system_init_ready_cb(void) {
    user_wifi_setup_ap_scan();
}

void wifi_event_cb(System_Event_t *evt) {
    os_printf("Wifi event %d\n", evt->event);

}




void user_setup_wifi(void) {
    /* 
     * 1) Determine if we have a useful configuration in flash, 
     * or if we should start in "config mode" (as AP)
     *
     * 2) If we have useful configuration, use the configuration. Don't
     * start the scanning part.
     * 2b) If no useful configuration, start in STA mode, and setup the
     * scanning
     *
     */


    wifi_set_event_handler_cb(wifi_event_cb);

    struct station_config station_conf;
    wifi_station_get_config_default(&station_conf);

    int saved_ssid_len = strnlen(station_conf.ssid, 32);
    if (saved_ssid_len > 0) {
        os_printf("There is a saved WLAN STA config");
        /* Set station mode */
        wifi_set_opmode(STATION_MODE);
        wifi_station_set_reconnect_policy(true);
        user_wifi_mode = USER_WIFI_MODE_STATION;
        /* The system will autoconnect, no action necessary */
        /* set a timer to check whether got ip from router succeed or not. */
        user_tcp_setup_dhcp_check();
   }
    else {
        os_printf("There is no saved WLAN STA config");
        wifi_station_set_reconnect_policy(false);
        wifi_set_opmode_current(STATION_MODE);
        user_wifi_mode = USER_WIFI_MODE_SETUP;
        /* Register a callback to be invoked when the system initialisation
         * is done */
        system_init_done_cb(system_init_ready_cb);

        /* After this, the story continues in rf_init_done_cb */
        /* FIXME move rf_init_done_cb to this file and register it here
         * */
    }
}

void user_wifi_start_ap(void) {
    char ssid[SSID_NAME_MAX_LEN];
    memset(ssid, 0, SSID_NAME_MAX_LEN);

    struct softap_config softap_config;
    memset(&softap_config, 0, sizeof (struct softap_config));

    /* Write SSID prefix */
    int ssid_prefix_len = strnlen(MIST_CONFIG_SOFTAP_SSID_PREFIX, SSID_NAME_MAX_LEN);
    strncpy(ssid, MIST_CONFIG_SOFTAP_SSID_PREFIX, ssid_prefix_len);
    /* Write the customer specified string */
    int ssid_customer_str_len = strnlen(MIST_CONFIG_SSID_CUSTOMER_STRING,
        MIST_CONFIG_SSID_CUSTOMER_STRING_MAX_LEN);
    strncpy(ssid + ssid_prefix_len,
        MIST_CONFIG_SSID_CUSTOMER_STRING, ssid_customer_str_len);

    /* Write mac addr */
    uint8_t ap_mac_addr[6] = { 0 };
    if (wifi_get_macaddr(SOFTAP_IF, ap_mac_addr) == false) {
        os_printf("Failed to get mac addr");
    }
    os_sprintf(ssid + ssid_prefix_len + ssid_customer_str_len,
        "%02x%02x%02x", ap_mac_addr[3], ap_mac_addr[4], ap_mac_addr[5]);
    
    int ssid_len = strnlen(ssid, SSID_NAME_MAX_LEN);
    ssid[SSID_NAME_MAX_LEN-1]=0;    /* Ensure null termination in any
    case */
    os_printf("SSID is %s", ssid);
    strncpy((char *)&softap_config.ssid, ssid, ssid_len);
    softap_config.ssid_len = ssid_len;
    softap_config.channel = MIST_CONFIG_SOFTAP_CH;
    softap_config.authmode = AUTH_OPEN;
    softap_config.max_connection = 1; /* 4 is max */
    softap_config.beacon_interval = 100;    /* This should be default */

    wifi_set_opmode_current(SOFTAP_MODE);
    wifi_softap_set_config(&softap_config);
    if (!wifi_set_broadcast_if(2)) {
        WISHDEBUG(LOG_CRITICAL, "Could not set UDP bcast if to softap");
    }

    user_start_server();
    wish_ldiscover_enable_bcast();
}



static void start_ap_timer_cb(void) {
    user_wifi_start_ap();
}

static os_timer_t start_ap_timer;

/** This function will setupt a MistConfig Mist device for Wifi
 *
 * commissioning purposes */
void user_wifi_setup_commissioning(void) {
    mist_config_init();

    os_timer_disarm(&start_ap_timer);
    os_timer_setfn(&start_ap_timer, (os_timer_func_t *) start_ap_timer_cb, NULL);
    os_timer_arm(&start_ap_timer, 1000, 0);

}





void ap_scan_done_cb(void *arg, STATUS status) {
    if (status == OK) {
        struct bss_info *bss_link = (struct bss_info *) arg;
        /* First, de-allocate the existing SSID strings we have cached */
        int i = 0;
        for (i = 0; i < MAX_NUM_SSIDS; i++) {
            if (ssid_str_ptrs[i] != NULL) {
                os_free(ssid_str_ptrs[i]);
                ssid_str_ptrs[i] = NULL;
            }
        }
        i = 0;
        /* FIXME Here there is a risk that MAX_NUM_SSIDS is too small
         * and our favourite SSID can never be seen! */
        while (bss_link != NULL && i < MAX_NUM_SSIDS) {
            char ssid_name[SSID_NAME_MAX_LEN + 1];
            memset(ssid_name, 0, SSID_NAME_MAX_LEN + 1);
            memcpy(ssid_name, bss_link->ssid, 32);
            int ssid_len = strnlen(ssid_name, SSID_NAME_MAX_LEN);
            ssid_str_ptrs[i] = os_malloc(ssid_len + 1);
            memset(ssid_str_ptrs[i], 0, ssid_len + 1);
            memcpy(ssid_str_ptrs[i], ssid_name, ssid_len);
            os_printf(ssid_str_ptrs[i]);
            os_printf("\n");
            ssid_rssis[i] = bss_link->rssi;

            /* Advance to next record */
            bss_link = bss_link->next.stqe_next;
            i++;
        }
    }
    else {
        os_printf("AP scan: Status not OK, what does that mean?");
    }
    if (user_wifi_get_mode() == USER_WIFI_MODE_SETUP) {
        user_wifi_setup_commissioning();
    }
    else {
        os_printf("Nothing to do, just idling?");
    }
}

void user_wifi_setup_ap_scan(void) {
    wifi_station_scan(NULL, ap_scan_done_cb);

}

void user_wifi_set_station_mode(void) {
    user_wifi_mode = USER_WIFI_MODE_STATION;
    wifi_set_opmode(STATION_MODE);
}

