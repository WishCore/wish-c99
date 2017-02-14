/*
 * ESP8266 as TCP client
 *
 * Example program presented in forum post:
 * http://bbs.espressif.com/viewtopic.php?f=21&t=232
 *
 * Original presentation:
 *
 * Sample code below is based on ESP8266 SDK without OS.
 *
 * 1. Start from user_init
 * 2. Connect to router
 * 3. Connect to cn.bing.com as example
 * 4. Send some HTTP packet..
 */
#include "ets_sys.h"
#include "osapi.h"
#include "gpio.h"
#include "os_type.h"
#include "user_task.h"
#include <stdio.h>

#include "driver/uart.h"

#include "c_types.h"
#include "ip_addr.h"
#include "espconn.h"
#include "mem.h"
#include "user_interface.h"
#include "espmissingincludes.h"

#include "wish_io.h"
#include "wish_dispatcher.h"

#include "user_wifi.h"
#include "user_tcp_client.h"
#include "user_relay.h"

#include "wish_event.h"
#include "mist_follow.h"
#include "mist_app.h"
#include "wish_platform.h"
#include "mbedtls/platform.h"

#include "spiffs_integration.h"
#include "wish_fs.h"
#include "wish_identity.h"
#include "wish_time.h"

#include "mist_model.h"
#include "mist_app.h"

#include "user_hw_config.h"
#include "user_support.h"

#ifdef OLIMEX_HARDWARE
#include "mist_esp8266_evb_app.h"
#else
#ifdef SONOFF_HARDWARE
#include "mist_esp8266_sonoff_app.h"
#else
#error no hardware defined
#endif
#endif
#include "mist_config.h"

/* Call-back functoin to the meminfo timer to periodically print memory
 * statistics */
static void ICACHE_FLASH_ATTR user_print_meminfo(void) {
    os_printf("\t*** Free heap size %d\n\r", system_get_free_heap_size());
    os_printf("\t*** Current amount of untouched stack: %d \n\r", user_find_stack_canary());
}

/* A wrapper to "calloc" function, which will be used by mbedtls. The
 * wrapper is needed because the platform-supplied os_calloc is a macro
 * expanding to a function call with incompatible signature */
static void* my_calloc(size_t n_members, size_t size) {
    void* ptr = (void*) os_malloc(n_members*size);
    os_memset(ptr, 0, n_members*size);
    return ptr;
}

static void* my_malloc(size_t size) {
    return (void*) os_malloc(size);
}

static void* my_realloc(void *ptr, size_t size) {
    return (void*) os_realloc(ptr, size);
}

/* A wrapper to "free" function, which will be used by mbedtls. */
static void  my_free(void* ptr) {
    os_free(ptr);
}


LOCAL os_timer_t systick_timer;

void ICACHE_FLASH_ATTR systick_timer_cb(void) {
    /* Report to Wish that one second has passed */
    wish_time_report_periodic();

    static wish_time_t timestamp;
    wish_time_t now = wish_time_get_relative();
    if (now >= (timestamp + 60)) {
        timestamp = now;
        os_printf("\t***\n\r");
        os_printf("\t*** System uptime %d minutes secs \n\r", now/60);
        user_print_meminfo();
        os_printf("\t***\n\r");
    }
}

/******************************************************************************
 * FunctionName : user_init
 * Description  : entry of user application, init user function here
 * Parameters   : none
 * Returns      : none
*******************************************************************************/
void user_init(void)
{
    user_paint_stack();
    uart_init(BIT_RATE_115200, BIT_RATE_115200);
    system_print_meminfo();
    os_printf("SDK version:%s\n", system_get_sdk_version());
    user_print_meminfo();

    /* Setup system tick timer which supplies timebase to Wish */
    os_timer_disarm(&systick_timer);
    os_timer_setfn(&systick_timer, (os_timer_func_t *) systick_timer_cb, NULL);
    os_timer_arm(&systick_timer, 1000, 1);

    os_printf("Some randomnedd: ADC reading is %d\n\r", system_adc_read());
    os_printf("VDD33 reading is %d\n\r", system_get_vdd33());

    mbedtls_platform_set_calloc_free(my_calloc, my_free);

    wish_platform_set_malloc(my_malloc);
    wish_platform_set_realloc(my_realloc);
    wish_platform_set_free(my_free);
    wish_platform_set_rng((long int (*)(void))os_random);

    wish_fs_set_open(my_fs_open);
    wish_fs_set_read(my_fs_read);
    wish_fs_set_write(my_fs_write);
    wish_fs_set_lseek(my_fs_lseek);
    wish_fs_set_close(my_fs_close);
    wish_fs_set_rename(my_fs_rename);
    wish_fs_set_remove(my_fs_remove);

    my_spiffs_mount();
    //test_spiffs();
    wish_uid_list_elem_t uid_list[4];
    memset(uid_list, 0, sizeof (uid_list));

    int num_ids = wish_load_uid_list(uid_list, 4);
    os_printf("Number of identities in db: %d\n", num_ids);

    int i = 0;
    for (i = 0; i < num_ids; i++) {
        wish_identity_t recovered_id;
        memset(&recovered_id, 0, sizeof (wish_identity_t));
        wish_load_identity(uid_list[i].uid, &recovered_id);
        os_printf("Loaded identity, alias: %s\n", recovered_id.alias);
    }

    if (num_ids <= 0) {
        os_printf("Creating new identity.\n");
        /* Create new identity */
        wish_identity_t id;
        wish_create_local_identity(&id, "Mr. Sonoff");
        wish_save_identity_entry(&id);
    }

    wish_core_init();

#ifdef OLIMEX_HARDWARE
    mist_esp8266_evb_app_init();
#else
#ifdef SONOFF_HARDWARE
    mist_esp8266_sonoff_app_init();
#endif
#endif

    wish_message_processor_init();
    mist_follow_task_init();

    /* Configure the relay GPIO */
    // Initialize the GPIO subsystem.
    gpio_init();


    user_setup_wifi();


}

uint32 user_rf_cal_sector_set(void) {
    /* RF_CAL_SEC_ADDR defined in Makefile as flash address, we need to
     * shift 3 bytes out of the address to get sector number */
    return RF_CAL_SEC_ADDR >> 24;
}

void uart0_rx_intr_handler(void *para) {

}

