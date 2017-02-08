#include <string.h>

#include "ets_sys.h"
#include "osapi.h"
#include "gpio.h"
#include "user_interface.h"
#include "mem.h"
#include "osapi.h"
#include "espmissingincludes.h"

#include "mist_app.h"
#include "mist_model.h"
#include "mist_model.h"
#include "wish_debug.h"

#include "user_task.h"

mist_app_t *mist_app;

static bool relay_state = false;

static void user_actuate_relay(bool new_state) {
    os_printf("Actuating relay\n\r");
    relay_state = new_state;
    if (relay_state) {
        gpio_output_set(BIT5, 0, BIT5, 0);
    }
    else {
        gpio_output_set(0, BIT5, BIT5, 0);
    }
}

static int user_get_relay_state() {
    return relay_state;
}

#include "ntc10_lookup.h"

static int user_get_temperature() {
    return ntc10_lookup[system_adc_read()];
}

/* This variable is incremented every time the button is pressed */
static volatile bool button_state;
static volatile int btn_event_time = 0;
static volatile bool btn_handled = false;
static volatile int curr_time = 0;

LOCAL os_timer_t button_timer;

static void button_timer_cb(void) {
    /* Detect a long press on the button */
    curr_time++;

    static bool old_state;
    if (curr_time > btn_event_time + 10 && !btn_handled) {
        if (button_state == true) {
            os_printf("Button was held down for 10 secs\n");
            btn_handled = true;
            old_state = user_get_relay_state();
            wish_identity_delete_db();
            system_restore();
        }
    }

    /* When we have detected a long press, toggle relay once then reboot */
    static int cnt;
    if (btn_handled) {
        cnt++;
        if (curr_time % 3 == 0) {
            user_actuate_relay(!old_state);
        }
        else if (curr_time % 3 == 1) {
            user_actuate_relay(old_state);
        }
        else if (curr_time % 3 == 2) {
            system_restart();
        }
    }

}


void __attribute__((section(".text"))) evb_gpio_isr(void *arg) {
    /* Temporarly disable GPIO interrupt and prepare for clearing the
     * interrupt */
    ETS_GPIO_INTR_DISABLE();
    uint32_t status = GPIO_REG_READ(GPIO_STATUS_ADDRESS);

    btn_event_time = curr_time;
    button_state = !button_state;
    os_printf_plus("btn\n");

    /* Clear interrupt and re-enable GPIO interrupt */
    GPIO_REG_WRITE(GPIO_STATUS_W1TC_ADDRESS, status);
    mist_value_changed(&(mist_app->model), "button");
    ETS_GPIO_INTR_ENABLE();
}



static enum mist_error hw_read(mist_ep* ep, void* result) {
    char *id = ep->id;
    int type = ep->type;
    os_printf("hw read: %s, type %d", id, type);
    if (strcmp(id, "state") == 0) {
        if (type == MIST_TYPE_BOOL) {
            bool * bool_result = result;
            *bool_result = relay_state;
        }
    }
    else if (strcmp(id, "button") == 0) {
        bool* bool_result = result;
        *bool_result = button_state;
    }
 
    return MIST_NO_ERROR;
}

static enum mist_error hw_write(mist_ep* ep, void* new_value) {
    char *id = ep->id;
    int type = ep->type;
    os_printf("hw write: %s, type %d\n", id, type);
    if (strcmp(id, "state") == 0) {
        if (type == MIST_TYPE_BOOL) {
            bool* bool_value = new_value;
            relay_state = *bool_value;
            user_actuate_relay(relay_state);
        }
    }
 
    mist_value_changed(&(mist_app->model), id);

    return MIST_NO_ERROR;
}

static void init_hardware(void) {

    //Set GPIO5 to output mode
    PIN_FUNC_SELECT(PERIPHS_IO_MUX_GPIO5_U, FUNC_GPIO5);
    //Set GPIO5 low
    gpio_output_set(0, BIT5, BIT5, 0);

    /* GPIO0 as button (input) */
    PIN_FUNC_SELECT(PERIPHS_IO_MUX_GPIO0_U, FUNC_GPIO0);
    PIN_PULLUP_EN(PERIPHS_IO_MUX_GPIO0_U);
    gpio_output_set(0, 0, 0, BIT0);
    GPIO_DIS_OUTPUT(BIT0);
    ETS_GPIO_INTR_ATTACH(evb_gpio_isr, NULL);
    gpio_pin_intr_state_set(GPIO_ID_PIN(0), GPIO_PIN_INTR_ANYEDGE);
    ETS_GPIO_INTR_ENABLE();
}

void mist_esp8266_evb_app_init(void) {
    init_hardware();
    char *name = "ESP8266 EVB";
    wish_app_t *app;
    mist_app = start_mist_app();
    mist_set_name(mist_app, name);

    struct mist_model *model = &(mist_app->model);
    model->custom_ui_url = "https://mist.controlthings.fi/mist-io-switch-0.0.2.tgz";
    mist_add_endpoint(model, "state", "Switch", MIST_TYPE_BOOL, "", hw_read, hw_write, NULL);
    mist_add_endpoint(model, "button", "Button", MIST_TYPE_BOOL, "", hw_read, NULL, NULL);

    app = wish_app_create(name);
    if (app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Failed creating wish app");
        return;
    }

    wish_app_add_protocol(app, &(mist_app->ucp_handler));
    mist_app->app = app;
    wish_app_login(app);
    
    os_timer_disarm(&button_timer);
    os_timer_setfn(&button_timer, (os_timer_func_t *) button_timer_cb, NULL);
    os_timer_arm(&button_timer, 1000, 1);


}


