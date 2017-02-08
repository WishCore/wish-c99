#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "wish_debug.h"
#include "wish_app.h"

#include "mist_model.h"
#include "mist_rpc.h"
#include "mist_handler.h"

wish_app_t *app;
mist_app_t *modbus_mist_app;

void hw_init(void);

void wish_app_mist_modbus_init() {

    char *name = "Modbus";

    //start wish apps
    modbus_mist_app = start_mist_app();
    mist_set_name(modbus_mist_app, name);
    
    struct mist_model *model = &(modbus_mist_app->model);
    // Large models require control.model response buffer to be sufficiently large
    //
    // See: mist_handler.c : MIST_RPC_REPLY_BUF_LEN 1400
    //                     : MODEL_MAX_LEN 1400
    
    mist_add_endpoint(model, "c-1", "Away", MIST_TYPE_BOOL, "", true, true, false);
    mist_add_endpoint(model,"c-3", "Overpressure", MIST_TYPE_BOOL, "", true, true, false);
    mist_add_endpoint(model,"c-10", "Boosting", MIST_TYPE_BOOL, "", true, true, false);
    //mist_add_endpoint("c-47", "Silent mode", MIST_TYPE_BOOL, "", true, true);
    mist_add_endpoint(model,"r-157", "Winter forcing outside temperature threshold", MIST_TYPE_FLOAT, "°C", true, true, false);
    //mist_add_endpoint("r-2", "Reg 2", MIST_TYPE_FLOAT, "°C", true, false);
    mist_add_endpoint(model,"r-3", "Supply fan speed", MIST_TYPE_FLOAT, "%", true, false, false);
    mist_add_endpoint(model,"r-4", "Extract fan speed", MIST_TYPE_FLOAT, "%", true, false, false);
    //mist_add_endpoint("r-5", "Reg 5", MIST_TYPE_FLOAT, "", true, false);
    mist_add_endpoint(model,"r-6", "Fresh air", MIST_TYPE_FLOAT, "°C", true, false, false);
    mist_add_endpoint(model,"r-7", "Supply air after heat recovery", MIST_TYPE_FLOAT, "°C", true, false, false);
    mist_add_endpoint(model,"r-8", "Supply air", MIST_TYPE_FLOAT, "°C", true, false, false);
    mist_add_endpoint(model,"r-9", "Exhaus air", MIST_TYPE_FLOAT, "°C", true, false, false);
    mist_add_endpoint(model,"r-10", "Extract air", MIST_TYPE_FLOAT, "°C", true, false, false);
    mist_add_endpoint(model,"r-11", "Extract air after hear recovery", MIST_TYPE_FLOAT, "°C", true, false, false);
    mist_add_endpoint(model,"r-12", "Return water", MIST_TYPE_FLOAT, "°C", true, false, false);
    mist_add_endpoint(model,"r-135", "Setpoint", MIST_TYPE_FLOAT, "°C", true, true, false);

    hw_init();
    
    app = wish_app_create(name);
    wish_app_add_protocol(app, &modbus_mist_app->ucp_handler);
    modbus_mist_app->app = app;
    wish_app_login(app);
    
    if (app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Failed creating wish app");
        return;
    }
}
