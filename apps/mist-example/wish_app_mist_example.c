#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "wish_debug.h"
#include "wish_app.h"

#include "mist_model.h"
#include "mist_rpc.h"
#include "mist_handler.h"

#include "example_hardware.h"

void wish_app_mist_example_init() {
    wish_app_t *app;
    mist_app_t *test_mist_app;

    // name used for WishApp and MistNode name
    char *name = "Example C99";

    //start wish apps
    test_mist_app = start_mist_app();

    struct mist_model *model = &(test_mist_app->model);
    mist_add_endpoint(model, "relay", "Relay", MIST_TYPE_BOOL, "", true, true, false);
    mist_add_endpoint(model, "my_str", "My String", MIST_TYPE_STRING, "", true, false, false);
    mist_add_endpoint(model, "function", "Function", MIST_TYPE_INVOKE, "", false, false, true);

    model->custom_ui_url = "https://mist.controlthings.fi/mist-io-switch-0.0.2.tgz";
    
    mist_set_name(test_mist_app, name);
    
    example_hw_init(model);
    
    app = wish_app_create(name);
    wish_app_add_protocol(app, &test_mist_app->ucp_handler);
    test_mist_app->app = app;
    wish_app_login(app);
    
    if (app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Failed creating wish app");
        return;
    }
}
