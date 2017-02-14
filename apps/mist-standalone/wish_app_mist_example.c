#include "wish_app.h"
#include "wish_core_client.h"

#include "mist_model.h"
#include "mist_handler.h"

#include "example_hardware.h"

static mist_app_t *mist_app;

mist_app_t* get_mist_app(void) {
    return mist_app;
}

int main(int argc, char** argv) {
    wish_app_t *app;

    // name used for WishApp and MistNode name
    char *name = "Example C99";

    //start wish apps
    mist_app = start_mist_app();

    struct mist_model *model = &(mist_app->model);
    
    mist_ep relay = { .id = "state", .label = "Relay", .type = MIST_TYPE_BOOL, .read = hw_read_relay, .write = hw_write_relay };
    mist_ep string = { .id = "my_str", .label = "My String", .type = MIST_TYPE_STRING, .read = hw_read_string };
    mist_ep function = { .id = "function", .label = "Function", .type = MIST_TYPE_INVOKE, .invoke = hw_invoke_function };
    
    mist_add_ep(model, &relay);
    mist_add_ep(model, &string);
    mist_add_ep(model, &function);

    model->custom_ui_url = "https://mist.controlthings.fi/mist-io-switch-0.0.2.tgz";
    
    mist_set_name(mist_app, name);
    
    app = wish_app_create(name);
    wish_app_add_protocol(app, &mist_app->ucp_handler);
    mist_app->app = app;
    
    if (app == NULL) {
        printf("Failed creating wish app");
        return 1;
    }
    
    return wish_core_client_init(app);
}
