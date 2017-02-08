#include "wish_app.h"
#include "wish_core_client.h"

#include "mist_api.h"

#include "mist_model.h"
#include "mist_handler.h"

#include <string.h>
#include "bson_visitor.h"

static void list_services_cb(struct wish_rpc_entry* req, void* ctx, uint8_t* data, size_t data_len) {
    printf("list_services_cb\n");
    bson_visit(data, elem_visitor);
}

static void signals_cb(struct wish_rpc_entry* req, void* ctx, uint8_t* data, size_t data_len) {
    printf("signals_cb\n");
    bson_visit(data, elem_visitor);
}

static void request_mapping_cb(struct wish_rpc_entry* req, void* ctx, uint8_t* data, size_t data_len) {
    printf("request_mapping_cb\n");
    bson_visit(data, elem_visitor);
}

static void load_app_cb(struct wish_rpc_entry* req, void* ctx, uint8_t* data, size_t data_len) {
    printf("load_app_cb\n");
    bson_visit(data, elem_visitor);
}

static void core_list_identities_cb(struct wish_rpc_entry* req, void* ctx, uint8_t* data, size_t data_len) {
    printf("core_list_identities_cb\n");
    bson_visit(data, elem_visitor);
}

static void get_service_id_cb(struct wish_rpc_entry* req, void* ctx, uint8_t* data, size_t data_len) {
    printf("get_service_id_cb\n");
    bson_visit(data, elem_visitor);
}

static int id;

static enum mist_error hw_read_string(mist_ep* ep, void* result) {
    memcpy(result, "Morjens", 8);
    return MIST_NO_ERROR;
}

static void make_some_calls() {
    bson bs;
    
    bson_init(&bs);
    bson_append_string(&bs, "op", "mist.listServices");
    bson_append_start_array(&bs, "args");
    bson_append_finish_array(&bs);
    bson_append_int(&bs, "id", ++id);
    bson_finish(&bs);
    
    mist_api_request(&bs, list_services_cb);
    bson_destroy(&bs);
    
    bson_init(&bs);
    bson_append_string(&bs, "op", "mist.signals");
    bson_append_start_array(&bs, "args");
    bson_append_finish_array(&bs);
    bson_append_int(&bs, "id", ++id);
    bson_finish(&bs);
    
    mist_api_request(&bs, list_services_cb);
    bson_destroy(&bs);
    
    //bson bs;
    bson_init(&bs);
    bson_append_string(&bs, "op", "mist.loadApp");
    bson_append_start_array(&bs, "args");
    bson_append_string(&bs, "0", "deadbeeffaceaced");
    bson_append_start_array(&bs, "1");
    bson_append_start_object(&bs, "0");
    bson_append_binary(&bs, "luid", "abcd", 4);
    bson_append_binary(&bs, "ruid", "bcde", 4);
    bson_append_binary(&bs, "rhid", "cdef", 4);
    bson_append_binary(&bs, "rsid", "defa", 4);
    bson_append_finish_object(&bs);
    bson_append_finish_array(&bs);
    bson_append_finish_array(&bs);
    bson_append_int(&bs, "id", ++id);
    bson_finish(&bs);
    
    mist_api_request(&bs, load_app_cb);
    bson_destroy(&bs);
    
    /* Test mist.getServiceId */
    bson_init(&bs);
    bson_append_string(&bs, "op", "mist.getServiceId");
    bson_append_start_array(&bs, "args");
    bson_append_finish_array(&bs);
    bson_append_int(&bs, "id", ++id);
    bson_finish(&bs);
    mist_api_request(&bs, get_service_id_cb);
    bson_destroy(&bs);
    
    
    bson_init(&bs);
    bson_append_string(&bs, "op", "identity.list");
    bson_append_start_array(&bs, "args");
    bson_append_finish_array(&bs);
    bson_append_int(&bs, "id", ++id);
    bson_finish(&bs);
    
    wish_api_request(&bs, core_list_identities_cb);
    bson_destroy(&bs);
    
    bson_init(&bs);
    bson_append_string(&bs, "op", "control.requestMapping");
    bson_append_start_array(&bs, "args");
    
    bson_append_start_object(&bs, "0");
    bson_append_binary(&bs, "luid", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", 32);
    bson_append_binary(&bs, "ruid", "bcdebcdebcdebcdebcdebcdebcdebcdebcdebcdebcdebcdebcdebcdebcdebcde", 32);
    bson_append_binary(&bs, "rhid", "cdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdef", 32);
    bson_append_binary(&bs, "rsid", "defadefadefadefadefadefadefadefadefadefadefadefadefadefadefadefa", 32);
    bson_append_string(&bs, "protocol", "ucp");
    bson_append_finish_object(&bs);

    bson_append_string(&bs, "1", "axis1");
    bson_append_start_object(&bs, "2");
    bson_append_string(&bs, "type", "direct");
    bson_append_string(&bs, "interval", "change");
    bson_append_finish_object(&bs);
    bson_append_string(&bs, "3", "robotLeg");
    bson_append_start_object(&bs, "4");
    bson_append_string(&bs, "type", "write");
    bson_append_finish_object(&bs);
    
    bson_append_finish_array(&bs);
    bson_append_int(&bs, "id", ++id);
    bson_finish(&bs);
    
    mist_api_request(&bs, request_mapping_cb);
    bson_destroy(&bs);
}

static void init(wish_app_t* app, bool ready) {
    if (ready) {
        WISHDEBUG(LOG_CRITICAL, "API ready!");
        make_some_calls();
    } else {
        WISHDEBUG(LOG_CRITICAL, "API not ready!");
    }
}

int main(int argc, char** argv) {
    wish_app_t *app;
    mist_app_t *mist_app;
    mist_api_t *mist_api;
    
    // name used for WishApp and MistNode name
    char *name = "Mist UI";

    //start wish apps
    mist_app = start_mist_app();

    struct mist_model *model = &(mist_app->model);
    
    mist_ep string = { .id = "info", .label = "Mist API", .type = MIST_TYPE_STRING, .read = hw_read_string };
    mist_add_ep(model, &string);

    mist_set_name(mist_app, name);
    
    app = wish_app_create(name);
    wish_app_add_protocol(app, &mist_app->ucp_handler);
    mist_app->app = app;

    mist_api_t* api = mist_api_init(mist_app);
    
    app->ready = init;
    
    if (app == NULL) {
        printf("Failed creating wish app");
        return 1;
    }
    
    wish_core_client_init(app);
    
    return 0;
}
