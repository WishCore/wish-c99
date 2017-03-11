#include "wish_directory.h"
#include "wish_platform.h"
#include "utlist.h"
#include "string.h"

void wish_directory_init(wish_core_t* core) {
    int size = sizeof(wish_directory_t);
    core->directory = wish_platform_malloc(size);
    memset(core->directory, 0, size);
}

/* args: 'String alias' */
void wish_api_directory_find(rpc_server_req* req, uint8_t* args) {
    wish_core_t* core = req->server->context;
    wish_app_entry_t* app = req->context;
    
    bson bs;
    bson_iterator it;
    bson_init_with_data(&bs, args);
    
    const char* uid = bson_iterator_bin_data(&it);
    
    bson_find(&it, &bs, "0");
    if (bson_iterator_type(&it) != BSON_STRING || bson_iterator_string_len(&it) >= ROLE_NAME_LEN) {
        wish_rpc_server_error(req, 501, "Expected alias to be String(<64).");
        return;
    }
    
    const char* name = bson_iterator_string(&it);
    
    wish_rpc_server_error(req, 600, "Not implemented.");
}
