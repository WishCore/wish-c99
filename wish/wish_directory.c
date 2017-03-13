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
    
    bson_find(&it, &bs, "0");
    if (bson_iterator_type(&it) != BSON_STRING || bson_iterator_string_len(&it) >= ROLE_NAME_LEN) {
        wish_rpc_server_error(req, 501, "Expected alias to be String(<64).");
        return;
    }
    
    const char* name = bson_iterator_string(&it);
    
    bson_find(&it, &bs, "1");
    if (bson_iterator_type(&it) != BSON_INT) {
        wish_rpc_server_error(req, 501, "Expected count to be Int.");
        return;
    }
    
    int limit = bson_iterator_int(&it);
    
    bson b;
    bson_init(&b);
    bson_append_string(&b, "data", name);
    bson_finish(&b);

    int i;
    
    for (i=0; i<limit && i>=0; i++) {
        wish_rpc_server_emit(req, bson_data(&b), bson_size(&b));
    }
    
    
    wish_rpc_server_error(req, 600, "Not implemented.");
    
    bson_destroy(&b);
}
