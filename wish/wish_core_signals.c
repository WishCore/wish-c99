#include "wish_core_signals.h"

void wish_core_signals(wish_rpc_ctx* req, uint8_t* args) {
    wish_core_t* core = (wish_core_t*) req->server->context;
    
    struct wish_rpc_server_handler *h = core->core_app_rpc_server->list_head;
    
    bson bs; 
    bson_init(&bs);
    bson_append_start_object(&bs, "data");
    
    while (h != NULL) {
        bson_append_start_object(&bs, h->op_str);
        bson_append_finish_object(&bs);

        h = h->next;
    }
    
    bson_append_finish_object(&bs);
    bson_finish(&bs);
    
    wish_rpc_server_send(req, bs.data, bson_size(&bs));
    bson_destroy(&bs);
}

void wish_core_signal_emit(wish_core_t* core, bson* signal) {
    wish_rpc_server_emit_broadcast(core->core_app_rpc_server, "signals", bson_data(signal), bson_size(signal));
}
