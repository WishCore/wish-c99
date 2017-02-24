#include "wish_core_signals.h"

void wish_core_signals(wish_rpc_ctx* req, uint8_t* args) {
    wish_core_t* core = (wish_core_t*) req->server->context;
    
    bson bs; 
    bson_init(&bs);
    bson_append_start_array(&bs, "data");
    bson_append_string(&bs, "0", "ok");
    bson_append_finish_array(&bs);
    bson_finish(&bs);
    
    wish_rpc_server_emit(req, bs.data, bson_size(&bs));
    bson_destroy(&bs);
}

void wish_core_signals_emit(wish_core_t* core, bson* signal) {
    wish_rpc_server_emit_broadcast(core->core_app_rpc_server, "signals", bson_data(signal), bson_size(signal));
}
