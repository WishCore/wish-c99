#include "mist_api.h"
#include "mist_app.h"
#include "wish_app.h"
#include "wish_rpc.h"
#include "wish_protocol.h"
#include "wish_platform.h"
#include "sandbox.h"
#include "utlist.h"
#include "wish_fs.h"

#include "wish_debug.h"
#include "bson_visitor.h"
#include <string.h>

static int id = 1000;

mist_api_t* mist_apis = NULL;

struct identity {
    // FIXME use real lengths, and move the struct to appropriate location
    char alias[32];
    uint8_t uid[32];
    uint8_t occupied;
    uint8_t export_occupied;
    uint8_t export[512];
    int export_len;
};

#define MIST_API_MAX_UIDS (128)

// FIXME For multiple mist_api's in same process (like when running tests) this has to be allocated per instance of mist_api
static struct identity identities[MIST_API_MAX_UIDS];

static void methods(wish_rpc_ctx* req, uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    struct wish_rpc_server_handler *h = mist_api->server.list_head;
    
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

static void model_cb(rpc_client_req* req, void *ctx, uint8_t *payload, size_t payload_len) {
    WISHDEBUG(LOG_CRITICAL, "model response:");
    bson_visit(payload, elem_visitor);
}

static void mist_ready(wish_rpc_ctx *req, uint8_t *args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    WISHDEBUG(LOG_DEBUG, "Handling ready request!");
    
    int buffer_len = 300;
    uint8_t buffer[buffer_len];
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_bool(&bs, "data", mist_api->wish_app->ready_state);
    bson_finish(&bs);

    //wish_core_send_message(rpc_ctx->ctx, res_doc, bson_get_doc_len(res_doc));
    wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
}

static void online(void* ctx, wish_protocol_peer_t* peer) {
    WISHDEBUG(LOG_CRITICAL, "online(%p): %p", ctx, peer);
    
    mist_api_t* mist_api = NULL; // find from existing mist apis based on context
    
    return;
    
    int buf_len = 300;
    char buf[buf_len];
    
    bson b;
    bson_init_buffer(&b, buf, buf_len);
    bson_append_string(&b, "data", "peers");
    bson_finish(&b);
    
    wish_rpc_server_emit_broadcast(&mist_api->server, "signals", bson_data(&b), bson_size(&b));

    //WISHDEBUG(LOG_CRITICAL, "Looking for peer in sandboxes.");
    
    bool changed = false;
    
    sandbox_t* sandbox;
    DL_FOREACH(mist_api->sandbox_db, sandbox) {
        sandbox_peers_t* elt;
        DL_FOREACH(sandbox->peers, elt) {
            if ( memcmp(elt->peer.luid, peer->luid, 32) == 0 &&
                 memcmp(elt->peer.ruid, peer->ruid, 32) == 0 &&
                 memcmp(elt->peer.rhid, peer->rhid, 32) == 0 &&
                 memcmp(elt->peer.rsid, peer->rsid, 32) == 0 &&
                 strncmp(elt->peer.protocol, peer->protocol, WISH_PROTOCOL_NAME_MAX_LEN) == 0 )
            {
                if (elt->peer.online == false) {
                    elt->peer.online = true;
                    changed = true;
                }
            }
        }
    }
    
    if (changed) {
        wish_rpc_server_emit_broadcast(&mist_api->server, "sandboxed.signals", bson_data(&b), bson_size(&b));
    }
}

static void offline(void* ctx, wish_protocol_peer_t* peer) {
    //WISHDEBUG(LOG_CRITICAL, "offline(%p): %p", ctx, peer);
    mist_api_t* mist_api = NULL; // find from existing mist apis based on context
    
    return;
    
    
    int buf_len = 300;
    char buf[buf_len];
    
    bson b;
    bson_init_buffer(&b, buf, buf_len);
    bson_append_string(&b, "data", "peers");
    bson_finish(&b);
    
    wish_rpc_server_emit_broadcast(&mist_api->server, "signals", bson_data(&b), bson_size(&b));
    
    
    bool changed = false;
    
    sandbox_t* sandbox;
    DL_FOREACH(mist_api->sandbox_db, sandbox) {
        sandbox_peers_t* elt;
        DL_FOREACH(sandbox->peers, elt) {
            if ( memcmp(elt->peer.luid, peer->luid, 32) == 0 &&
                 memcmp(elt->peer.ruid, peer->ruid, 32) == 0 &&
                 memcmp(elt->peer.rhid, peer->rhid, 32) == 0 &&
                 memcmp(elt->peer.rsid, peer->rsid, 32) == 0 &&
                 strncmp(elt->peer.protocol, peer->protocol, WISH_PROTOCOL_NAME_MAX_LEN) == 0 )
            {
                if (elt->peer.online != false) {
                    elt->peer.online = false;
                    changed = true;
                }
            }
        }
    }
    
    if (changed) {
        wish_rpc_server_emit_broadcast(&mist_api->server, "sandboxed.signals", bson_data(&b), bson_size(&b));
    }
    
}

static void mist_passthrough_end(wish_rpc_ctx *req) {
    WISHDEBUG(LOG_CRITICAL, "mist_passthrough_end, end... %p", req);
    
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    wish_rpc_client_t* peer_client = &mist_api->mist_app->ucp_handler.rpc_client;
    rpc_client_req* e = find_passthrough_request_entry(peer_client, req->id);
    if (e==NULL) {
        WISHDEBUG(LOG_CRITICAL, "mist_passthrough_end couldn't find request based on req->id: %i", req->id);
    } else {
        WISHDEBUG(LOG_CRITICAL, "mist_passthrough_end north ID: %i south ID: %i (passthrough id: %i peer: %p)", req->id, e->id, e->passthru_id, e->passthru_ctx);
        // Update the send_ctx for each call to passthrough. This is required because 
        // there is not own clients for each remote peer as there "shuold" be.
        peer_client->send_ctx = e->passthru_ctx;
        
        wish_rpc_client_end_by_id(peer_client, e->id);
    }
}

static void mist_passthrough(wish_rpc_ctx *req, uint8_t *args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    // Make a generic function for passing the control.* and manage.* commands to the device.

    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    char* bson_peer = (char*)bson_iterator_value(&it);

    wish_protocol_peer_t* peer = wish_protocol_peer_find_from_bson(&mist_api->mist_app->ucp_handler, bson_peer);
    
    //WISHDEBUG(LOG_CRITICAL, "Here is the peer %p", peer);
    //bson_visit(args, elem_visitor);
    
    if(peer == NULL) {
        wish_rpc_server_error(req, 55, "Peer not found.");
        return;
    }
    
    // create a bson request with:
    //
    // { op: (copy parent op),
    //   args: [parent args splice(1)] 
    //   id: copy parent id }
    //
    // Then send to passthrough
    
    int buf_len = 700;
    uint8_t buf[buf_len];
    bson b;
    bson_init_buffer(&b, buf, buf_len);

    // skip the prefix "sandbox.mist." from op string when forwarding request
    if (memcmp(req->op_str, "mist.", 5) == 0) {
        bson_append_string(&b, "op", req->op_str+5);
    } else {
        wish_rpc_server_error(req, 58, "Unrecognized mist command in passthrough. Should start with 'mist.' !");
    }
    
    
    bson_append_start_array(&b, "args");

    // Only single digit array index supported. 
    //   i.e Do not exceed 8 with the index. Rewrite indexing if you must!
    
    //   bson_find_from_buffer(&it, args, "1");
    //   bson_append_element(&b, "0", &it);
    //   bson_find_from_buffer(&it, args, "2");
    //   bson_append_element(&b, "1", &it);
    //   .
    //   .
    //   .
    
    bool done = false;
    int i;
    int args_len = 0;
    
    for(i=0; i<9; i++) {
    
        char src[2];
        src[0] = 48+i+1;
        src[1] = '\0';

        char dst[2];
        dst[0] = 48+i;
        dst[1] = '\0';
        
        // read the argument
        bson_find_from_buffer(&it, args, src);
        bson_type type = bson_iterator_type(&it);

        // FIXME check type under iterator is valid
        switch(type) {
            case BSON_EOO:
                done = true;
                break;
            case BSON_BOOL:
                bson_append_bool(&b, dst, bson_iterator_bool(&it));
                break;
            case BSON_INT:
                bson_append_int(&b, dst, bson_iterator_int(&it));
                break;
            case BSON_DOUBLE:
                bson_append_double(&b, dst, bson_iterator_double(&it));
                break;
            case BSON_STRING:
            case BSON_BINDATA:
            case BSON_OBJECT:
            case BSON_ARRAY:
                bson_append_element(&b, dst, &it);
                break;
            default:
                WISHDEBUG(LOG_CRITICAL, "Unsupported bson type %i in mist_passthrough", type);
        }
        
        if(done) {
            break;
        } else {
            args_len++;
        }
    }
    
    bson_append_finish_array(&b);
    bson_append_int(&b, "id", req->id);
    bson_finish(&b);

    //struct wish_rpc_context* rpc_ctx = (struct wish_rpc_context*) req->send_context;
    
    rpc_client_callback cb = req->ctx;
    
    // FIXME: this is a memory leak
    app_peer_t* app_peer = wish_platform_malloc(sizeof(app_peer_t));
    app_peer->app = mist_api->wish_app;
    app_peer->peer = peer;

    wish_rpc_client_t* peer_client = &mist_api->mist_app->ucp_handler.rpc_client;
    // Update the send_ctx for each call to passthrough. This is required because 
    // there is not own clients for each remote peer as there "shuold" be.
    peer_client->send_ctx = app_peer;

    req->end = mist_passthrough_end;
    
    wish_rpc_passthru_req(req, peer_client, &b, cb);
}

// FIXME move these to mist_api or somewhere else this does not work if there are multiple mist_apis
static int coercion_counter = 0;
static wish_rpc_ctx *coercion_req;
static uint8_t *coercion_args;

static void mist_request_mapping_cb(rpc_client_req* req, void *ctx, uint8_t *payload, size_t payload_len) {
    WISHDEBUG(LOG_CRITICAL, "Coercion response. %p %s", ctx, req->err ? "error" : "success");
    
    coercion_counter--;
    
    if(coercion_counter == 0) {
        // done here...
        WISHDEBUG(LOG_CRITICAL, "Coercion done. %p", ctx);
        mist_passthrough(coercion_req, coercion_args);
    }
}

static void mist_map_cb(rpc_client_req* req, void *ctx, uint8_t *payload, size_t payload_len) {
    
}

static void mist_map(wish_rpc_ctx *req, uint8_t *args) {
    WISHDEBUG(LOG_DEBUG, "Handling map request!");
    bson_visit(args, elem_visitor);
    
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    int buf_len = 300;
    uint8_t buf[buf_len];
    
    bson b;
    bson_init_buffer(&b, buf, buf_len);
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    wish_api_request(mist_api, &b, mist_map_cb);
    
    int buffer_len = 300;
    uint8_t buffer[buffer_len];
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_start_object(&bs, "data");
    bson_append_bool(&bs, "mappingCool", true);
    bson_append_finish_object(&bs);

    bson_finish(&bs);

    //wish_core_send_message(rpc_ctx->ctx, res_doc, bson_get_doc_len(res_doc));
    wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
}

static int mist_api_req_id = 0;

static void mist_request_mapping(wish_rpc_ctx *req, uint8_t *args) {
    WISHDEBUG(LOG_CRITICAL, "Handling requestMapping request! Should do some coercion.");
    
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    coercion_counter = 0;
    coercion_req = req;
    coercion_args = args;
    
    bson_visit(args, elem_visitor);
    
    bson_iterator dst_peer;
    bson_find_from_buffer(&dst_peer, args, "0");
    
    bson_iterator src_peer;
    bson_find_from_buffer(&src_peer, args, "1");

    bson_iterator it1;
    bson_iterator_from_buffer(&it1, args);
    
    if (bson_find_fieldpath_value("0.ruid", &it1) != BSON_BINDATA || bson_iterator_bin_len(&it1) != 32) {
        WISHDEBUG(LOG_CRITICAL, "Fail requestMapping: 0.ruid no.... %i", bson_iterator_type(&it1));
        return;
    }
    
    //bson_iterator_bin_data(&it1), 

    char* dst_export = NULL;
    int dst_export_len = 0;
    
    int i = 0;

    for (i=0; i<MIST_API_MAX_UIDS; i++) {
        if ( identities[i].occupied != 0 ) {
            if (memcmp(identities[i].uid, bson_iterator_bin_data(&it1), bson_iterator_bin_len(&it1)) == 0) {
                // found the identity
                dst_export = identities[i].export;
                dst_export_len = identities[i].export_len;
                WISHDEBUG(LOG_CRITICAL, "Found the thing it1. doc_len %i %p", identities[i].export_len, dst_export);
                break;
            }
        }
    }

    bson_iterator it2;
    bson_iterator_from_buffer(&it2, args);
    
    if (bson_find_fieldpath_value("1.ruid", &it2) != BSON_BINDATA || bson_iterator_bin_len(&it2) != 32) {
        WISHDEBUG(LOG_CRITICAL, "Fail requestMapping: 1.ruid no.... %i", bson_iterator_type(&it2));
        return;
    }
    
    char* src_export = NULL;
    int src_export_len = 0;
    

    for (i=0; i<MIST_API_MAX_UIDS; i++) {
        if ( identities[i].occupied != 0 ) {
            if (memcmp(identities[i].uid, bson_iterator_bin_data(&it2), bson_iterator_bin_len(&it2)) == 0) {
                // found the identity
                src_export = identities[i].export;
                src_export_len = identities[i].export_len;
                WISHDEBUG(LOG_CRITICAL, "Found the thing it2. doc_len %i %p", identities[i].export_len, src_export);
                break;
            }
        }
    }
    
    int buffer_len = 500;
    uint8_t buffer[buffer_len];
    bson bs;
    
    if (dst_export != NULL) {
        bson_init_buffer(&bs, buffer, buffer_len);
        bson_append_string(&bs, "op", "mist.manage.user.ensure");
        bson_append_start_array(&bs, "args");
        bson_append_element(&bs, "0", &src_peer);
        //bson_append_binary(&bs, "1", "asdcasdc", 8);
        //bson_append_string(&bs, "2", "bahamas-1");
        //bson_append_int(&bs, "3", dst_export_len);
        //bson_append_int(&bs, "4", (int)(long)dst_export);
        bson_append_binary(&bs, "1", dst_export, dst_export_len);
        bson_append_finish_array(&bs);
        bson_append_int(&bs, "id", ++mist_api_req_id);
        bson_finish(&bs);

        coercion_counter++;
        mist_api_request(mist_api, &bs, mist_request_mapping_cb);
    } else {
        WISHDEBUG(LOG_CRITICAL, "dst_export not set.", dst_export_len, src_export_len);
    }
    
    if (src_export != NULL) {
        bson_init_buffer(&bs, buffer, buffer_len);
        bson_append_string(&bs, "op", "mist.manage.user.ensure"); 
        bson_append_start_array(&bs, "args");
        bson_append_element(&bs, "0", &dst_peer);
        bson_append_binary(&bs, "1", src_export, src_export_len);
        //bson_append_string(&bs, "2", "bahamas-2");
        //bson_append_int(&bs, "3", src_export_len);
        //bson_append_int(&bs, "4", (int)(long)src_export);
        bson_append_finish_array(&bs);
        bson_append_int(&bs, "id", ++mist_api_req_id);
        bson_finish(&bs);

        coercion_counter++;
        mist_api_request(mist_api, &bs, mist_request_mapping_cb);
    } else {
        WISHDEBUG(LOG_CRITICAL, "src_export not set.");
    }
    
    
    
    //mist_passthrough(req, args);
}

static void mist_list_services(wish_rpc_ctx *req, uint8_t *args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    WISHDEBUG(LOG_DEBUG, "Handling listServices request!");
    
    wish_protocol_peer_t* peer;
    wish_protocol_peer_t* peer_pool = mist_api->mist_app->ucp_handler.peer_pool;
    int peer_pool_len = mist_api->mist_app->ucp_handler.peer_pool_size;
    
    int buffer_len = peer_pool_len * (2*WISH_ID_LEN + WISH_WSID_LEN + WISH_WHID_LEN + WISH_PROTOCOL_NAME_MAX_LEN + 128);
    uint8_t buffer[buffer_len];
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_start_object(&bs, "data");
    
    char key[6];
    
    int i;
    int c = 0;
    for(i=0; i<peer_pool_len; i++) {
        peer = &peer_pool[i];
        if (peer->occupied != 0) {
            c++;
            /* FIXME array index producer! */
            key[0] = 48 + i;
            key[1] = 0;
            
            bson_append_start_object(&bs, key);
            bson_append_binary(&bs, "luid", peer->luid, 32);
            bson_append_binary(&bs, "ruid", peer->ruid, 32);
            bson_append_binary(&bs, "rhid", peer->rhid, 32);
            bson_append_binary(&bs, "rsid", peer->rsid, 32);
            bson_append_string(&bs, "protocol", "ucp");
            bson_append_bool(&bs, "online", peer->online);
            bson_append_finish_object(&bs);
            
        }
    }
    
    bson_append_finish_object(&bs);

    bson_finish(&bs);
    
    if (bs.err) {
        WISHDEBUG(LOG_CRITICAL, "BSON error in mist_list_services");
        wish_rpc_server_error(req, 999, "BSON error in mist_list_services");
    }
    else {
        //wish_core_send_message(rpc_ctx->ctx, res_doc, bson_get_doc_len(res_doc));
        wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    }
}

static void mist_signals(wish_rpc_ctx *req, uint8_t *args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    //WISHDEBUG(LOG_CRITICAL, "mist.signals request!");

    int buffer_len = 300;
    uint8_t buffer[buffer_len];
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_string(&bs, "data", "ok");
    bson_finish(&bs);

    wish_rpc_server_emit(req, bson_data(&bs), bson_size(&bs));

    if (mist_api->wish_app->ready_state) {
        bson_init_buffer(&bs, buffer, buffer_len);
        bson_append_string(&bs, "data", "ready");
        bson_finish(&bs);

        wish_rpc_server_emit(req, bson_data(&bs), bson_size(&bs));
    }    
}

static void mist_load_app(wish_rpc_ctx *req, uint8_t *args) {
    WISHDEBUG(LOG_CRITICAL, "Load app request!");
    bson_visit(args, elem_visitor);

    int buffer_len = 300;
    uint8_t buffer[buffer_len];
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_start_object(&bs, "data");
    bson_append_bool(&bs, "nada", true);
    bson_append_finish_object(&bs);

    bson_finish(&bs);

    //wish_core_send_message(rpc_ctx->ctx, res_doc, bson_get_doc_len(res_doc));
    wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
}

static void mist_get_service_id(wish_rpc_ctx *req, uint8_t *args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    WISHDEBUG(LOG_CRITICAL, "mist.getServiceId request!");
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satify request because mist_api->wish_app is NULL");
        return;
    }
    uint8_t *wsid = mist_api->wish_app->wsid;
    bson bs;
    bson_init(&bs);
    bson_append_start_object(&bs, "data");
    bson_append_binary(&bs, "wsid", wsid, WISH_WSID_LEN);
    bson_append_finish_object(&bs);
    bson_finish(&bs);
    wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    bson_destroy(&bs);
}

static sandbox_t* mist_sandbox_by_id(mist_api_t* mist_api, char* id) {
    sandbox_t* elt;
    
    DL_FOREACH(mist_api->sandbox_db, elt) {
        //WISHDEBUG(LOG_CRITICAL, "  * a sandbox: %02x %02x %02x", elt->sandbox_id[0], elt->sandbox_id[1], elt->sandbox_id[2]);
        if (memcmp(id, elt->sandbox_id, 32) == 0) {
            //WISHDEBUG(LOG_CRITICAL, "Found!: %02x %02x %02x", elt->sandbox_id[0], elt->sandbox_id[1], elt->sandbox_id[2]);
            return elt;
        }
    }
    
    return NULL;
}

static void sandbox_passthrough_end(wish_rpc_ctx *req) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    //WISHDEBUG(LOG_CRITICAL, "sandbox_passthrough_end, end... %p", req);
    
    wish_rpc_client_t* peer_client = &mist_api->mist_app->ucp_handler.rpc_client;
    rpc_client_req* e = find_passthrough_request_entry(peer_client, req->id);
    if (e==NULL) {
        WISHDEBUG(LOG_CRITICAL, "sandbox_passthrough_end couldn't find request based on req->id: %i", req->id);
    } else {
        //WISHDEBUG(LOG_CRITICAL, "sandbox_passthrough_end north ID: %i south ID: %i (passthrough id: %i peer: %p)", req->id, e->id, e->passthru_id, e->passthru_ctx);
        
        // Update the send_ctx for each call to passthrough. This is required because 
        // there is not own clients for each remote peer as there "shuold" be.
        peer_client->send_ctx = e->passthru_ctx;
        
        wish_rpc_client_end_by_id(peer_client, e->id);
    }
}

static void sandbox_passthrough(wish_rpc_ctx *req, uint8_t *args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    // Make a generic function for passing the control.* and manage.* commands to the device.

    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    char* sandbox_id = (char*) bson_iterator_bin_data(&it);
    
    sandbox_t* sandbox = mist_sandbox_by_id(mist_api, sandbox_id);

    if (sandbox == NULL) {
        wish_rpc_server_error(req, 58, "Sandbox not found.");
        return;
    }
    
    bson_find_from_buffer(&it, args, "1");
    char* bson_peer = (char*)bson_iterator_value(&it);

    wish_protocol_peer_t* peer = wish_protocol_peer_find_from_bson(&mist_api->mist_app->ucp_handler, bson_peer);
    
    
    if(peer == NULL) {
        wish_rpc_server_error(req, 55, "Peer not found.");
        WISHDEBUG(LOG_CRITICAL, "Here is the peer %p, and arguments follow:", peer);
        bson_visit(args, elem_visitor);
        return;
    }
    
    // create a bson request with:
    //
    // { op: (copy parent op),
    //   args: [parent args splice(1)] 
    //   id: copy parent id }
    //
    // Then send to passthrough
    
    int buf_len = 700;
    uint8_t buf[buf_len];
    bson b;
    bson_init_buffer(&b, buf, buf_len);
    
    // skip the prefix "sandbox.mist." from op string when forwarding request
    if (memcmp(req->op_str, "sandboxed.mist.", 10+5) == 0) {
        bson_append_string(&b, "op", req->op_str+10+5);
    } else {
        wish_rpc_server_error(req, 58, "Unrecognized sandbox command in passthrough. Should start with 'sandbox.mist.' !");
        return;
    }
    
    bson_append_start_array(&b, "args");

    // Only single digit array index supported. 
    //   i.e Do not exceed 7 with the index. Rewrite indexing if you must!
    
    //   bson_find_from_buffer(&it, args, "1");
    //   bson_append_element(&b, "0", &it);
    //   bson_find_from_buffer(&it, args, "2");
    //   bson_append_element(&b, "1", &it);
    //   .
    //   .
    //   .
    
    bool done = false;
    int i;
    int args_len = 0;
    
    for(i=0; i<8; i++) {
    
        char src[2];
        src[0] = 48+i+2;
        src[1] = '\0';

        char dst[2];
        dst[0] = 48+i;
        dst[1] = '\0';
        
        // read the argument
        bson_find_from_buffer(&it, args, src);
        bson_type type = bson_iterator_type(&it);

        // FIXME check type under iterator is valid
        switch(type) {
            case BSON_EOO:
                done = true;
                break;
            case BSON_BOOL:
                bson_append_bool(&b, dst, bson_iterator_bool(&it));
                break;
            case BSON_INT:
                bson_append_int(&b, dst, bson_iterator_int(&it));
                break;
            case BSON_DOUBLE:
                bson_append_double(&b, dst, bson_iterator_double(&it));
                break;
            case BSON_STRING:
            case BSON_BINDATA:
            case BSON_OBJECT:
            case BSON_ARRAY:
                bson_append_element(&b, dst, &it);
                break;
            default:
                WISHDEBUG(LOG_CRITICAL, "Unsupported bson type %i in mist_passthrough", type);
        }
        
        if(done) {
            break;
        } else {
            args_len++;
        }
    }
    
    bson_append_finish_array(&b);
    bson_append_int(&b, "id", req->id);
    bson_finish(&b);

    rpc_client_callback cb = req->ctx;
    
    // FIXME: this is a memory leak
    app_peer_t* app_peer = wish_platform_malloc(sizeof(app_peer_t));
    app_peer->app = mist_api->wish_app;
    app_peer->peer = peer;

    wish_rpc_client_t* peer_client = &mist_api->mist_app->ucp_handler.rpc_client;
    // Update the send_ctx for each call to passthrough. This is required because 
    // there is not own clients for each remote peer as there "shuold" be.
    peer_client->send_ctx = app_peer;

    req->end = sandbox_passthrough_end;
    
    wish_rpc_passthru_req(req, peer_client, &b, cb);
}

static void sandbox_signals(wish_rpc_ctx *req, uint8_t *args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    //WISHDEBUG(LOG_CRITICAL, "sandbox.signals request, added to subscription list!");

    int buffer_len = 300;
    uint8_t buffer[buffer_len];
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_string(&bs, "data", "ok");
    bson_finish(&bs);

    wish_rpc_server_emit(req, bson_data(&bs), bson_size(&bs));

    if (mist_api->wish_app->ready_state) {
        bson_init_buffer(&bs, buffer, buffer_len);
        bson_append_string(&bs, "data", "ready");
        bson_finish(&bs);

        wish_rpc_server_emit(req, bson_data(&bs), bson_size(&bs));
    }
}

static void mist_sandbox_list(wish_rpc_ctx *req, uint8_t *args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    //WISHDEBUG(LOG_CRITICAL, "mist.sandbox.list");
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satisfy request because mist_api->wish_app is NULL");
        return;
    }

    bson bs;
    bson_init(&bs);
    bson_append_start_array(&bs, "data");
    
    sandbox_t* elt;

    DL_FOREACH(mist_api->sandbox_db, elt) {
        //WISHDEBUG(LOG_CRITICAL, "  * a sandbox: %02x %02x %02x %p", elt->sandbox_id[0], elt->sandbox_id[1], elt->sandbox_id[2], elt);
        bson_append_start_object(&bs, "0");
        bson_append_string_maxlen(&bs, "name", elt->name, SANDBOX_NAME_LEN);
        bson_append_binary(&bs, "id", elt->sandbox_id, SANDBOX_ID_LEN);
        bson_append_bool(&bs, "online", elt->online);
        bson_append_finish_object(&bs);
        
        if (bs.err) {
            WISHDEBUG(LOG_CRITICAL, "  bs.err %s", bs.errstr);
            break;
        }
    }
    
    bson_append_finish_array(&bs);
    bson_finish(&bs);
    wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    bson_destroy(&bs);
}

#define SANDBOX_FILE   "sandbox.bin"
 
static void mist_sandbox_write_file(const char* buf, int buf_len) {
    wish_fs_remove(SANDBOX_FILE);
    wish_file_t fd = wish_fs_open(SANDBOX_FILE);
    if (fd <= 0) {
        WISHDEBUG(LOG_CRITICAL, "Error opening file! Sandbox state could not be saved.");
        return;
    }
    wish_fs_lseek(fd, 0, WISH_FS_SEEK_SET);
    wish_fs_write(fd, buf, buf_len);
    wish_fs_close(fd);
}

static void sandbox_save(mist_api_t* mist_api) {
    //WISHDEBUG(LOG_CRITICAL, "Saving sandbox states:");
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satisfy request because mist_api->wish_app is NULL");
        return;
    }

    bson bs;
    bson_init(&bs);
    bson_append_start_array(&bs, "data");
    
    sandbox_t* sandbox;
    int i = 0;
    
    DL_FOREACH(mist_api->sandbox_db, sandbox) {
        // sandbox string index
        char si[21];
        BSON_NUMSTR(si, i);

        bson_append_start_object(&bs, si);
        bson_append_string_maxlen(&bs, "name", sandbox->name, SANDBOX_NAME_LEN);
        bson_append_binary(&bs, "id", sandbox->sandbox_id, SANDBOX_ID_LEN);
        bson_append_start_array(&bs, "peers");
        
        struct sandbox_peers_t* p;
        //WISHDEBUG(LOG_CRITICAL, "  about to add peer.");

        // peer index and string index
        int pi = 0;
        char spi[21];

        DL_FOREACH(sandbox->peers, p) {
            BSON_NUMSTR(spi, pi);
            bson_append_start_object(&bs, spi);
            bson_append_binary(&bs, "luid", p->peer.luid, WISH_UID_LEN);
            bson_append_binary(&bs, "ruid", p->peer.ruid, WISH_UID_LEN);
            bson_append_binary(&bs, "rhid", p->peer.rhid, WISH_UID_LEN);
            bson_append_binary(&bs, "rsid", p->peer.rsid, WISH_UID_LEN);
            bson_append_string_maxlen(&bs, "protocol", p->peer.protocol, WISH_PROTOCOL_NAME_MAX_LEN);
            bson_append_finish_object(&bs);
            pi++;
        }
        
        bson_append_finish_array(&bs);
        bson_append_finish_object(&bs);
        i++;
    }
    
    bson_append_finish_array(&bs);
    bson_finish(&bs);
    
    //WISHDEBUG(LOG_CRITICAL, "  about write sandbox file:");
    //bson_visit((char*)bson_data(&bs), elem_visitor);
    
    mist_sandbox_write_file( bson_data(&bs), bson_size(&bs) );
    bson_destroy(&bs);
}

static void mist_sandbox_remove(wish_rpc_ctx *req, uint8_t *args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    //WISHDEBUG(LOG_CRITICAL, "mist.sandbox.list");
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satisfy request because mist_api->wish_app is NULL");
        return;
    }

    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    char* sandbox_id = (char*) bson_iterator_bin_data(&it);    
    
    sandbox_t* elt;
    sandbox_t* tmp;

    bool deleted = false;
    
    DL_FOREACH_SAFE(mist_api->sandbox_db, elt, tmp) {
        
        if ( memcmp(elt->sandbox_id, sandbox_id, SANDBOX_ID_LEN) == 0 ) {
            
            sandbox_peers_t* p;
            sandbox_peers_t* ptmp;
            
            DL_FOREACH_SAFE(elt->peers, p, ptmp) {
                if (p != NULL) { wish_platform_free(p); }
            }
            
            DL_DELETE(mist_api->sandbox_db, elt);
            
            wish_platform_free(elt);
            
            deleted = true;
            break;
        }
    }
    
    sandbox_save(mist_api);
    
    bson bs;
    bson_init(&bs);
    bson_append_bool(&bs, "data", deleted);
    bson_finish(&bs);
    
    wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    
    bson_destroy(&bs);
}


/**
 * BSON.deserialize(fs.readFileSync('./sandbox.bin'))
 * { data: 
 *    [ { name: 'ControlThings App',
 *        id: <Buffer be ef 00 ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab>,
 *        peers: [] },
 *      { name: 'Soikea App',
 *        id: <Buffer de ad 00 ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab>,
 *        peers: 
 *         [ { luid: <Buffer 45 07 9c 1a 9a 15 4c 55 4c 27 62 9d c5 a6 30 3c f3 01 85 c2 3a 23 6a 33 b6 18 3b 35 35 31 43 c9>,
 *             ruid: <Buffer 45 07 9c 1a 9a 15 4c 55 4c 27 62 9d c5 a6 30 3c f3 01 85 c2 3a 23 6a 33 b6 18 3b 35 35 31 43 c9>,
 *             rhid: <Buffer 0e b9 2d bf 29 a8 49 53 b9 36 9f 11 9a 2d 94 97 6a a0 33 ac 33 55 d5 ae f7 ed ff 07 2e 20 68 3b>,
 *             rsid: <Buffer 47 50 53 20 6e 6f 64 65 2e 6a 73 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00>,
 *             protocol: 'ucp' } ] } ] }
 */
static void sandbox_load(mist_api_t* mist_api) {
    wish_file_t fd = wish_fs_open(SANDBOX_FILE);
    if (fd <= 0) {
        WISHDEBUG(LOG_CRITICAL, "Error opening file! Sandbox could not be loaded!");
        return;
    }
    wish_fs_lseek(fd, 0, WISH_FS_SEEK_SET);
    
    
    int size = 0;
    
    /* First, read in the next mapping id */
    int read_ret = wish_fs_read(fd, (void*) &size, 4);

    if (read_ret != 4) {
        WISHDEBUG(LOG_CRITICAL, "Empty file, or read error in sandbox load.");
        return;
    }

    if(size>64*1024) {
        WISHDEBUG(LOG_CRITICAL, "Sandbox load, file too large (64KiB limit). Found: %i bytes.", size);
        return;
    }
    
    bson bs;
    bson_init_size(&bs, size);
    
    /* Go back to start and read the whole file to bson buffer */
    wish_fs_lseek(fd, 0, WISH_FS_SEEK_SET);
    read_ret = wish_fs_read(fd, ((void*)bs.data), size);
    
    if (read_ret != size) {
        WISHDEBUG(LOG_CRITICAL, "Sandbox failed to read %i bytes, got %i.", size, read_ret);
    }
    
    wish_fs_close(fd);
    
    //WISHDEBUG(LOG_CRITICAL, "Sandbox file loaded this:");
    //bson_visit( (char*) bson_data(&bs), elem_visitor);

    /* Load content from sandbox file */
    
    bson_iterator it;
    bson_iterator sit;
    bson_iterator soit;
    bson_iterator pit;
    bson_iterator poit;
    
    if ( bson_find(&it, &bs, "data") != BSON_ARRAY ) {
        // that didn't work
        WISHDEBUG(LOG_CRITICAL, "That didn't work d. %i", bson_find(&sit, &bs, "data"));
        return;
    }
    
    // sandbox index
    int si = 0;
    char sindex[21];
    
    while (true) {
        BSON_NUMSTR(sindex, si++);
        
        bson_iterator_subiterator(&it, &sit);
        if ( bson_find_fieldpath_value(sindex, &sit) != BSON_OBJECT ) {
            // that didn't work
            //WISHDEBUG(LOG_CRITICAL, "Not an object at index %s looking for sandboxes.", sindex);
            return;
        }
        
        bson_iterator_subiterator(&sit, &soit);

        if ( bson_find_fieldpath_value("name", &soit) != BSON_STRING ) {
            // that didn't work
            WISHDEBUG(LOG_CRITICAL, "That didn't work b.");
            return;
        }

        const char* name = bson_iterator_string(&soit);

        //WISHDEBUG(LOG_CRITICAL, "A sandbox name: %s", name);

        bson_iterator_subiterator(&sit, &soit);

        if ( bson_find_fieldpath_value("id", &soit) != BSON_BINDATA || bson_iterator_bin_len(&soit) != WISH_UID_LEN ) {
            // that didn't work
            WISHDEBUG(LOG_CRITICAL, "That didn't work c.");
            return;
        }

        const char* id = bson_iterator_bin_data(&soit);

        //WISHDEBUG(LOG_CRITICAL, "A sandbox id: %02x %02x %02x %02x", id[0], id[1], id[2], id[3]);

        bson_iterator_subiterator(&sit, &soit);

        if ( bson_find_fieldpath_value("peers", &soit) != BSON_ARRAY ) {
            // that didn't work
            WISHDEBUG(LOG_CRITICAL, "That didn't work d.");
            return;
        }


        /* We have confirmed there is a sandbox object here */
        sandbox_t* sandbox = wish_platform_malloc(sizeof(sandbox_t));

        if (!sandbox) {
            WISHDEBUG(LOG_CRITICAL, "Memory allocation failed.");
            return;
        }

        memset(sandbox, 0, sizeof(sandbox_t));
        memcpy(sandbox->sandbox_id, id, SANDBOX_ID_LEN);
        strncpy(sandbox->name, name, SANDBOX_NAME_LEN);
        sandbox->online = false;

        DL_APPEND(mist_api->sandbox_db, sandbox);


        int pi = 0;
        char pindex[21];

        while (true) {
            BSON_NUMSTR(pindex, pi++);
            bson_iterator_subiterator(&soit, &pit);
            if ( bson_find_fieldpath_value(pindex, &pit) != BSON_OBJECT ) {
                // that didn't work
                //WISHDEBUG(LOG_CRITICAL, "No index %s looking for peers in %s.", pindex, name);
                break;
            }

            bson_iterator_subiterator(&pit, &poit);
            if ( bson_find_fieldpath_value("luid", &poit) != BSON_BINDATA || bson_iterator_bin_len(&poit) != WISH_UID_LEN ) { 
                WISHDEBUG(LOG_CRITICAL, "That didn't work luid."); break; }
            const char* luid = bson_iterator_bin_data(&poit);

            bson_iterator_subiterator(&pit, &poit);
            if ( bson_find_fieldpath_value("ruid", &poit) != BSON_BINDATA || bson_iterator_bin_len(&poit) != WISH_UID_LEN ) { 
                WISHDEBUG(LOG_CRITICAL, "That didn't work ruid."); break; }
            const char* ruid = bson_iterator_bin_data(&poit);

            bson_iterator_subiterator(&pit, &poit);
            if ( bson_find_fieldpath_value("rhid", &poit) != BSON_BINDATA || bson_iterator_bin_len(&poit) != WISH_UID_LEN ) { 
                WISHDEBUG(LOG_CRITICAL, "That didn't work rhid."); break; }
            const char* rhid = bson_iterator_bin_data(&poit);

            bson_iterator_subiterator(&pit, &poit);
            if ( bson_find_fieldpath_value("rsid", &poit) != BSON_BINDATA || bson_iterator_bin_len(&poit) != WISH_UID_LEN ) { 
                WISHDEBUG(LOG_CRITICAL, "That didn't work rsid."); break; }
            const char* rsid = bson_iterator_bin_data(&poit);

            bson_iterator_subiterator(&pit, &poit);
            if ( bson_find_fieldpath_value("protocol", &poit) != BSON_STRING || bson_iterator_string_len(&poit) > WISH_PROTOCOL_NAME_MAX_LEN ) { 
                WISHDEBUG(LOG_CRITICAL, "That didn't work protocol."); break; }
            const char* protocol = bson_iterator_string(&poit);

            //WISHDEBUG(LOG_CRITICAL, "Got all the way here. %s", protocol);

            /* We have confirmed there is a peer object here */
            sandbox_peers_t* peer_elt = wish_platform_malloc(sizeof(sandbox_peers_t));

            if (!peer_elt) {
                WISHDEBUG(LOG_CRITICAL, "Memory allocation failed for peer.");
                bson_destroy(&bs);
                return;
            }

            memset(peer_elt, 0, sizeof(sandbox_peers_t));

            peer_elt->peer.occupied = true;
            memcpy(&peer_elt->peer.luid, luid, WISH_UID_LEN);
            memcpy(&peer_elt->peer.ruid, ruid, WISH_UID_LEN);
            memcpy(&peer_elt->peer.rhid, rhid, WISH_UID_LEN);
            memcpy(&peer_elt->peer.rsid, rsid, WISH_UID_LEN);
            strncpy(peer_elt->peer.protocol, protocol, WISH_PROTOCOL_NAME_MAX_LEN);

            DL_PREPEND(sandbox->peers, peer_elt);
        }
    }
    
    bson_destroy(&bs);
}

static void sandbox_signals_emit(mist_api_t* mist_api, char* signal) { //, bson* elem) {
    int buf_len = 300;
    char buf[buf_len];
    
    bson b;
    bson_init_buffer(&b, buf, buf_len);
    
    //bson_append_start_array(&b, "data");
    //bson_append_string(&b, "0", signal);
    //bson_append_(&b, "0", elem);
    //bson_append_finish_array(&b);
    
    bson_append_string(&b, "data", signal);
    bson_finish(&b);
    
    wish_rpc_server_emit_broadcast(&mist_api->server, "sandboxed.signals", bson_data(&b), bson_size(&b));
}

static void mist_sandbox_add_peer(wish_rpc_ctx *req, uint8_t *args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    //WISHDEBUG(LOG_CRITICAL, "mist.sandbox.addPeer");
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satify request because mist_api->wish_app is NULL");
        return;
    }
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    char* sandbox_id = (char*) bson_iterator_bin_data(&it);
    
    bson_find_from_buffer(&it, args, "1");
    
    wish_protocol_peer_t peer;
    
    bool success = wish_protocol_peer_populate_from_bson(&peer, (uint8_t*) bson_iterator_value(&it));
    
    if ( success ) {
        // try to find the peer in the db
        wish_protocol_peer_t* actual = wish_protocol_peer_find(&mist_api->mist_app->ucp_handler, &peer);
        
        if (actual == NULL) {
            // there is no actual peer that corresponds to the sandboxed peer
        } else {
            peer.online = actual->online;
        }        
        
        sandbox_t* sandbox = mist_sandbox_by_id(mist_api, sandbox_id);
        
        if (sandbox == NULL) {
            wish_rpc_server_error(req, 58, "Sandbox not found.");
            return;
        }
        
        bool added = sandbox_add_peer(sandbox, &peer);
        
        bson bs;
        bson_init(&bs);
        bson_append_bool(&bs, "data", added);
        bson_finish(&bs);
        wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
        bson_destroy(&bs);

        if (added) { sandbox_signals_emit(mist_api, "peers"); }
    } else {
        //WISHDEBUG(LOG_CRITICAL, "  Peer invalid.");
        //bson_visit(args, elem_visitor);
        wish_rpc_server_error(req, 57, "Peer invalid.");
    }
    
    sandbox_save(mist_api);
}

static void mist_sandbox_remove_peer(wish_rpc_ctx *req, uint8_t *args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    //WISHDEBUG(LOG_CRITICAL, "mist.sandbox.removePeer");
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satify request because mist_api->wish_app is NULL");
        return;
    }
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    char* sandbox_id = (char*) bson_iterator_bin_data(&it);
    
    bson_find_from_buffer(&it, args, "1");
    
    wish_protocol_peer_t peer;
    
    bool success = wish_protocol_peer_populate_from_bson(&peer, (uint8_t*) bson_iterator_value(&it));
    
    if ( success ) {
        // try to find the peer in the db
        wish_protocol_peer_t* actual = wish_protocol_peer_find(&mist_api->mist_app->ucp_handler, &peer);
        
        if (actual == NULL) {
            // there is no actual peer that corresponds to the sandboxed peer
        } else {
            peer.online = actual->online;
        }        
        
        sandbox_t* sandbox = mist_sandbox_by_id(mist_api, sandbox_id);
        
        if (sandbox == NULL) {
            wish_rpc_server_error(req, 58, "Sandbox not found.");
            return;
        }
        
        bool removed = sandbox_remove_peer(sandbox, &peer);
        
        bson bs;
        bson_init(&bs);
        bson_append_bool(&bs, "data", removed);
        bson_finish(&bs);
        wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
        bson_destroy(&bs);

        if (removed) { sandbox_signals_emit(mist_api, "peers"); }
    } else {
        //WISHDEBUG(LOG_CRITICAL, "  Peer invalid.");
        //bson_visit(args, elem_visitor);
        wish_rpc_server_error(req, 57, "Peer invalid.");
    }
    
    sandbox_save(mist_api);
}

static void sandbox_list_peers(wish_rpc_ctx *req, uint8_t *args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    //WISHDEBUG(LOG_CRITICAL, "mist.sandbox.listPeers");
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satisfy request because mist_api->wish_app is NULL");
        return;
    }
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    char* sandbox_id = (char*) bson_iterator_bin_data(&it);
    
    sandbox_t* sandbox = mist_sandbox_by_id(mist_api, sandbox_id);

    if (sandbox == NULL) {
        wish_rpc_server_error(req, 58, "Sandbox not found.");
        return;
    }

    bson bs;
    bson_init(&bs);
    bson_append_start_array(&bs, "data");
    
    sandbox_peers_t* elt;
    int c = 0;
    
    DL_FOREACH(sandbox->peers, elt) {
        char s[21];
        bson_numstr(s, c++);
        bson_append_start_object(&bs, s);
        bson_append_binary(&bs, "luid", elt->peer.luid, 32);
        bson_append_binary(&bs, "ruid", elt->peer.ruid, 32);
        bson_append_binary(&bs, "rhid", elt->peer.rhid, 32);
        bson_append_binary(&bs, "rsid", elt->peer.rsid, 32);
        bson_append_string(&bs, "protocol", elt->peer.protocol);
        bson_append_bool(&bs, "online", elt->peer.online);
        bson_append_finish_object(&bs);
    }

    bson_append_finish_array(&bs);
    bson_finish(&bs);
    wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    bson_destroy(&bs);
}

static void sandbox_settings(wish_rpc_ctx *req, uint8_t *args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    //WISHDEBUG(LOG_CRITICAL, "mist.sandbox.addPeer");
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satify request because mist_api->wish_app is NULL");
        return;
    }
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    char* sandbox_id = (char*) bson_iterator_bin_data(&it);
    
    int buffer_len = 300;
    uint8_t buffer[buffer_len];
    
    bson b;
    bson_init_buffer(&b, buffer, buffer_len);
    bson_append_start_array(&b, "data");
    bson_append_string(&b, "0", "sandboxed.settings");
    bson_append_start_object(&b, "1");
    bson_append_binary(&b, "id", sandbox_id, SANDBOX_ID_LEN);
    bson_append_string(&b, "hint", "commission");
    bson_append_finish_object(&b);
    bson_append_finish_array(&b);
    bson_finish(&b);

    wish_rpc_server_emit_broadcast(&mist_api->server, "signals", bson_data(&b), bson_size(&b));
    
    
    bson bs;
    bson_init(&bs);
    bson_append_bool(&bs, "data", true);
    bson_finish(&bs);
    wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    bson_destroy(&bs);
}

static void sandbox_login(wish_rpc_ctx *req, uint8_t *args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;

    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satify request because mist_api->wish_app is NULL");
        return;
    }
    
    bool changed = false;
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    if (bson_iterator_type(&it) != BSON_BINDATA) {
        wish_rpc_server_error(req, 88, "Invalid sandbox id");
        return;
    }
    
    char* id = (char*) bson_iterator_bin_data(&it);
    
    sandbox_t* sandbox = mist_sandbox_by_id(mist_api, id);

    if (sandbox == NULL) {
        sandbox = wish_platform_malloc(sizeof(sandbox_t));

        if (!sandbox) {
            wish_rpc_server_error(req, 102, "Memory allocation failed.");
            return;
        }

        memset(sandbox, 0, sizeof(sandbox_t));
        memcpy(sandbox->sandbox_id, id, SANDBOX_ID_LEN);
        
        DL_PREPEND(mist_api->sandbox_db, sandbox);
        changed = true;
    }    

    bson_find_from_buffer(&it, args, "1");
    char* name = (char*) bson_iterator_string(&it);

    if ( strncmp(sandbox->name, name, SANDBOX_NAME_LEN) != 0 ) {
        changed = true;
    }
    
    strncpy(sandbox->name, name, SANDBOX_NAME_LEN);
    sandbox->online = true;

    if (changed) {
        sandbox_save(mist_api);
    }
    
    bson b;
    bson_init(&b);
    bson_append_start_array(&b, "data");
    bson_append_string(&b, "0", "sandboxed.login");
    bson_append_start_object(&b, "1");
    bson_append_binary(&b, "id", id, SANDBOX_ID_LEN);
    bson_append_finish_object(&b);
    bson_append_finish_array(&b);
    bson_finish(&b);

    wish_rpc_server_emit_broadcast(&mist_api->server, "signals", bson_data(&b), bson_size(&b));
    bson_destroy(&b);
    
    
    bson bs;
    bson_init(&bs);
    bson_append_bool(&bs, "data", true);
    bson_finish(&bs);
    wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    bson_destroy(&bs);
}

static void sandbox_logout(wish_rpc_ctx *req, uint8_t *args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satify request because mist_api->wish_app is NULL");
        return;
    }

    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    char* sandbox_id = (char*) bson_iterator_bin_data(&it);
    
    sandbox_t* sandbox = mist_sandbox_by_id(mist_api, sandbox_id);
    
    if (sandbox == NULL) {
        wish_rpc_server_error(req, 58, "Sandbox not found.");
        return;
    }

    sandbox->online = false;

    bson bs;
    bson_init(&bs);
    bson_append_bool(&bs, "data", true);
    bson_finish(&bs);
    wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    bson_destroy(&bs);
}

// Mist remote node commands
static struct wish_rpc_server_handler control_read_handler =                 { .op_str = "mist.control.read",               .handler = mist_passthrough };
static struct wish_rpc_server_handler control_write_handler =                { .op_str = "mist.control.write",              .handler = mist_passthrough };
static struct wish_rpc_server_handler control_invoke_handler =               { .op_str = "mist.control.invoke",             .handler = mist_passthrough };
static struct wish_rpc_server_handler control_follow_handler =               { .op_str = "mist.control.follow",             .handler = mist_passthrough };
static struct wish_rpc_server_handler control_model_handler =                { .op_str = "mist.control.model",              .handler = mist_passthrough };
static struct wish_rpc_server_handler control_map_handler =                  { .op_str = "mist.control.map",                .handler = mist_passthrough };
static struct wish_rpc_server_handler control_un_map_handler =               { .op_str = "mist.control.unMap",              .handler = mist_passthrough };
static struct wish_rpc_server_handler control_notify_handler =               { .op_str = "mist.control.notify",             .handler = mist_passthrough };
static struct wish_rpc_server_handler control_request_mapping_handler =      { .op_str = "mist.control.requestMapping",     .handler = mist_request_mapping };
static struct wish_rpc_server_handler manage_claim_handler =                 { .op_str = "mist.manage.claim",               .handler = mist_passthrough };
static struct wish_rpc_server_handler manage_peers_handler =                 { .op_str = "mist.manage.peers",               .handler = mist_passthrough };
static struct wish_rpc_server_handler manage_acl_model_handler =             { .op_str = "mist.manage.acl.model",           .handler = mist_passthrough };
static struct wish_rpc_server_handler manage_acl_allow_handler =             { .op_str = "mist.manage.acl.allow",           .handler = mist_passthrough };
static struct wish_rpc_server_handler manage_acl_remove_allow_handler =      { .op_str = "mist.manage.acl.removeAllow",     .handler = mist_passthrough };
static struct wish_rpc_server_handler manage_acl_add_user_roles_handler =    { .op_str = "mist.manage.acl.addUserRoles",    .handler = mist_passthrough };
static struct wish_rpc_server_handler manage_acl_remove_user_roles_handler = { .op_str = "mist.manage.acl.removeUserRoles", .handler = mist_passthrough };
static struct wish_rpc_server_handler manage_acl_user_roles_handler =        { .op_str = "mist.manage.acl.userRoles",       .handler = mist_passthrough };
static struct wish_rpc_server_handler manage_user_ensure_handler =           { .op_str = "mist.manage.user.ensure",         .handler = mist_passthrough };

// RPC enumeration
static struct wish_rpc_server_handler methods_handler =                      { .op_str = "methods",                         .handler = methods };

// MistAPI commands
static struct wish_rpc_server_handler mist_signals_handler =                 { .op_str = "signals",                         .handler = mist_signals };
static struct wish_rpc_server_handler mist_ready_handler =                   { .op_str = "ready",                           .handler = mist_ready };
static struct wish_rpc_server_handler mist_list_services_handler =           { .op_str = "listPeers",                       .handler = mist_list_services };
static struct wish_rpc_server_handler mist_sandbox_list_handler =            { .op_str = "sandbox.list",                    .handler = mist_sandbox_list };
static struct wish_rpc_server_handler mist_sandbox_remove_handler =          { .op_str = "sandbox.remove",                  .handler = mist_sandbox_remove };
static struct wish_rpc_server_handler mist_sandbox_list_peers_handler =      { .op_str = "sandbox.listPeers",               .handler = sandbox_list_peers };
static struct wish_rpc_server_handler mist_sandbox_add_peer_handler =        { .op_str = "sandbox.addPeer",                 .handler = mist_sandbox_add_peer };
static struct wish_rpc_server_handler mist_sandbox_remove_peer_handler =     { .op_str = "sandbox.removePeer",              .handler = mist_sandbox_remove_peer };
static struct wish_rpc_server_handler mist_get_service_id_handler =          { .op_str = "getServiceId",                    .handler = mist_get_service_id };

//static struct wish_rpc_server_handler mist_load_app_handler =                { .op_str = "loadApp",                         .handler = mist_load_app };

// sandbox interface
//
//   The sandbox interface is closely related to the regular mist-api interface, 
//   but is filtered according to permissions. 
static struct wish_rpc_server_handler sandbox_login_handler =                { .op_str = "sandboxed.login",                   .handler = sandbox_login };
static struct wish_rpc_server_handler sandbox_logout_handler =               { .op_str = "sandboxed.logout",                  .handler = sandbox_logout };
static struct wish_rpc_server_handler sandbox_settings_handler =             { .op_str = "sandboxed.settings",                .handler = sandbox_settings };
static struct wish_rpc_server_handler sandbox_signals_handler =              { .op_str = "sandboxed.signals",                 .handler = sandbox_signals };
static struct wish_rpc_server_handler sandbox_list_peers_handler =           { .op_str = "sandboxed.listPeers",               .handler = sandbox_list_peers };
static struct wish_rpc_server_handler sandbox_control_read_handler =         { .op_str = "sandboxed.mist.control.read",       .handler = sandbox_passthrough };
static struct wish_rpc_server_handler sandbox_control_write_handler =        { .op_str = "sandboxed.mist.control.write",      .handler = sandbox_passthrough };
static struct wish_rpc_server_handler sandbox_control_invoke_handler =       { .op_str = "sandboxed.mist.control.invoke",     .handler = sandbox_passthrough };
static struct wish_rpc_server_handler sandbox_control_follow_handler =       { .op_str = "sandboxed.mist.control.follow",     .handler = sandbox_passthrough };
static struct wish_rpc_server_handler sandbox_control_model_handler =        { .op_str = "sandboxed.mist.control.model",      .handler = sandbox_passthrough };
static struct wish_rpc_server_handler sandbox_identity_list_handler =        { .op_str = "sandboxed.wish.identity.list",      .handler = mist_get_service_id }; //sandbox_passthrough_wish };

int wish_req_id = 0;

static void identity_export_cb(rpc_client_req* req, void *ctx, uint8_t *payload, size_t payload_len) {
    WISHDEBUG(LOG_CRITICAL, "Got exported identity");
    bson_visit(payload, elem_visitor);
    
    bson_iterator it;
    
    bson_find_from_buffer(&it, payload, "data");
    
    if (bson_iterator_type(&it) != BSON_BINDATA) {
        WISHDEBUG(LOG_CRITICAL, "not bindata as expected! %i\n", bson_iterator_type(&it));
        return;
    }
    
    int data_len = bson_iterator_bin_len(&it);
    char* data = (char*) bson_iterator_bin_data(&it);
    
    if (data_len > 512) {
        WISHDEBUG(LOG_CRITICAL, "exported document too large, bail out!\n");
        return;
    }
    
    //bson_visit((uint8_t*)bson_iterator_bin_data(&it), elem_visitor);
    bson_find_from_buffer(&it, bson_iterator_bin_data(&it), "uid");
    
    if (bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) != 32) {
        WISHDEBUG(LOG_CRITICAL, " exported uid not 32 bytes of bindata as expected! %i %i\n", bson_iterator_type(&it), bson_iterator_bin_len(&it));
        return;
    }
    
    char* uid = (char*) bson_iterator_bin_data(&it);
    
    int i=0;
    
    for (i=0; i<MIST_API_MAX_UIDS; i++) {
        //WISHDEBUG(LOG_CRITICAL, "   index %i", i);
        // if occupied but has no export data
        if (identities[i].occupied != 0 && memcmp(identities[i].uid, uid, 32) == 0 ) {
            //WISHDEBUG(LOG_CRITICAL, "   found uid @ %i", i);
            identities[i].export_len = data_len;
            memcpy(identities[i].export, data, data_len);
            return;
        }
    }
}

static void update_identity_export_db(mist_api_t* mist_api) {
    //WISHDEBUG(LOG_CRITICAL, "Update identity export DB.");
    int i = 0;
    
    for (i=0; i<MIST_API_MAX_UIDS; i++) {
        //WISHDEBUG(LOG_CRITICAL, "   index %i", i);
        // if occupied but has no export data
        if ( identities[i].occupied != 0 && identities[i].export_occupied == 0 ) {
            //WISHDEBUG(LOG_CRITICAL, "   get export data %i", i);
            
            // request export data
            int buf_len = 500;
            char buf[buf_len];

            bson b;
            //bson_init_buffer(&b, buf, buf_len);
            bson_init_buffer(&b, buf, buf_len);
            bson_append_string(&b, "op", "identity.export");
            bson_append_start_array(&b, "args");
            bson_append_binary(&b, "0", identities[i].uid, 32);
            bson_append_string(&b, "1", "binary");
            bson_append_finish_array(&b);
            bson_append_int(&b, "id", ++wish_req_id);
            bson_finish(&b);

            //WISHDEBUG(LOG_CRITICAL, "sending request %i\n", wish_req_id);
            //bson_visit((uint8_t*) bson_data(&b), elem_visitor);
            
            wish_api_request(mist_api, &b, identity_export_cb);
            //return;
        }
    }
}

void identity_list_cb(rpc_client_req* req, void *ctx, uint8_t *payload, size_t payload_len) {
    WISHDEBUG(LOG_CRITICAL, "API ready! context is %p", ctx);
    //bson_visit(payload, elem_visitor);
    
    bson_iterator it;
    bson_iterator ait;
    bson_iterator sit;
    bson_find_from_buffer(&it, payload, "data");
    bson_iterator_subiterator(&it, &ait);
    bson_find_fieldpath_value("0", &ait);
    
    while ( BSON_OBJECT == bson_iterator_type(&ait) ) {

        int free = -1;
        int i = 0;
        
        for (i=0; i<MIST_API_MAX_UIDS; i++) {
            //WISHDEBUG(LOG_CRITICAL, "   index %i", i);
            // if occupied but has no export data
            if ( identities[i].occupied == 0 ) {
                free = i;
                break;
            }
        }
        
        if(free == -1) {
            WISHDEBUG(LOG_CRITICAL, "Memory full for identities. in mist_api\n");
            break;
        }
        
        //WISHDEBUG(LOG_CRITICAL, "  data.next is of type: %i\n", bson_iterator_type(&ait));
        
        bson_iterator_subiterator(&ait, &sit);
        bson_find_fieldpath_value("alias", &sit);

        if ( bson_iterator_type(&sit) == BSON_STRING ) {
            //WISHDEBUG(LOG_CRITICAL, "  alias: %s\n", bson_iterator_string(&sit));
            // FIXME this string manipulation should be cleaned up
            int len = bson_iterator_string_len(&sit);
            len = len > 31 ? 32 : len;
            memcpy(identities[free].alias, bson_iterator_string(&sit), 32);
            identities[free].alias[31] = '\0';
            identities[free].occupied = 1;
        } else {
            //WISHDEBUG(LOG_CRITICAL, "  alias is of type: %i\n", bson_iterator_type(&sit));
            continue;
        }
        
        bson_iterator_subiterator(&ait, &sit);
        bson_find_fieldpath_value("uid", &sit);

        if ( bson_iterator_type(&sit) == BSON_BINDATA && bson_iterator_bin_len(&sit) == 32 ) {
            memcpy(identities[free].uid, bson_iterator_bin_data(&sit), 32);
        } else {
            WISHDEBUG(LOG_CRITICAL, "  uid is not 32 byte bindata\n");
            continue;
        }
        
        bson_iterator_next(&ait);
    }    
    
    int buf_len = 300;
    char buf[buf_len];
    
    bson b;
    bson_init_buffer(&b, buf, buf_len);
    bson_append_string(&b, "data", "ready");
    bson_finish(&b);
    
    //wish_rpc_server_emit_broadcast(&mist_api->server, "signals", bson_data(&b), bson_size(&b));
    //wish_rpc_server_emit_broadcast(&mist_api->server, "sandboxed.signals", bson_data(&b), bson_size(&b));
    
    //update_identity_export_db(mist_api);
}

static void wish_app_ready_cb(wish_app_t* app, bool ready) {
    //WISHDEBUG(LOG_CRITICAL, "Core ready!");
    
    mist_api_t* elt = NULL;
    mist_api_t* mist_api = NULL;
    
    DL_FOREACH(mist_apis, elt) {
        if ( app == elt->wish_app ) {
            mist_api = elt;
            break;
        }
    }
    
    if (mist_api == NULL) {
        printf("==================================== MistApi not found!! Cannot continue! \n");
        return;
    }
    
    if (ready) {
        sandbox_load(mist_api);

        int buf_len = 300;
        char buf[buf_len];

        bson b;
        bson_init_buffer(&b, buf, buf_len);
        bson_append_string(&b, "op", "identity.list");
        bson_append_int(&b, "id", 1);
        bson_finish(&b);

        wish_api_request(mist_api, &b, identity_list_cb);
    } else {
        int buf_len = 300;
        char buf[buf_len];

        bson b;
        bson_init_buffer(&b, buf, buf_len);
        bson_append_string(&b, "data", "ready");
        bson_finish(&b);

        wish_rpc_server_emit_broadcast(&mist_api->server, "signals", bson_data(&b), bson_size(&b));        
        wish_rpc_server_emit_broadcast(&mist_api->server, "sandboxed.signals", bson_data(&b), bson_size(&b));        
    }
}

static void periodic_cb(void* ctx) {
    mist_api_t* mist_api = (mist_api_t*) ctx;
    //WISHDEBUG(LOG_CRITICAL, "Periodic %p", ctx);
    
    if (mist_api->periodic != NULL) {
        mist_api->periodic(mist_api->periodic_ctx);
    }
}

static void mist_api_init_rpc(mist_api_t* mist_api) {
    // FIXME this is a dirty workaround for the handlers containing the list pointers
    if (mist_api->server.list_head != NULL || methods_handler.next != NULL) {
        if ( mist_api->server.list_head == NULL ) { mist_api->server.list_head = &methods_handler; }
        return;
    }
    
    wish_rpc_server_register(&mist_api->server, &methods_handler);
    
    wish_rpc_server_register(&mist_api->server, &mist_list_services_handler);
    wish_rpc_server_register(&mist_api->server, &mist_signals_handler);
    wish_rpc_server_register(&mist_api->server, &mist_ready_handler);
    //wish_rpc_server_register(&mist_api->server, &mist_load_app_handler);
    wish_rpc_server_register(&mist_api->server, &mist_get_service_id_handler);
    
    wish_rpc_server_register(&mist_api->server, &control_read_handler);
    wish_rpc_server_register(&mist_api->server, &control_write_handler);
    wish_rpc_server_register(&mist_api->server, &control_invoke_handler);
    wish_rpc_server_register(&mist_api->server, &control_follow_handler);
    wish_rpc_server_register(&mist_api->server, &control_model_handler);
    wish_rpc_server_register(&mist_api->server, &control_map_handler);
    wish_rpc_server_register(&mist_api->server, &control_un_map_handler);
    wish_rpc_server_register(&mist_api->server, &control_notify_handler);
    wish_rpc_server_register(&mist_api->server, &control_request_mapping_handler);
    
    wish_rpc_server_register(&mist_api->server, &manage_claim_handler);
    wish_rpc_server_register(&mist_api->server, &manage_peers_handler);
    wish_rpc_server_register(&mist_api->server, &manage_acl_model_handler);
    wish_rpc_server_register(&mist_api->server, &manage_acl_allow_handler);
    wish_rpc_server_register(&mist_api->server, &manage_acl_remove_allow_handler);
    wish_rpc_server_register(&mist_api->server, &manage_acl_add_user_roles_handler);
    wish_rpc_server_register(&mist_api->server, &manage_acl_remove_user_roles_handler);
    wish_rpc_server_register(&mist_api->server, &manage_acl_user_roles_handler);
    wish_rpc_server_register(&mist_api->server, &manage_user_ensure_handler);

    wish_rpc_server_register(&mist_api->server, &mist_sandbox_list_handler);
    wish_rpc_server_register(&mist_api->server, &mist_sandbox_remove_handler);
    wish_rpc_server_register(&mist_api->server, &mist_sandbox_list_peers_handler);
    wish_rpc_server_register(&mist_api->server, &mist_sandbox_add_peer_handler);
    wish_rpc_server_register(&mist_api->server, &mist_sandbox_remove_peer_handler);
    
    wish_rpc_server_register(&mist_api->server, &sandbox_login_handler);
    wish_rpc_server_register(&mist_api->server, &sandbox_logout_handler);
    wish_rpc_server_register(&mist_api->server, &sandbox_settings_handler);
    wish_rpc_server_register(&mist_api->server, &sandbox_list_peers_handler);
    wish_rpc_server_register(&mist_api->server, &sandbox_signals_handler);
    wish_rpc_server_register(&mist_api->server, &sandbox_control_model_handler);
    wish_rpc_server_register(&mist_api->server, &sandbox_control_follow_handler);
    wish_rpc_server_register(&mist_api->server, &sandbox_control_read_handler);
    wish_rpc_server_register(&mist_api->server, &sandbox_control_write_handler);
    wish_rpc_server_register(&mist_api->server, &sandbox_control_invoke_handler);
}

static void send(void* ctx, uint8_t* buf, int len) {
    wish_app_t* app = ctx;
    wish_app_send_app_to_core(app, buf, len);
}

mist_api_t* mist_api_init(mist_app_t* mist_app) {
    mist_api_t* mist_api = wish_platform_malloc(sizeof(mist_api_t));
    memset(mist_api, 0, sizeof(mist_api_t));
    
    DL_APPEND(mist_apis, mist_api);
    
    strncpy(mist_api->server.server_name, "mist-api", MAX_RPC_SERVER_NAME_LEN);
    mist_api->server.rpc_ctx_pool = mist_api->request_pool;
    mist_api->server.rpc_ctx_pool_num_slots = MIST_API_REQUEST_POOL_SIZE;
    
    /* To access mist_api inside requests to this server (via req->server->context) */
    mist_api->server.context = mist_api;
    
    mist_api->mist_app = mist_app;
    mist_api->wish_app = mist_app->app;
    mist_api_init_rpc(mist_api);
    
    mist_api->client.send = send;
    mist_api->client.send_ctx = mist_api->wish_app;
    
    mist_api->mist_app->online = online;
    mist_api->mist_app->offline = offline;
    
    mist_api->wish_app->ready = wish_app_ready_cb;
    mist_api->wish_app->periodic = periodic_cb;
    mist_api->wish_app->periodic_ctx = mist_api;
    
    return mist_api;
}

int wish_api_request_context(mist_api_t* mist_api, bson* req, rpc_client_callback cb, void* ctx) {
    return wish_rpc_passthru_context(&mist_api->wish_app->rpc_client, req, cb, ctx);
}

int wish_api_request(mist_api_t* mist_api, bson* req, rpc_client_callback cb) {
    return wish_api_request_context(mist_api, req, cb, NULL);
}

void wish_api_request_cancel(mist_api_t* mist_api, int id) {
    wish_rpc_client_end_by_id(&mist_api->wish_app->rpc_client, id);
}

static void send_north(void* ctx, uint8_t *payload, int payload_len) {
    //mist_app(wish_ctx, (uint8_t*)bson_data(&bs), bson_size(&bs));
    struct wish_rpc_context *rpc_ctx = ctx;
    
    rpc_client_callback cb = rpc_ctx->ctx;
    
    //WISHDEBUG(LOG_CRITICAL, "Sending this northward:");
    //bson_visit(payload, elem_visitor);
    
    cb(NULL, rpc_ctx->context, payload, payload_len);
}

static void mist_api_request_cb() {
    
}

int mist_api_request_context(mist_api_t* api, bson* req, rpc_client_callback cb, void* cb_ctx) {

    bson_iterator it;
    bson_find(&it, req, "op");
    char* op = (char*)bson_iterator_string(&it);
    
    bson_find(&it, req, "args");
    char* args = (char*)bson_iterator_value(&it);
    
    bson_find(&it, req, "id");
    int id = bson_iterator_int(&it);
    
    struct wish_rpc_context_list_elem *list_elem = wish_rpc_server_get_free_rpc_ctx_elem(&api->server);
    if (list_elem == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Could not save the rpc context. Failing in mist_api.");
        wish_rpc_server_print(&api->server);
        return 0;
    } else {
        struct wish_rpc_context *rpc_ctx = &(list_elem->request_ctx);
        rpc_ctx->server = &api->server;
        rpc_ctx->send = send_north;
        rpc_ctx->send_context = rpc_ctx;
        memcpy(rpc_ctx->op_str, op, MAX_RPC_OP_LEN);
        rpc_ctx->id = id;
        rpc_ctx->ctx = cb;
        rpc_ctx->context = cb_ctx;
        
        //printf("mist_api_request_context cb %p: cb_ctx %p send_context %p\n", cb, cb_ctx, rpc_ctx);
    
        if (wish_rpc_server_handle(&api->server, rpc_ctx, args)) {
            WISHDEBUG(LOG_CRITICAL, "RPC server fail: mist_api_request");
        }
    }
    return id;
}

int mist_api_request(mist_api_t* api, bson* req, rpc_client_callback cb) {
    return mist_api_request_context(api, req, cb, NULL);
}

void mist_api_request_cancel(mist_api_t* mist_api, int id) {
    //WISHDEBUG(LOG_CRITICAL, "mist_api_request_cancel id: %i", id);
    wish_rpc_server_end(&mist_api->server, id);
}

/**

Injects sandbox_id as first argument
 
  Incoming request:
 
    { op: 'sanboxed.*', args: [arg1, args2, ...], id: n }
  
  Rewritten request should look like this:
  
    { op: 'sanboxed.*', args: [sandbox_id, arg1, args2, ...], id: n }

*/

int sandboxed_api_request_context(mist_api_t* mist_api, const char* sandbox_id, bson* req, rpc_client_callback cb, void* ctx) {
    //WISHDEBUG(LOG_CRITICAL, "sandboxed_api_request");
    
    bson_iterator it;
    bson_find(&it, req, "op");
    char* op = (char*)bson_iterator_string(&it);
    
    bson_find(&it, req, "id");
    int id = bson_iterator_int(&it);

    int buf_len = 1400;
    uint8_t buf[buf_len];
    bson b;
    bson_init_buffer(&b, buf, buf_len);

    // skip the prefix "sandboxed." from op string when forwarding request
    if (memcmp(op, "sandboxed.", 10) == 0) {
        bson_append_string(&b, "op", op);
    } else {
        return 0;
    }
    
    bson_append_start_array(&b, "args");
    bson_append_binary(&b, "0", sandbox_id, SANDBOX_ID_LEN);

    bson_iterator ait;
    bson_iterator sit;
    bson_find(&ait, req, "args");

    bool done = false;
    int i;
    int args_len = 0;
    
    // Only single digit array index supported. 
    //   i.e Do not exceed 8 with the index. Rewrite indexing if you must!
    for(i=0; i<9; i++) {
    
        char src[2];
        src[0] = 48+i;
        src[1] = '\0';

        char dst[2];
        dst[0] = 48+i+1;
        dst[1] = '\0';
        
        // init the sub iterator from args array iterator
        bson_iterator_subiterator(&ait, &sit);
        
        // read the argument
        //bson_find(&it, req, src);
        bson_type type = bson_find_fieldpath_value(src, &sit);

        // FIXME check type under iterator is valid
        switch(type) {
            case BSON_EOO:
                done = true;
                break;
            case BSON_BOOL:
                bson_append_bool(&b, dst, bson_iterator_bool(&sit));
                break;
            case BSON_INT:
                bson_append_int(&b, dst, bson_iterator_int(&sit));
                break;
            case BSON_DOUBLE:
                bson_append_double(&b, dst, bson_iterator_double(&sit));
                break;
            case BSON_STRING:
            case BSON_BINDATA:
            case BSON_OBJECT:
            case BSON_ARRAY:
                bson_append_element(&b, dst, &sit);
                break;
            default:
                WISHDEBUG(LOG_CRITICAL, "Unsupported bson type %i in mist_passthrough", type);
        }
        
        if(done) {
            break;
        } else {
            args_len++;
        }
    }
    
    bson_append_finish_array(&b);
    bson_append_int(&b, "id", id);
    bson_finish(&b);

    //WISHDEBUG(LOG_CRITICAL, "sandbox_api-request re-written:");
    //bson_visit((char*)bson_data(&b), elem_visitor);    
    
    // FIXME check sandbox validity
    return mist_api_request_context(mist_api, &b, cb, ctx);
}

void sandboxed_api_request_cancel(mist_api_t* mist_api, const char* sandbox_id, int id) {
    // FIXME check sandbox validity
    mist_api_request_cancel(mist_api, id);
}
