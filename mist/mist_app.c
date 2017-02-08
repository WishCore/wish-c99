#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "cbson.h"
#include "wish_debug.h"
#include "wish_rpc.h"
#include "wish_app.h"
#include "mist_follow.h"
#include "mist_app.h"
#include "mist_handler.h"
#include "mist_mapping.h"

#include "bson_visitor.h"

mist_app_t mist_apps[NUM_MIST_APPS];

mist_app_t *mist_app_get_new_context(void) {
    mist_app_t *new_ctx = NULL;
    int i = 0;
    for (i = 0; i < NUM_MIST_APPS; i++) {
        if (mist_apps[i].occupied == false) {
            mist_apps[i].occupied = true;
            new_ctx = &(mist_apps[i]);
            break;
        }
    }
    return new_ctx;
}

static int ucp_online(void *app_ctx, wish_protocol_peer_t* peer) {
    //WISHDEBUG(LOG_CRITICAL, "in ucp_online %p luid: %02x %02x %02x %02x ruid:  %02x %02x %02x %02x", peer, peer->luid[0], peer->luid[1], peer->luid[2], peer->luid[3], peer->ruid[0], peer->ruid[1], peer->ruid[2], peer->ruid[3]);
    
    mist_app_t *mist_app_ctx = app_ctx;
    
    if(mist_app_ctx->online != NULL) {
        mist_app_ctx->online(app_ctx, peer);
    }

    return 0;
}

static int ucp_offline(void *app_ctx, wish_protocol_peer_t* peer) {
    //WISHDEBUG(LOG_CRITICAL, "in ucp_offline %p", peer);

    mist_app_t *mist_app = app_ctx;
    
    if(mist_app->offline != NULL) {
        mist_app->offline(app_ctx, peer);
    }
    
    wish_rpc_server_end_by_ctx(&mist_app->device_rpc_server, peer);
    
    return 0;
}

/* Handle a Mist frame which has been received by the ucp protocol
 * 'on_frame' callback */
void handle_mist_message(mist_app_t *mist_app, uint8_t* data, int data_len, wish_protocol_peer_t* peer) {
    receive_device_northbound(mist_app, data, data_len, peer);
}

static int ucp_frame_received(void *app_ctx, uint8_t *data, size_t data_len, wish_protocol_peer_t* peer) {
    mist_app_t *mist_app_ctx = app_ctx;
    
    handle_mist_message(mist_app_ctx, data, data_len, peer);
    return 0;
}

// expect ctx to be app_peer_t, and send data to the peer of this app. This will
// call services.send and send in case of a remote device
static void send_to_peer(void* ctx, uint8_t* buf, int buf_len) {
    app_peer_t* app_peer = ctx;    
    wish_app_send(app_peer->app, app_peer->peer, buf, buf_len, NULL);
}

#define REQUEST_POOL_SIZE 10
static struct wish_rpc_context_list_elem request_pool[REQUEST_POOL_SIZE];

mist_app_t *start_mist_app() {
    mist_app_t *ctx = mist_app_get_new_context();
    if (ctx == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Could not instantiate new Mist App!");
        return NULL;
    }

    // set a default name, override using mist_set_name
    strncpy(ctx->name, "Node", MIST_APP_NAME_MAX_LEN);

    memcpy(ctx->ucp_handler.protocol_name, "ucp", WISH_PROTOCOL_NAME_MAX_LEN);

    ctx->ucp_handler.on_online = ucp_online,
    ctx->ucp_handler.on_offline = ucp_offline,
    ctx->ucp_handler.on_frame = ucp_frame_received,
    ctx->ucp_handler.app_ctx = ctx; /* Saved here so that the online, frame callbacks will receive the appropriate Mist app context */
    
    ctx->ucp_handler.rpc_client.send = send_to_peer;
    // FIXME this peer context is sent each time before calling send. This way 
    //   the rpc_client can be reused for all rpc calls to other nodes. In the
    //   node.js implementation there is one rpc_client for each peer, which is
    //   the "right way" to do it.
    //ctx->ucp_handler.rpc_client.send_ctx = peer;

    strncpy(ctx->device_rpc_server.server_name, "app/mist", MAX_RPC_SERVER_NAME_LEN);
    ctx->device_rpc_server.context = ctx;
    ctx->device_rpc_server.request_list_head = NULL;
    
#ifdef WISH_RPC_SERVER_STATIC_REQUEST_POOL
    ctx->device_rpc_server.rpc_ctx_pool = request_pool;
    ctx->device_rpc_server.rpc_ctx_pool_num_slots = REQUEST_POOL_SIZE;
#else
#error not implemented
#endif

    mist_device_setup_rpc_handlers(&(ctx->device_rpc_server));

    /* FIXME intialise the Mist model name to be same as the app's name */
    ctx->model.name = ctx->name;
    /* FIXME the name separately as above is redundant id app pointer is saved */
    ctx->model.mist_app = ctx;
    
    ctx->model.custom_ui_url = NULL;

    return ctx;
}

void mist_set_name(mist_app_t *ctx, char* name) {
    strncpy(ctx->name, name, MIST_APP_NAME_MAX_LEN);
    ctx->name[MIST_APP_NAME_MAX_LEN-1] = 0;  /* Ensure null terminate */
}

/* This function is called by the device's RPC server when it
 * needs to send a reply to an RPC request */
wish_rpc_id_t receive_device_southbound(mist_app_t *mist_app, uint8_t *reply_doc, size_t reply_doc_actual_len, wish_protocol_peer_t* peer, rpc_client_callback cb) {
    WISHDEBUG(LOG_DEBUG, "receive_device_southbound");
    /** The RPC id of the message which is sent down */
    wish_rpc_id_t id = -1;
    if (reply_doc_actual_len > 0) {
        if (reply_doc_actual_len != bson_get_doc_len(reply_doc)) {
            WISHDEBUG(LOG_CRITICAL, "Wish app send fail, doc len mismatch");
            return -1;
        }

        id = wish_app_send(mist_app->app, peer, reply_doc, bson_get_doc_len(reply_doc), cb);
        if (id < 0) {
            WISHDEBUG(LOG_CRITICAL, "Wish app send fail");
        }
    }
    WISHDEBUG(LOG_DEBUG, "exiting receive_device_southbound");
    return id;
}

wish_rpc_id_t mist_app_request(mist_app_t *mist_app, wish_protocol_peer_t* peer, uint8_t *request, size_t request_len, rpc_client_callback cb) {
    bson_iterator it;
    bson_find_from_buffer(&it, request, "op");
    char* op = (char*)bson_iterator_string(&it);
    
    int buf_len = 1400;
    char buf[buf_len];
    
    wish_rpc_client_bson(&mist_app->ucp_handler.rpc_client, op, request, request_len, cb, buf, buf_len);

    // dont use buf_len, read size of doc
    
    bson bs;
    bson_init_buffer(&bs, buf, buf_len);
    
    wish_app_send(mist_app->app, peer, buf, bson_size(&bs), NULL);
    
    return 0;
}

mist_app_t *mist_app_lookup_by_wsid(uint8_t *wsid) {
    mist_app_t *app_ctx = NULL;
    int i = 0;
    for (i = 0; i < NUM_MIST_APPS; i++) {
        if (mist_apps[i].occupied == false) {
            continue;
        }
        if (memcmp(mist_apps[i].app->wsid, wsid, WISH_WSID_LEN) == 0) {
            app_ctx = &(mist_apps[i]);
            break;
        }
    }

    return app_ctx;
}
