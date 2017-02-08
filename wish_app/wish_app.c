#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "mbedtls/sha256.h"
#include "ed25519.h"

#include "wish_platform.h"
#include "wish_rpc.h"
#include "wish_app.h"
#include "wish_protocol.h"
#include "wish_debug.h"
#include "app_service_ipc.h"
#include "cbson.h"
#include "bson.h"
#include "bson_visitor.h"


static wish_app_t apps[NUM_WISH_APPS];


//wish_rpc_client_t core_rpc_client;

static wish_app_t * wish_app_get_new(void) {
    int i = 0;

    for (i = 0; i < NUM_WISH_APPS; i++) {
        if (apps[i].occupied == false) {
            return &(apps[i]);
        }
    }
    /* Reached only if no free context was found */
    WISHDEBUG(LOG_CRITICAL, "Cannot get new Wish app context");
    return NULL;
}

wish_app_t * wish_app_find_by_wsid(uint8_t wsid[WISH_WSID_LEN]) {
    wish_app_t *retval = NULL;
    int i = 0;
    for (i = 0; i < NUM_WISH_APPS; i++) {
        if (apps[i].occupied == false) {
            continue;
        }
        if (memcmp(apps[i].wsid, wsid, WISH_WSID_LEN) == 0) {
            /* Found the proper app */
            retval = &(apps[i]);
            break;
        }
    }
    return retval;
}

wish_protocol_peer_t* wish_protocol_peer_find(wish_protocol_handler_t* protocol, wish_protocol_peer_t* peer) {
    int i;
    int pool_sz = protocol->peer_pool_size;
    wish_protocol_peer_t* pool = protocol->peer_pool;
    
    for (i=0; i<pool_sz; i++) {
        if ( pool[i].occupied == false ) { continue; }
        if ( memcmp(peer->luid, pool[i].luid, WISH_UID_LEN) == 0 && 
            memcmp(peer->ruid, pool[i].ruid, WISH_UID_LEN) == 0 && 
            memcmp(peer->rhid, pool[i].rhid, WISH_UID_LEN) == 0 && 
            memcmp(peer->rsid, pool[i].rsid, WISH_UID_LEN) == 0 ) 
        {
            // Found!
            return &pool[i];
        }
    }
    
    return NULL;
};

wish_protocol_peer_t* wish_protocol_peer_from_bson(wish_protocol_handler_t* protocol, uint8_t* buf) {
    bson_iterator it;
    
    wish_protocol_peer_t peer;
    
    bson_find_from_buffer(&it, buf, "luid");
    if (bson_iterator_type(&it) != BSON_BINDATA)    { return NULL; }
    if (bson_iterator_bin_len(&it) != WISH_UID_LEN) { return NULL; }
    memcpy(peer.luid, bson_iterator_bin_data(&it), WISH_UID_LEN);
    
    bson_find_from_buffer(&it, buf, "ruid");
    if (bson_iterator_type(&it) != BSON_BINDATA)    { return NULL; }
    if (bson_iterator_bin_len(&it) != WISH_UID_LEN) { return NULL; }
    memcpy(peer.ruid, bson_iterator_bin_data(&it), WISH_UID_LEN);
    
    bson_find_from_buffer(&it, buf, "rhid");
    if (bson_iterator_type(&it) != BSON_BINDATA)    { return NULL; }
    if (bson_iterator_bin_len(&it) != WISH_UID_LEN) { return NULL; }
    memcpy(peer.rhid, bson_iterator_bin_data(&it), WISH_UID_LEN);
    
    bson_find_from_buffer(&it, buf, "rsid");
    if (bson_iterator_type(&it) != BSON_BINDATA)    { return NULL; }
    if (bson_iterator_bin_len(&it) != WISH_UID_LEN) { return NULL; }
    memcpy(peer.rsid, bson_iterator_bin_data(&it), WISH_UID_LEN);
    
    bson_find_from_buffer(&it, buf, "protocol");
    if (bson_iterator_type(&it) != BSON_STRING)    { return NULL; }
    if (bson_iterator_string_len(&it) >= WISH_PROTOCOL_NAME_MAX_LEN) { return NULL; }
    strncpy(peer.protocol, bson_iterator_string(&it), WISH_PROTOCOL_NAME_MAX_LEN);


    int i;
    int free = -1;
    int pool_sz = protocol->peer_pool_size;
    wish_protocol_peer_t* pool = protocol->peer_pool;
    
    for (i=0; i<pool_sz; i++) {
        if ( pool[i].occupied == false && free == -1) { free = i; continue; }
        if ( memcmp(peer.luid, pool[i].luid, WISH_UID_LEN) == 0 && 
            memcmp(peer.ruid, pool[i].ruid, WISH_UID_LEN) == 0 && 
            memcmp(peer.rhid, pool[i].rhid, WISH_UID_LEN) == 0 && 
            memcmp(peer.rsid, pool[i].rsid, WISH_UID_LEN) == 0 ) 
        {
            // Found!
            return &pool[i];
        }
    }
    
    if(free != -1) {
        // insert at free'
        pool[free].occupied = true;
        memcpy(pool[free].luid, peer.luid, WISH_UID_LEN);
        memcpy(pool[free].ruid, peer.ruid, WISH_UID_LEN);
        memcpy(pool[free].rhid, peer.rhid, WISH_UID_LEN);
        memcpy(pool[free].rsid, peer.rsid, WISH_UID_LEN);
        strncpy(pool[free].protocol, peer.protocol, WISH_PROTOCOL_NAME_MAX_LEN);
        return &pool[free];
    }
    
    return NULL;
}

bool wish_protocol_peer_populate_from_bson(wish_protocol_peer_t* peer, uint8_t* buf) {
    bson_iterator it;
    
    wish_protocol_peer_t tmp;
    
    bson_find_from_buffer(&it, buf, "luid");
    if (bson_iterator_type(&it) != BSON_BINDATA)    { return false; }
    if (bson_iterator_bin_len(&it) != WISH_UID_LEN) { return false; }
    memcpy(tmp.luid, bson_iterator_bin_data(&it), WISH_UID_LEN);
    
    bson_find_from_buffer(&it, buf, "ruid");
    if (bson_iterator_type(&it) != BSON_BINDATA)    { return false; }
    if (bson_iterator_bin_len(&it) != WISH_UID_LEN) { return false; }
    memcpy(tmp.ruid, bson_iterator_bin_data(&it), WISH_UID_LEN);
    
    bson_find_from_buffer(&it, buf, "rhid");
    if (bson_iterator_type(&it) != BSON_BINDATA)    { return false; }
    if (bson_iterator_bin_len(&it) != WISH_UID_LEN) { return false; }
    memcpy(tmp.rhid, bson_iterator_bin_data(&it), WISH_UID_LEN);
    
    bson_find_from_buffer(&it, buf, "rsid");
    if (bson_iterator_type(&it) != BSON_BINDATA)    { return false; }
    if (bson_iterator_bin_len(&it) != WISH_UID_LEN) { return false; }
    memcpy(tmp.rsid, bson_iterator_bin_data(&it), WISH_UID_LEN);
    
    bson_find_from_buffer(&it, buf, "protocol");
    if (bson_iterator_type(&it) != BSON_STRING)    { return false; }
    if (bson_iterator_string_len(&it) >= WISH_PROTOCOL_NAME_MAX_LEN) { return false; }
    strncpy(tmp.protocol, bson_iterator_string(&it), WISH_PROTOCOL_NAME_MAX_LEN);


    memcpy(peer->luid, tmp.luid, WISH_UID_LEN);
    memcpy(peer->ruid, tmp.ruid, WISH_UID_LEN);
    memcpy(peer->rhid, tmp.rhid, WISH_UID_LEN);
    memcpy(peer->rsid, tmp.rsid, WISH_UID_LEN);
    strncpy(peer->protocol, tmp.protocol, WISH_PROTOCOL_NAME_MAX_LEN);
        
    return true;
}

wish_protocol_peer_t* wish_protocol_peer_find_from_bson(wish_protocol_handler_t* protocol, uint8_t* buf) {
    bson_iterator it;
    
    wish_protocol_peer_t peer;
    
    bson_find_from_buffer(&it, buf, "luid");
    if (bson_iterator_type(&it) != BSON_BINDATA)    { return NULL; }
    if (bson_iterator_bin_len(&it) != WISH_UID_LEN) { return NULL; }
    memcpy(peer.luid, bson_iterator_bin_data(&it), WISH_UID_LEN);
    
    bson_find_from_buffer(&it, buf, "ruid");
    if (bson_iterator_type(&it) != BSON_BINDATA)    { return NULL; }
    if (bson_iterator_bin_len(&it) != WISH_UID_LEN) { return NULL; }
    memcpy(peer.ruid, bson_iterator_bin_data(&it), WISH_UID_LEN);
    
    bson_find_from_buffer(&it, buf, "rhid");
    if (bson_iterator_type(&it) != BSON_BINDATA)    { return NULL; }
    if (bson_iterator_bin_len(&it) != WISH_UID_LEN) { return NULL; }
    memcpy(peer.rhid, bson_iterator_bin_data(&it), WISH_UID_LEN);
    
    bson_find_from_buffer(&it, buf, "rsid");
    if (bson_iterator_type(&it) != BSON_BINDATA)    { return NULL; }
    if (bson_iterator_bin_len(&it) != WISH_UID_LEN) { return NULL; }
    memcpy(peer.rsid, bson_iterator_bin_data(&it), WISH_UID_LEN);
    
    int i;
    int free = -1;
    int pool_sz = protocol->peer_pool_size;
    wish_protocol_peer_t* pool = protocol->peer_pool;
    
    for (i=0; i<pool_sz; i++) {
        if ( pool[i].occupied == false && free == -1) { free = i; continue; }
        if ( memcmp(peer.luid, pool[i].luid, WISH_UID_LEN) == 0 && 
            memcmp(peer.ruid, pool[i].ruid, WISH_UID_LEN) == 0 && 
            memcmp(peer.rhid, pool[i].rhid, WISH_UID_LEN) == 0 && 
            memcmp(peer.rsid, pool[i].rsid, WISH_UID_LEN) == 0 &&
            strncmp(protocol->protocol_name, pool[i].protocol, WISH_PROTOCOL_NAME_MAX_LEN) == 0 ) 
        {
            // Found!
            return &pool[i];
        }
    }
    
    return NULL;
}

/** Set this to 1 if you want to drop frames from non-exposed peers */
#define DROP_FRAME_FROM_UNKNOWN_PEER 0
/** Set this to 1 if you want to drop frames from peers that are marked offline */
#define DROP_FRAME_FROM_OFFLINE_PEER 0


void wish_app_on_frame(wish_app_t *app, uint8_t *frame, size_t frame_len) {
    //WISHDEBUG(LOG_DEBUG, "Frame to app");
    //bson_visit(frame, elem_visitor);

    uint8_t *peer_doc = NULL;
    int32_t peer_doc_len = 0;
    if (bson_get_document(frame, "peer", &peer_doc, &peer_doc_len)
            == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Cannot get peer from frame");
        return;
    }

    char *protocol_name = NULL;
    int32_t protocol_len = 0;
    if (bson_get_string(peer_doc, "protocol", &protocol_name, &protocol_len)
            == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Cannot get protocol elem from peer");
        return;
    }

    uint8_t *data = NULL;
    int32_t data_len = 0;
    if (bson_get_binary(frame, "data", &data, &data_len)
            == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Cannot get data element from incoming frame");
        return;
    }

    /* We now know the protocol, lets lookup the protocol handler */

    wish_protocol_handler_t* protocol = NULL;
    
    int i = 0;
    for (i = 0; i < app->num_protocols; i++) {
        if (strncmp(app->protocols[i]->protocol_name, protocol_name, WISH_PROTOCOL_NAME_MAX_LEN) == 0) {
            /* Found protocol handler */
            if (app->protocols[i]->on_frame != NULL) {
                //WISHDEBUG(LOG_CRITICAL, "Calling protocol handler");
                WISHDEBUG(LOG_DEBUG, "calling on_frame for %s with payload len: %d", protocol_name, data_len);
                protocol = app->protocols[i];
            }
            else {
                WISHDEBUG(LOG_CRITICAL, "Protocol handler is null!");
            }
            break;
        }
    }
    
    if(protocol) {
        // protocol handler found, get peer
        wish_protocol_peer_t* peer = wish_protocol_peer_find_from_bson(protocol, peer_doc);
        
        if(peer == NULL) {
#if DROP_FRAME_FROM_UNKNOWN_PEER
            WISHDEBUG(LOG_CRITICAL, "frame from unknown peer. The remote service was not exposed?");
            /* If frame is from unknown peer, drop the frame. */
            return;
#else
            /* Frame is from unknown peer, add the peer as protoocol peer anyway and pass to frame handler if addition succeeds */
            WISHDEBUG(LOG_CRITICAL, "frame from unknown peer. Adding as online protocol peer, calling online and passing frame to handler anyway");
            peer = wish_protocol_peer_from_bson(protocol, peer_doc);
            if (peer == NULL) {
                WISHDEBUG(LOG_CRITICAL, "Could not add the peer!");
                return;
            }
            peer->online = true;
            if (protocol->on_online != NULL) {
                protocol->on_online(protocol->app_ctx, peer);
            }
#endif
        } else if ( peer->online == false ) {
#if DROP_FRAME_FROM_OFFLINE_PEER
            WISHDEBUG(LOG_CRITICAL, "frame from peer which was not online. The remote service was not exposed?");
            return;
#else
            WISHDEBUG(LOG_CRITICAL, "frame from peer which was not online. Calling online and passing frame to handler anyway.");
            peer->online = true;
            if (protocol->on_online != NULL) {
                protocol->on_online(protocol->app_ctx, peer);
            }
#endif
        }
        
        protocol->on_frame(protocol->app_ctx, data, data_len, peer);
    }
}

/** Callback invoked when core has determined a change in the peer's
 * status */
void wish_app_on_peer(wish_app_t *app, uint8_t *peer_doc) {
    //WISHDEBUG(LOG_CRITICAL, "Peer information to app");
    //bson_visit(peer_doc, elem_visitor);
    
    char *protocol_name = NULL;
    int32_t protocol_len = 0;
    if (bson_get_string(peer_doc, "protocol", &protocol_name, &protocol_len)
            == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Cannot get protocol elem from peer");
        return;
    }

    bool protocol_online = false;
    if (bson_get_boolean(peer_doc, "online", &protocol_online) == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Cannot get online elem from peer");
        return;
    }
    
    /* We now know the protocol, lets lookup the protocol handler */

    wish_protocol_handler_t* protocol = NULL;
    
    int i = 0;
    for (i = 0; i < app->num_protocols; i++) {
        if (strncmp(app->protocols[i]->protocol_name, protocol_name, WISH_PROTOCOL_NAME_MAX_LEN) == 0) {
            /* Found protocol handler */
            if (app->protocols[i]->on_online != NULL || app->protocols[i]->on_offline != NULL) {
                protocol = app->protocols[i];
            } else {
                WISHDEBUG(LOG_CRITICAL, "There is no handler for online or offline messages for protocol %s, on: %p, off: %p", protocol_name, app->protocols[i]->on_online, app->protocols[i]->on_offline);
            }
            break;
        }
    }
    
    if(protocol) {
        // protocol handler found, get peer
        wish_protocol_peer_t* peer = wish_protocol_peer_from_bson(protocol, peer_doc);
        if(peer == NULL) { return; }
        
        if(peer->online != protocol_online) {
            peer->online = protocol_online;
            // there was a change in state
            if(protocol_online) {
                protocol->on_online(protocol->app_ctx, peer);
            } else {
                protocol->on_offline(protocol->app_ctx, peer);
            }
        }
    }
}

/** Callback invoked when service is connected to core */
void wish_app_on_ready(wish_app_t *app, uint8_t whid[WISH_ID_LEN]) {
    WISHDEBUG(LOG_DEBUG, "Ready signal to app");
    size_t ready_doc_max_len = 100;
    uint8_t ready_doc[ready_doc_max_len];
    memset(ready_doc, 0, ready_doc_max_len);
    bson_init_doc(ready_doc, ready_doc_max_len);
    bson_write_boolean(ready_doc, ready_doc_max_len, "ready", true);
    send_app_to_core(app->wsid, ready_doc, bson_get_doc_len(ready_doc));
    if(app->ready != NULL) {
        app->ready_state = true;
        app->ready(app, true);
    }
}

static void send(void* ctx, uint8_t* buf, int len) {
    wish_app_t* app = ctx;
    send_app_to_core(app->wsid, buf, len);
}

/** 
 * Create a wish application
 *
 * Returns the wish_app instance which was just created, or NULL if
 * error
 */
wish_app_t * wish_app_create(char *app_name) {

    uint8_t app_wsid[WISH_ID_LEN];

    if (wish_app_get_wsid(app_name, app_wsid)) {
        WISHDEBUG(LOG_CRITICAL, "Cannot get wsid for %s", app_name);
        return NULL;
    }

    wish_debug_print_array(LOG_DEBUG, "wish_app_create", app_wsid, WISH_ID_LEN);

    wish_app_t *app = wish_app_get_new();
    if (app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Fresh app context is null!");
        return NULL;
    }

    app->occupied = true;
    memcpy(app->wsid, app_wsid, WISH_WSID_LEN);
    strncpy(app->name, app_name, WISH_APP_NAME_MAX_LEN);
    /* Ensure null termination: */
    app->name[WISH_APP_NAME_MAX_LEN-1] = 0;
    
    app->rpc_client.send = send;
    app->rpc_client.send_ctx = app;

    return app;
}


/* Login:
 * App to core: { name: 'Chat CLI',
 *   protocols: [ 'chat' ],
 *     permissions: [ 'identity.list', 'services.listPeers' ] }
 */
void wish_app_login(wish_app_t *app) {
    
    int i = 0;

    const size_t login_msg_max_len = 255;
    uint8_t login_msg[login_msg_max_len];
    
    bson bs;
    bson_init_buffer(&bs, login_msg, login_msg_max_len);
    bson_append_binary(&bs, "wsid", app->wsid, WISH_WSID_LEN);
    bson_append_string(&bs, "name", app->name);
    bson_append_start_array(&bs, "protocols");

    #define NBUFL 8
    uint8_t pbuf[NBUFL];
    for (i = 0; i < app->num_protocols; i++) {
        bson_numstrn(pbuf, NBUFL, i);
        bson_append_string(&bs, pbuf, app->protocols[i]->protocol_name);
    }

    bson_append_finish_array(&bs);
    bson_append_start_array(&bs, "permissions");

    /* requesting permissions not yet supported
    for (i = 0; i < app->num_permissions; i++) {
        bson_numstrn((char *)nbuf, NBUFL, i);
        bson_append_string(&bs, nbuf, *(app->permissions[i]));
    }
    */
    
    bson_append_finish_array(&bs);
    bson_finish(&bs);
    
    //bson_visit(login_msg, elem_visitor);
    
    if (bs.err) {
        WISHDEBUG(LOG_CRITICAL, "BSON error in wish_app_create");
    }
    
    send_app_to_core(app->wsid, login_msg, bson_size(&bs));
    
    /*
     * RPC app to core { op: 'identity.list', id: 1 }
     */

    /* Then, upon RPC reply: 
     *
     * App to core: { ready: true }
     */
}

void wish_app_add_protocol(wish_app_t *app, wish_protocol_handler_t *handler) {
    /* Set up protocols */
    if (app->num_protocols < WISH_APP_MAX_PROTOCOLS) {
        app->protocols[app->num_protocols] = handler;
        // WishApp: Added protocol %s at index %d", handler->protocol_name, app->num_protocols
        handler->peer_pool_size = WISH_APP_PROTOCOL_PEERS_MAX;
        handler->peer_pool = handler->peer_pool_data;
#if 0        
        handler->peer_pool = malloc(sizeof(wish_protocol_peer_t)*WISH_APP_PROTOCOL_PEERS_MAX);
        if(handler->peer_pool == NULL) {
            WISHDEBUG(LOG_CRITICAL, "WishApp: Error allocating peer_pool memory for %s.", handler->protocol_name);
            exit(1);
        }
        memset(handler->peer_pool, 0, sizeof(wish_protocol_peer_t)*WISH_APP_PROTOCOL_PEERS_MAX);
#endif
        app->num_protocols++;
    } else {
        WISHDEBUG(LOG_CRITICAL, "WishApp: Error adding protocol %s, memory full.", handler->protocol_name);
    }
}

/**
 * Disconnect a Wish app from the core, release app context
 * @param app pointer to app context object to be deleted
 */
void wish_app_destroy(wish_app_t *app) {
    WISHDEBUG(LOG_CRITICAL, "in wish_app_destroy");
}



/**
 * Get WSID correspoinding to app_name, storing it to array wsid
 *
 * Returns 0 on success
 */
int wish_app_get_wsid(char *app_name, uint8_t wsid[WISH_ID_LEN]) {
#if 0
    /* Just generate a wsid by first hashing the app name (to form 32
     * bytes), which is used as seed to ed25519 create keypair - note
     * that under this scheme the wsid will always be the same for any 
     * given app_name string. */
    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0); 
    mbedtls_sha256_update(&sha256_ctx, (const unsigned char *)app_name, 
        strnlen(app_name, WISH_APP_NAME_MAX_LEN)); 
    uint8_t seed[WISH_ED25519_SEED_LEN];
    mbedtls_sha256_finish(&sha256_ctx, seed);
    mbedtls_sha256_free(&sha256_ctx);

    uint8_t service_pubkey[WISH_PUBKEY_LEN];
    uint8_t service_privkey[WISH_PRIVKEY_LEN];
    ed25519_create_keypair(service_pubkey, service_privkey, seed);
#endif

    memset(wsid, 0, WISH_ID_LEN);
    strncpy(wsid, app_name, WISH_ID_LEN);
    return 0;
}


void wish_app_determine_handler(wish_app_t *app, uint8_t *data, size_t len) {
    char* type_str = NULL;
    int32_t type_str_len = 0;
    if (bson_get_string(data, "type", &type_str, &type_str_len) 
            == BSON_SUCCESS) {
        if (strncmp(type_str, "signal", type_str_len) == 0) {
            /* Is a signal */
            char *signal_str = NULL;
            int32_t signal_str_len = 0;
            if (bson_get_string(data, "signal", &signal_str, &signal_str_len) 
                == BSON_SUCCESS) {
                if (strncmp(signal_str, "ready", signal_str_len) == 0) {
                    /* Ready signal */
                    uint8_t whid[WISH_WHID_LEN] = { 0 };
                    wish_app_on_ready(app, whid);
                }
                else if (strncmp(signal_str, "quarantine", signal_str_len) == 0) {
                    WISHDEBUG(LOG_CRITICAL, "We ended up in Ellis island. (Quarantined!)");
                }
                else {
                    WISHDEBUG(LOG_CRITICAL, "Unrecognized signal from core");

                }
            }
        }
        else if (strncmp(type_str, "peer", type_str_len) == 0) {
            uint8_t *peer_info_doc = NULL;
            int32_t peer_info_doc_len = 0;
            if (bson_get_document(data, "peer", &peer_info_doc,
                    &peer_info_doc_len) == BSON_FAIL) {

                WISHDEBUG(LOG_CRITICAL, "Failed to get peer info doc");
                return;
            }

            wish_app_on_peer(app, peer_info_doc);
        }
        else if (strncmp(type_str, "frame", type_str_len) == 0) {
            /* Frame */
            wish_app_on_frame(app, data, len);
        }
    }
    else {
        int32_t ack = 0, err = 0;
        //WISHDEBUG(LOG_CRITICAL, "No type in core to app, len=%d", len);
        //bson_visit(data, elem_visitor);

        if (bson_get_int32(data, "ack", &ack) == BSON_SUCCESS || 
                bson_get_int32(data, "err", &err) == BSON_SUCCESS) {
            /* I recon this is an RPC request reply, an ack or err to a
             * request that we sent using wish_app_send! */
            if (wish_rpc_client_handle_res(&app->rpc_client, NULL, data, bson_get_doc_len(data))) {
                WISHDEBUG(LOG_CRITICAL, "RPC Client did not find a matching request.");
            }
        }
        else {
            WISHDEBUG(LOG_CRITICAL, "No ack or err in reponse!");
        }

    }
}

/** Function for sending an App RPC frame. Will in turn call send_app_to_core
 * in the serivice IPC layer
 *
 * @param app pointer to relevant Wish App struct
 * @param peer the peer (in BSON format)
 * @param peer_len the length of the peer doc
 * @param buffer the data to be sent down
 * @param len the length of the buffer
 * @param cb an optional callback which will be invoked when the RPC
 * request over Service IPC layer to core returns. Can be NULL if no cb
 * is needed
 * @return the RPC id of the message send downwards, or 0 for an error
 */
wish_rpc_id_t wish_app_send(wish_app_t *app, wish_protocol_peer_t* peer, 
    uint8_t *buffer, size_t len, rpc_client_callback cb) {

    // Call send_app_to_core as in app.js:send, like this:
    // this.coreClient.rpc('services.send', [peer, payload], cb);
    
    int args_len = 0;
    int frame_len_max = len + 512;
    uint8_t args[frame_len_max];
    
    bson bs;
    bson_init_buffer(&bs, args, frame_len_max);
    
    bson_append_start_array(&bs, "args");
    bson_append_start_object(&bs, "0");
    bson_append_binary(&bs, "luid", peer->luid, WISH_UID_LEN);
    bson_append_binary(&bs, "ruid", peer->ruid, WISH_UID_LEN);
    bson_append_binary(&bs, "rhid", peer->rhid, WISH_UID_LEN);
    bson_append_binary(&bs, "rsid", peer->rsid, WISH_UID_LEN);
    bson_append_string(&bs, "protocol", peer->protocol);
    bson_append_finish_object(&bs);
    bson_append_binary(&bs, "1", buffer, len);
    bson_append_finish_array(&bs);
    bson_finish(&bs);
    
    //WISHDEBUG(LOG_CRITICAL,"wish_app_send: BSON Dump\n");
    //bson_visit(buffer, elem_visitor);
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "args");
    char* v = (char*)bson_iterator_value(&it);
    
    int frame_len = frame_len_max + MAX_RPC_OP_LEN + 128;
    uint8_t* frame = wish_platform_malloc(frame_len);
    if (frame == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Out of memory, frame wish_app_send");
        return 0;
    }
    
    wish_rpc_id_t service_rpc_id = wish_rpc_client(&app->rpc_client, 
        "services.send", v, bson_get_doc_len(v), cb, frame, frame_len);

    send_app_to_core(app->wsid, frame, bson_get_doc_len(frame));
    wish_platform_free(frame);
    
    return service_rpc_id;
}


/*

Call send_app_to_core as in app.js:send, like this:
this.coreClient.rpc(op, args, cb);

Usage:

    void identity_list_cb(void *ctx, wish_rpc_id_t id, uint8_t *payload, size_t payload_len) {
        WISHDEBUG(LOG_CRITICAL, "response to identity_list request: wish_app_core %i", payload_len);
        bson_visit(payload, elem_visitor);
    }
   
    bson bs; 
    bson_init(&bs);
    bson_append_start_array(&bs, "args");
    bson_append_bool(&bs, "0", true);
    bson_append_string(&bs, "1", "complex");
    bson_append_int(&bs, "2", 2);
    bson_append_start_object(&bs, "3");
    bson_append_string(&bs, "complex", "trem");
    bson_append_finish_object(&bs);
    bson_append_finish_array(&bs);
    bson_finish(&bs);
    
    bson_iterator it;
    bson_find_from_buffer(&it, bs.data, "args");
    
    // init an iterator to the first element in the bson array value, skip first 
    //   4 bytes, it contains total length of content
    char* args = (char*)(bson_iterator_value(&it) + 4);
    const char* p0 = it.cur;
    bson_iterator_next(&it);
    int size = (int)(it.cur - p0);

    WISHDEBUG(LOG_CRITICAL, "wish_app_core %i", size);
    bson_visit(args, elem_visitor);
    
    wish_app_core(app, "identity.list", args, size, identity_list_cb);
  
*/

wish_rpc_id_t wish_app_core(wish_app_t *app, char* op, uint8_t *buffer, size_t len, rpc_client_callback cb) {
   
    int frame_len = len + MAX_RPC_OP_LEN + 128;
    uint8_t* frame = wish_platform_malloc(frame_len);
    if (frame == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Out of memory, frame in wish_app_core");
        return 0;
    }
    
    wish_rpc_id_t service_rpc_id = wish_rpc_client_bson(&app->rpc_client, op, buffer, len, cb, frame, frame_len);

    send_app_to_core(app->wsid, frame, bson_get_doc_len(frame));
    wish_platform_free(frame);
    
    return service_rpc_id;
}

/* This is a copy of function wish_app_core, to be used in the situation where we have core and app in the same process, and core RPC callbacks are executed synchronosly */
wish_rpc_id_t wish_app_core_with_cb_context(wish_app_t *app, char* op, uint8_t *buffer, size_t len, rpc_client_callback cb, void* cb_ctx) {
   
    int frame_len = len + MAX_RPC_OP_LEN + 128;
    uint8_t* frame = wish_platform_malloc(frame_len);
    if (frame == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Out of memory, frame in wish_app_core");
        return 0;
    }
    
    wish_rpc_id_t service_rpc_id = wish_rpc_client_bson(&app->rpc_client, op, buffer, len, cb, frame, frame_len);
    wish_rpc_client_set_cb_context(&app->rpc_client, service_rpc_id, cb_ctx);
    
    send_app_to_core(app->wsid, frame, bson_get_doc_len(frame));
    wish_platform_free(frame);
    
    return service_rpc_id;
}

void wish_app_send_app_to_core(wish_app_t* app, uint8_t* frame, int frame_len) {
    send_app_to_core(app->wsid, frame, frame_len);
}


void wish_app_connected(wish_app_t *app, bool connected) {
    if (connected) {
        //WISHDEBUG(LOG_CRITICAL, "App is connected");
        wish_app_login(app);
    } else {
        WISHDEBUG(LOG_CRITICAL, "App is disconnected!");
        app->ready_state = false;
        app->ready(app, app->ready_state);
    }
}

void wish_app_periodic(wish_app_t* app) {
    if(app->periodic != NULL) {
        app->periodic(app->periodic_ctx);
    }
}