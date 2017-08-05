#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "wish_core.h"
#include "wish_debug.h"
#include "wish_rpc.h"
#include "bson.h"
#include "wish_io.h"
#include "wish_core_rpc.h"
#include "wish_service_registry.h"
#include "core_service_ipc.h"
#include "bson_visit.h"
#include "wish_relationship.h"
#include "wish_event.h"
#include "wish_core_signals.h"

#include "utlist.h"

void wish_send_peer_update(wish_core_t* core, struct wish_service_entry *service_entry, bool online) {
    int buffer_len = 300;
    uint8_t buffer[buffer_len];
    if (wish_service_entry_is_valid(core, service_entry)) {
        
        // TODO: support multiple protocols (protocols[0])
        if (strnlen(service_entry->protocols[0].name, WISH_PROTOCOL_NAME_MAX_LEN) > 0) {
            bson bs;
            bson_init_buffer(&bs, buffer, buffer_len);
            bson_append_start_object(&bs, "data");
            bson_append_bool(&bs, "N", true);
            bson_append_string(&bs, "type", "N");
            bson_append_start_object(&bs, "data");
            bson_append_binary(&bs, "rsid", service_entry->wsid, WISH_WSID_LEN);

            /* FIXME protocols[0][0]??? It will only include first of
             * the protocols */
            bson_append_string(&bs, "protocol", (char*) service_entry->protocols[0].name);
            bson_append_bool(&bs, "online", online);
            bson_append_finish_object(&bs);
            bson_append_finish_object(&bs);

            bson_finish(&bs);

            //WISHDEBUG(LOG_CRITICAL, "wish_core_rpc_func: wish_send_peer_update: %s", online ? "online" : "offline");
            wish_rpc_server_emit_broadcast(core->core_api, "peers", bson_data(&bs), bson_size(&bs));
        } else {
            // no protocol, no peer
            //WISHDEBUG(LOG_CRITICAL, "wish_core_rpc_func: wish_send_peer_update, no protocol no peer: %s", service_entry->name);
        }
    }
}

/**
 * Handle peers request
 * 
 * 
 * 
 *     data: {
 *          rsid: Buffer(0x16 2e 9d 73 ...)
 *          protocol: 'ucp'
 *          online: true }
 *   
 * @param req
 * @param args
 */
static void peers_op_handler(rpc_server_req* req, const uint8_t *args) {
    WISHDEBUG(LOG_DEBUG, "Handling peers request!");
    wish_core_t* core = (wish_core_t*) req->server->context;
    wish_connection_t* connection = (wish_connection_t*) req->ctx;

    int buffer_len = 300;
    uint8_t buffer[buffer_len];

    struct wish_service_entry *registry = wish_service_get_registry(core);

    int i;
    for(i=0; i < WISH_MAX_SERVICES; i++) {
        if (wish_service_entry_is_valid(core, &registry[i])) {
            // TODO: support multiple protocols (protocols[0])
            if (strnlen(registry[i].protocols[0].name, WISH_PROTOCOL_NAME_MAX_LEN) > 0) {
                
                memset(buffer, 0, buffer_len);

                bson bs;
                bson_init_buffer(&bs, buffer, buffer_len);
                bson_append_start_object(&bs, "res");
                bson_append_int(&bs, "sig", req->id);
                bson_append_start_object(&bs, "data");
                bson_append_binary(&bs, "rsid", registry[i].wsid, WISH_WSID_LEN);

                /* FIXME protocols[0][0]??? It will only include first of
                 * the protocols */
                bson_append_string(&bs, "protocol", (char*) registry[i].protocols[0].name);
                
                bson_append_bool(&bs, "online", true);
                bson_append_finish_object(&bs);
                bson_append_finish_object(&bs);

                bson_finish(&bs);

                //bson_visit("sending peers response:", (uint8_t*)bson_data(&bs));

                //WISHDEBUG(LOG_CRITICAL, "core 0x%02x%02x: wish_core_rpc_func: peers_op_handler: online", core->id[0], core->id[1]);
                wish_core_send_message(core, connection, bson_data(&bs), bson_size(&bs));
            } else {
                // no protocol, no peer
                //WISHDEBUG(LOG_CRITICAL, "wish_core_rpc_func: wish_send_peer_update, no protocol no peer: %s", registry[i].name);
            }
        }
    }
}

/**
 * This function adds information (rsid and protocol) about a remote
 * service to the wish connection context, but checks first if it exists
 * in the list or not. 
 */
static void wish_core_add_remote_service(wish_connection_t *ctx, const uint8_t rsid[WISH_WSID_LEN], const char *protocol) {
    struct wish_remote_service *tmp;
    /* Find out if we already know this peer */
    LL_FOREACH(ctx->rsid_list_head, tmp) {
        if (memcmp(tmp->rsid, rsid, WISH_WSID_LEN) == 0) {
            if (strncmp(tmp->protocol, protocol, 
                    WISH_PROTOCOL_NAME_MAX_LEN) == 0) {
                /* The peer is already known from before, and we should
                 * not add it to the list */
                return;
            }
        }
    }
    /* If we got this far, the peer is a new one */

    struct wish_remote_service *new_service
        = wish_platform_malloc(sizeof (struct wish_remote_service));
    if (new_service == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Out of memory when adding context peer!");
        return;
    }
    memcpy(new_service->rsid, rsid, WISH_WSID_LEN);
    strncpy(new_service->protocol, protocol, WISH_PROTOCOL_NAME_MAX_LEN);
    LL_APPEND(ctx->rsid_list_head, new_service);
}

/** 
 * Client callback function for 'peers' RPC request send by core RPC
 * 
 *     data: {
 *         rsid: Buffer(32),
 *         protocol: string
 *         online: boolean
 *     }
 * 
 * client to a remote core 
 */
void peers_callback(rpc_client_req* req, void* context, const uint8_t* payload, size_t payload_len) {
    wish_connection_t *connection = context;
    wish_core_t* core = req->client->context;
    
    /* When obtaining a peer response from the remote core,
     * go through the list of our local wish apps (services), and see
     * which of the protocols match the peer message's protocol field.
     * If it matches, we now have a peer to report up to the wish_app! 
     */
    /* FIXME should we be infact be supplying only "data" element to this the cb function?? */

    bson_visit("peers_callback (refactored):", payload);
    
    bson_iterator it;
    
    bson_iterator_from_buffer(&it, payload);
    
    if (bson_find_fieldpath_value("data.protocol", &it) != BSON_STRING) {
        WISHDEBUG(LOG_CRITICAL, "No data.protocol in peers_callback!");
        return;
    }
    
    const char* protocol = bson_iterator_string(&it);

    bson_iterator_from_buffer(&it, payload);
    
    if (bson_find_fieldpath_value("data.rsid", &it) != BSON_BINDATA) {
        WISHDEBUG(LOG_CRITICAL, "No data.rsid in peers_callback!");
        return;
    }
    
    const uint8_t *rsid = bson_iterator_bin_data(&it);

    bson_iterator_from_buffer(&it, payload);
    
    if (bson_find_fieldpath_value("data.online", &it) != BSON_BOOL) {
        WISHDEBUG(LOG_CRITICAL, "No data.online in peers_callback!");
        return;
    }

    bool online = bson_iterator_bool(&it);

    /* Add information about the new peer (but check first if we knew it
     * from before). This is information needs to be saved here so that
     * we can send online/offline messages to a service in case the
     * service reconnects or connection is lost */
    wish_core_add_remote_service(connection, rsid, protocol);

    
    /* Build Core-to-App message indicating the new peer */
    int l = 356;
    char buf[l];

    bson b;
    bson_init_buffer(&b, buf, l);
    bson_append_string(&b, "type", "peer");
    bson_append_start_object(&b, "peer");
    bson_append_binary(&b, "luid", connection->luid, WISH_UID_LEN);
    bson_append_binary(&b, "ruid", connection->ruid, WISH_UID_LEN);
    bson_append_binary(&b, "rhid", connection->rhid, WISH_UID_LEN);
    bson_append_binary(&b, "rsid", rsid, WISH_WSID_LEN);
    bson_append_string(&b, "protocol", protocol);
    bson_append_bool(&b, "online", online);
    bson_append_finish_object(&b);
    bson_finish(&b);

    if (b.err) {
        WISHDEBUG(LOG_CRITICAL, "bs.err in peers_callback: %s", b.errstr);
        return;
    }
    

    /* Send the peer information to all the services of this core, which
     * have the specified protocol */
    struct wish_service_entry *registry = wish_service_get_registry(core);
    if (registry == NULL) {
        WISHDEBUG(LOG_CRITICAL, "App registry is null");
        return;
    }

    int i = 0;
    
    for (i = 0; i < WISH_MAX_SERVICES; i++) {
        if (wish_service_entry_is_valid(core, &(registry[i]))) {
            //WISHDEBUG(LOG_CRITICAL, "Service entry is valid");
            if (strncmp(((const char*) &(registry[i].protocols[0].name)), protocol, WISH_PROTOCOL_NAME_MAX_LEN) == 0) {
                WISHDEBUG(LOG_CRITICAL, "core 0x%02x%02x: wish_core_rpc_func: peers_callback: %s", core->id[0], core->id[1], online ? "online" : "offline");
                
                send_core_to_app(core, registry[i].wsid, (char*)bson_data(&b), bson_size(&b));
            }
        }
    }


}

/**
 * Core to core send handler
 * 
 * Handles messages from another core, going towards a WishApp
 * 
 * args: BSON([rsid: Buffer(32), lsid: Buffer(32), payload: Buffer])
 * 
 * @param rpc_ctx
 * @param args_array
 */
static void send_op_handler(rpc_server_req* req, const uint8_t* args) {
    //bson_visit("Handling send request from remote core!", args_array);
    wish_core_t* core = req->server->context;

    bson_iterator it;
    
    bson_iterator_from_buffer(&it, args);
    
    if (bson_find_fieldpath_value("0", &it) != BSON_BINDATA) {
        WISHDEBUG(LOG_CRITICAL, "send_op_handler: Could not get rsid");
        return;
    }
    
    if (bson_iterator_bin_len(&it) != WISH_UID_LEN) {
        WISHDEBUG(LOG_CRITICAL, "send_op_handler: rsid not Buffer(32)");
        return;
    }
   
    /* The remote wsid, the originator of this message, is element "0" */
    const uint8_t *rsid = bson_iterator_bin_data(&it);
    
    bson_iterator_from_buffer(&it, args);
    
    if (bson_find_fieldpath_value("1", &it) != BSON_BINDATA) {
        WISHDEBUG(LOG_CRITICAL, "send_op_handler: Could not get lsid");
        return;
    }
    
    if (bson_iterator_bin_len(&it) != WISH_UID_LEN) {
        WISHDEBUG(LOG_CRITICAL, "send_op_handler: lsid not Buffer(32)");
        return;
    }
   
    /* Take element 1 of args_array. That is the destination wsid */
    const uint8_t *lsid = bson_iterator_bin_data(&it);

    /* The protocol is element 2 */
    bson_iterator_from_buffer(&it, args);
    
    if (bson_find_fieldpath_value("2", &it) != BSON_STRING) {
        WISHDEBUG(LOG_CRITICAL, "send_op_handler: Could not get protocol");
        return;
    }
    
    const char* protocol = bson_iterator_string(&it);

    bson_iterator_from_buffer(&it, args);
    
    if (bson_find_fieldpath_value("3", &it) != BSON_BINDATA) {
        WISHDEBUG(LOG_CRITICAL, "send_op_handler: Could not get payload");
        return;
    }
    
    const uint8_t* payload = bson_iterator_bin_data(&it);
    int32_t payload_len = bson_iterator_bin_len(&it);
    
    /* Create new document 
     * Add a type:frame element, and build a peer document:
     * { luid, ruid, rhid, rsid, protocol } and add it add peer element.
     * Then add the payload data (element 3 of args_array), as element
     * "data".
     */

    size_t buf_len = 4*WISH_ID_LEN + WISH_PROTOCOL_NAME_MAX_LEN + 100 + payload_len;
    uint8_t buf[buf_len];
    
    bson bs;
    bson_init_buffer(&bs, buf, buf_len);

    wish_connection_t* ctx = req->ctx;
    
    bson_append_string(&bs, "type", "frame");

    /* luid, ruid, rhid are obtained from the wish_context */
    bson_append_start_object(&bs, "peer");
    bson_append_binary(&bs, "luid", ctx->luid, WISH_ID_LEN);
    bson_append_binary(&bs, "ruid", ctx->ruid, WISH_ID_LEN);
    bson_append_binary(&bs, "rhid", ctx->rhid, WISH_WHID_LEN);
    bson_append_binary(&bs, "rsid", rsid, WISH_WSID_LEN);
    bson_append_string(&bs, "protocol", protocol);
    bson_append_finish_object(&bs);
    
    bson_append_binary(&bs, "data", payload, payload_len); 
    
    send_core_to_app(core, lsid, bson_data(&bs), bson_size(&bs));
}


static void core_directory(rpc_server_req* req, const uint8_t* args) {
    wish_rpc_server_error(req, 500, "Not implemented.");
}

/**
 * This is the core2core RPC server handler for the method "friendRequest"
 * 
 * @param req
 * @param args a BSON object, like this: [ 0: { data: <Buffer> cert, meta: <Buffer> transports, signatures: { } } ]
 */
static void core_friend_req(rpc_server_req* req, const uint8_t* args) {
    wish_connection_t *connection = req->ctx;
    wish_core_t *core = req->server->context;
    
    /* Get the recepient identity of the friend request */
    uint8_t *recepient_uid = connection->luid;
    uint8_t *new_friend_uid = connection->ruid;
    
    // bson_visit("args:", args);
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    if (bson_iterator_type(&it) != BSON_OBJECT) {
        WISHDEBUG(LOG_CRITICAL, "Cannot get the object '0'");
        wish_rpc_server_error(req, 501, "Bad friend request args");
        return;
    }
    
    /* Reset iterator */
    bson_iterator_from_buffer(&it, args);
    /* Find the element pointed by 0.data */
    if ( bson_find_fieldpath_value("0.data", &it) != BSON_BINDATA ) {
        WISHDEBUG(LOG_CRITICAL, "0.data not bin data");

        wish_rpc_server_error(req, 502, "friend req args does not have { data: <Buffer> }.");
        return;
    }
    
    char *cert = (char *) bson_iterator_bin_data(&it);
    
    /* Reset iterator */
    bson_iterator_from_buffer(&it, args);
    /* Find the element pointed by 0.data */
    if ( bson_find_fieldpath_value("0.meta", &it) != BSON_BINDATA ) {
        WISHDEBUG(LOG_CRITICAL, "0.meta not bin data");

        wish_rpc_server_error(req, 502, "friend req args does not have { meta: <Buffer> }.");
        return;
    }
    
    char* meta = (char*) bson_iterator_bin_data(&it);
    
    bson_iterator meta_it;
    bson_iterator_from_buffer(&meta_it, meta);
    
    if (bson_find_fieldpath_value("transports.0", &meta_it) != BSON_STRING) {
        WISHDEBUG(LOG_CRITICAL, "Friend request: no transports in meta field!");
    }
    
    /* Reset iterator */
    bson_iterator_from_buffer(&it, args);
    /* Find the element pointed by 0.data */
    if ( bson_find_fieldpath_value("0.signatures", &it) != BSON_ARRAY ) {
        WISHDEBUG(LOG_CRITICAL, "0.signatures not array");

        wish_rpc_server_error(req, 503, "friend req args does not have { signatures: [...] }.");
        return;
    }
    
    /* TODO: verify signatures */
   
    /* Start setting up a relationship request. */
    wish_relationship_req_t rel;
    
    /* Copy the RPC request context to the relationship request */
    memcpy(&(rel.friend_rpc_req), req, sizeof (rpc_server_req));
    
    strncpy(rel.luid, recepient_uid, WISH_UID_LEN);

    wish_identity_t* new_id = &rel.id;
    memset(new_id, 0, sizeof (wish_identity_t));

    bson b;
    bson_init_with_data(&b, cert);
    
    wish_identity_from_bson(new_id, &b);
    
    bson meta_bson;
    bson_init_with_data(&meta_bson, meta);
    
    wish_identity_add_meta_from_bson(new_id, &meta_bson);
    //WISHDEBUG(LOG_CRITICAL, "Transports: %s", new_id->transports[0]);

    wish_relationship_req_add(core, &rel);

    /* Save the 'id' element in payload to wish context. It will be
     * used later, if/when user accepts friend request, to retrieve
     * the friend request from "quarantine" and really add it to
     * contacts */
    //memcpy(ctx->pending_friend_req_id, friend_req_id, SIZEOF_ID)

    /* Save the recipient UID of the friend request as luid for the
     * context. This information will be used later when exporting
     * the cert */
    memcpy(connection->luid, recepient_uid, WISH_ID_LEN);
    memcpy(connection->ruid, new_id->uid, WISH_ID_LEN);

    WISHDEBUG(LOG_CRITICAL, "Friend request to luid: %02x %02x %02x %02x", connection->luid[0], connection->luid[1], connection->luid[2], connection->luid[3]);
    WISHDEBUG(LOG_CRITICAL, "Friend request from ruid: %02x %02x %02x %02x", connection->ruid[0], connection->ruid[1], connection->ruid[2], connection->ruid[3]);

    int buf_len = 1024;
    char buf[1024];

    bson bs;
    bson_init_buffer(&bs, buf, buf_len);
    bson_append_start_array(&bs, "data");
    bson_append_string(&bs, "0", "friendRequest");
    bson_append_finish_array(&bs);
    bson_finish(&bs);

    wish_core_signals_emit(core, &bs);
}

static void friend_req_callback(rpc_client_req* req, void* context, const uint8_t* payload, size_t payload_len) {
    bson_visit("Friend req callback, payload: ", payload);
    
    bson_iterator data_it;
    bson_iterator_from_buffer(&data_it, payload);
    bson_type type = bson_find_fieldpath_value("data.data", &data_it);
    if ( type != BSON_BINDATA ) {
        WISHDEBUG(LOG_CRITICAL, "Could not import friend cert, data.data not BSON_BINDATA, is type %i", type );
        return;
    }
    
    uint8_t *cert_data = (uint8_t *) bson_iterator_bin_data(&data_it);
    bson_visit("Friend req callback, cert data: ", cert_data);
         
    /* FIXME TODO: verify cert signatures */
      
    wish_identity_t new_friend_id;
    memset(&new_friend_id, 0, sizeof (wish_identity_t));

    bson b;
    bson_init_with_data(&b, cert_data);
    
    wish_identity_from_bson(&new_friend_id, &b);
    
    /* Get the meta part from data; reset iterator */
    bson_iterator_from_buffer(&data_it, payload);
    type = bson_find_fieldpath_value("data.meta", &data_it);
    if ( type != BSON_BINDATA ) {
        WISHDEBUG(LOG_CRITICAL, "Could not import friend metadata, data.meta not BSON_BINDATA, is type %i", type );
        return;
    }
    
    uint8_t *meta_data = (uint8_t *) bson_iterator_bin_data(&data_it);
    bson_visit("Friend req callback, meta data: ", cert_data);
    
    /* Add the friend request metadata to the internal identity structure */
    bson meta_bson;
    bson_init_with_data(&meta_bson, meta_data);
    wish_identity_add_meta_from_bson(&new_friend_id, &meta_bson);
    
    // Check if identity is already in db

    int num_uids_in_db = wish_get_num_uid_entries();
    wish_uid_list_elem_t uid_list[num_uids_in_db];
    int num_uids = wish_load_uid_list(uid_list, num_uids_in_db);


    bool found = false;
    int i = 0;
    for (i = 0; i < num_uids; i++) {
        if ( memcmp(&uid_list[i].uid, new_friend_id.uid, WISH_ID_LEN) == 0 ) {
            WISHDEBUG(LOG_CRITICAL, "New friend identity already in DB, we wont add it multiple times.");
            found = true;
            break;
        }
    }

    if(!found) {
        wish_save_identity_entry(&new_friend_id);
    }
}


/**
 * This function is used to send a friend request over a Wish connection to the remote core 
 * 
 * args to the RPC 'friendRequest':
 * 
 *     [ 0: {
 *        data: BSON(document),
 *        meta: BSON({ transports: ['123.234.123.234:40000'] })
 *        signatures: [ // 0..n
 *          { uid: Buffer(32), sign: Buffer(64), claim: BSON({ msg: 'This guy is good!', timestamp: Date.now(), trust: 'VERIFIED', (algo: 'sha256-ed25519') }) }
 *          { uid: Buffer(32), sign: Buffer(64), claim: BSON({ trust: 'NONE', (algo: 'sha256-ed25519') }) }
 *        ]
 *       }]
 */
void wish_core_send_friend_req(wish_core_t* core, wish_connection_t *ctx) {        
    size_t signed_cert_buffer_len = 1024;
    uint8_t signed_cert_buffer[signed_cert_buffer_len];
    bin signed_cert = { .base = signed_cert_buffer, .len = signed_cert_buffer_len };
    
    if (wish_build_signed_cert(core, ctx->luid, &signed_cert) != RET_SUCCESS) {
        WISHDEBUG(LOG_CRITICAL, "Could not construct the signed cert");
        return;
    }
    
    bson cert;
    bson_init_with_data(&cert, signed_cert.base);
    
    char buf_base[WISH_PORT_RPC_BUFFER_SZ];
    
    bin buf;
    buf.base = buf_base;
    buf.len = WISH_PORT_RPC_BUFFER_SZ;
    
    bson b;
    bson_init_buffer(&b, buf.base, buf.len);
    bson_append_start_array(&b, "args");
    bson_append_bson(&b, "0", &cert);
    bson_append_finish_array(&b);
    bson_finish(&b);
    
    bson_visit("Signed cert buffer: ", bson_data(&b));

    size_t buffer_len = 1024;
    uint8_t buffer[buffer_len];
    wish_rpc_id_t id = wish_rpc_client_bson(core->core_rpc_client, "friendRequest", (uint8_t*)bson_data(&b), bson_size(&b), friend_req_callback, buffer, buffer_len);

    rpc_client_req* mreq = find_request_entry(core->core_rpc_client, id);
    mreq->cb_context = ctx;

    bson req;
    bson_init_with_data(&req, buffer);
    
    size_t request_max_len = 1024;
    uint8_t request[request_max_len];
    
    bson bs;
    bson_init_buffer(&bs, request, request_max_len);
    bson_append_bson(&bs, "req", &req);
    bson_finish(&bs);
    
    wish_core_send_message(core, ctx, bson_data(&bs), bson_size(&bs));
}


typedef struct wish_rpc_server_handler handler;

handler core_peers_h =                                 { .op_str = "peers",                               .handler = peers_op_handler };
handler core_send_h =                                  { .op_str = "send",                                .handler = send_op_handler };
handler core_directory_h =                             { .op_str = "directory",                           .handler = core_directory };
handler core_friend_req_h =                            { .op_str = "friendRequest",                       .handler = core_friend_req };

static void wish_core_connection_send(rpc_server_req* req, const bson* bs) {
    wish_connection_t* connection = (wish_connection_t*) req->ctx;
    
    if (connection == NULL) {
        WISHDEBUG(LOG_CRITICAL, "wish_core_connection_send: The connection is null, bailing.");
        return;
    }
    
    wish_core_t* core = connection->core;
    
    const uint8_t* payload = bson_data(bs);
    int payload_len = bson_size(bs);

    bson bp;
    bson_init_with_data(&bp, payload);
    
    int buffer_len = payload_len + 128;
    uint8_t buffer[buffer_len];
    
    bson res;
    bson_init_buffer(&res, buffer, buffer_len);
    bson_append_bson(&res, "res", &bp);
    bson_finish(&res);
    
    if (res.err) {
        WISHDEBUG(LOG_CRITICAL, "BSON write error, buffer in wish_core_connection_send");
        return;
    }

    //bson_visit("actual outgoing data:", (uint8_t*)bson_data(&bs));
    //WISHDEBUG(LOG_CRITICAL, "(end)");

    wish_core_send_message(core, connection, bson_data(&res), bson_size(&res));
}

void wish_core_init_rpc(wish_core_t* core) {
    core->core_api = wish_rpc_server_init(core, wish_core_connection_send);
    wish_rpc_server_set_name(core->core_api, "core-to-core");
    wish_rpc_server_register(core->core_api, &core_peers_h);
    wish_rpc_server_register(core->core_api, &core_send_h);
    wish_rpc_server_register(core->core_api, &core_directory_h);
    
    /* Initialize core "friend request API" RPC server */
    core->friend_req_api = wish_rpc_server_init(core, wish_core_connection_send);
    wish_rpc_server_set_name(core->friend_req_api, "c2c insecure");
    wish_rpc_server_register(core->friend_req_api, &core_friend_req_h);
}

/**
 * Feed to core's RPC server. You should feed the document which is as the element 'req' 
 */
void wish_core_feed_to_rpc_server(wish_core_t* core, wish_connection_t *connection, const uint8_t *data, size_t len) {
    
    bson bs;
    bson_init_with_data(&bs, data);
    
    if (connection->friend_req_connection) {
        /* Friend request connection: Feed to the message to the special untrusted friend request RPC server */
        wish_rpc_server_receive(core->friend_req_api, connection, NULL, &bs);
    } else {
        /* Normal Wish connection: feed the message to the normal "core to core" RPC server */
        wish_rpc_server_receive(core->core_api, connection, NULL, &bs);
    }
}

/**
 * Feed to core's RPC client response handler. 
 * You should feed the document which is as the element 'res' 
 */
void wish_core_feed_to_rpc_client(wish_core_t* core, wish_connection_t *ctx, const uint8_t *data, size_t len) {
    wish_rpc_client_handle_res(core->core_rpc_client, ctx, data, len);
}

void wish_core_send_peers_rpc_req(wish_core_t* core, wish_connection_t *ctx) {
    size_t buffer_max_len = 75;
    uint8_t buffer[buffer_max_len];
    wish_rpc_id_t id = wish_rpc_client_bson(core->core_rpc_client, "peers", NULL, 0, peers_callback, buffer, buffer_max_len);

    rpc_client_req* mreq = find_request_entry(core->core_rpc_client, id);
    mreq->cb_context = ctx;
    

    bson req;
    bson_init_with_data(&req, buffer);
    
    size_t request_max_len = 256;
    uint8_t request[request_max_len];
    
    bson bs;
    bson_init_buffer(&bs, request, request_max_len);
    bson_append_bson(&bs, "req", &req);
    bson_finish(&bs);
    
    wish_core_send_message(core, ctx, bson_data(&bs), bson_size(&bs));
}

/**
 * Build and send a peer `offline` message 
 *
 * A peer becomes online, when the 'peers' request sent by the local
 * wish core returns with a list of services on the remote core. Each of
 * the remote service is a 'peer', and is reported to local services
 * with matching protocol. 
 *
 * A peer becomes offline, if
 *  -Connection to the peer's remote wish core is broken. In that case
 *  the "local" core must send the offline message to the local peer(s)
 *  which were "interested" of the remote peer.
 *  -A remote service becomes unavailable for some reason (e.g. change
 *  in ACLs, or service has shutdown). In that case the remote core will
 *  send offline messages over the Wish connection 
 *
 * Note that in contrast to online messages, offline messages do not
 * include information on the remote service id, or the protocol. 
 * The local wish core unconditionally delivers the offline message to 
 * each local service, regardless if the service got a online signal
 * before or not. FIXME this might not be the correct behaviour!
 *
 * @param ctx is the pointer to the wish connection context were luid, ruid and
 * rhid are taken. 
 *
 */
void wish_send_online_offline_signal_to_apps(wish_core_t* core, wish_connection_t *ctx, bool online) {
    struct wish_remote_service *service;
    struct wish_remote_service *tmp;
    /* Generate and send sparate peer status update messages for each
     * remote service associated with the wish context */
    LL_FOREACH_SAFE(ctx->rsid_list_head, service, tmp) {
        
        if ( strnlen(service->protocol, 5) == 0 ) {
            // no protocol, no peer
            continue;
        }
        
        /* Build Core-to-App message indicating the severed link */
        int32_t core_to_app_max_len = 288;
        uint8_t core_to_app[core_to_app_max_len];
        
        bson bs;
        bson_init_buffer(&bs, core_to_app, core_to_app_max_len);
        
        bson_append_string(&bs, "type", "peer");
        
        /* luid, ruid and rhid come from the wish context */
        bson_append_start_object(&bs, "peer");
        bson_append_binary(&bs, "luid", ctx->luid, WISH_ID_LEN);
        bson_append_binary(&bs, "ruid", ctx->ruid, WISH_ID_LEN);
        bson_append_binary(&bs, "rhid", ctx->rhid, WISH_WHID_LEN);
        bson_append_binary(&bs, "rsid", service->rsid, WISH_WSID_LEN);
        bson_append_string(&bs, "protocol", service->protocol);
        bson_append_bool(&bs, "online", online);
        bson_append_finish_object(&bs);
        bson_finish(&bs);
        
        if(bs.err) {
            WISHDEBUG(LOG_CRITICAL, "wish_send_online_offline_signal_to_apps: error encoding bson: %s", bs.errstr);
            return;
        }

        /* Send the peer offline information to all the services of this core */
        struct wish_service_entry *registry = wish_service_get_registry(core);
        if (registry == NULL) {
            WISHDEBUG(LOG_CRITICAL, "App registry is null");
            return;
        }

        int i = 0;
        for (i = 0; i < WISH_MAX_SERVICES; i++) {
            if (wish_service_entry_is_valid(core, &(registry[i]))) {
                //bson_visit("This is peer info", peer_info);
                WISHDEBUG(LOG_CRITICAL, "wish_core_rpc_func: wish_send_online_offline_signal_to_apps: (len %d)", bson_size(&bs));
                send_core_to_app(core, registry[i].wsid, bson_data(&bs), bson_size(&bs));
            }
        }

        if (online == false) {
            /* Delete service from list */
            LL_DELETE(ctx->rsid_list_head, service);
            wish_platform_free(service);
        }
    }

}

/** 
 * Clean up requests by connection context
 * 
 * This function is used to clean up the core RPC server from old requests when a connection to a remote core is severed 
 * 
 * @param core Wish Core
 * @param ctx The connection context of the severed link
 */
void wish_cleanup_core_rpc_server(wish_core_t* core, wish_connection_t *ctx) {
    struct wish_rpc_context_list_elem *list_elem = NULL;
    struct wish_rpc_context_list_elem *tmp = NULL;
    
            
    //WISHDEBUG(LOG_CRITICAL, "Core disconnect clean up client.");
    wish_rpc_client_end_by_ctx(core->core_rpc_client, ctx);

    
    LL_FOREACH_SAFE(core->core_api->request_list_head, list_elem, tmp) {
        if (list_elem->request_ctx.ctx == (void*) ctx) {
            WISHDEBUG(LOG_CRITICAL, "Core disconnect clean up: Deleting outstanding rpc request: %s", list_elem->request_ctx.op_str);
            LL_DELETE(core->core_api->request_list_head, list_elem);
#ifdef WISH_RPC_SERVER_STATIC_REQUEST_POOL
            memset(&(list_elem->request_ctx), 0, sizeof(rpc_server_req));
#else
#error not implemented
            //wish_platform_free....
#endif
        }
    }
}

