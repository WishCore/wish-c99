#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "wish_core.h"
#include "wish_debug.h"
#include "wish_rpc.h"
#include "cbson.h"
#include "bson.h"
#include "wish_io.h"
#include "wish_core_rpc_func.h"
#include "wish_service_registry.h"
#include "core_service_ipc.h"
#include "bson_visitor.h"
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

static void peers_op_handler(struct wish_rpc_context *rpc_ctx, uint8_t *args_array) {
    WISHDEBUG(LOG_DEBUG, "Handling peers request!");
    wish_core_t* core = (wish_core_t*) rpc_ctx->server->context;
    wish_connection_t* connection = (wish_connection_t*) rpc_ctx->ctx;

    int buffer_len = 300;
    uint8_t buffer[buffer_len];
    
    /* Get list of wish_apps (services) on this node */

#if 0
    /* For each identity: */
    struct wish_service_entry *registry = wish_service_get_registry();
    int i = 0;
    for (i = 0; i < WISH_MAX_SERVICES; i++) {
        if (wish_service_entry_is_valid(&(registry[i]))) {
            const size_t data_doc_max_len = 50;
            uint8_t data_doc[peer_data_doc_max_len];
            WISHDEBUG(LOG_CRITICAL, "Adding service");
            bson_init_doc(data_doc, data_doc_max_len);

        }
    }
    
    res: {
        sig: 0
        data: {
            N: true
            type: 'N'
            data: {
                rsid: Buffer(0x16 2e 9d 73 ...)
                protocol: 'ucp'
                online: true
    
#endif

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
                bson_append_int(&bs, "sig", rpc_ctx->id);
                bson_append_start_object(&bs, "data");
                bson_append_bool(&bs, "N", true);
                bson_append_string(&bs, "type", "N");
                bson_append_start_object(&bs, "data");
                bson_append_binary(&bs, "rsid", registry[i].wsid, WISH_WSID_LEN);

                /* FIXME protocols[0][0]??? It will only include first of
                 * the protocols */
                bson_append_string(&bs, "protocol", (char*) registry[i].protocols[0].name);
                
                bson_append_bool(&bs, "online", true);
                bson_append_finish_object(&bs);
                bson_append_finish_object(&bs);
                bson_append_finish_object(&bs);

                bson_finish(&bs);

                //bson_visit("sending peers response:", (uint8_t*)bson_data(&bs));

                WISHDEBUG(LOG_CRITICAL, "core 0x%02x%02x: wish_core_rpc_func: peers_op_handler: online", core->id[0], core->id[1]);
                wish_core_send_message(core, connection, (char*)bson_data(&bs), bson_size(&bs));
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
 * in the list or not. */
static void wish_core_add_remote_service(wish_connection_t *ctx, 
        uint8_t rsid[WISH_WSID_LEN], char *protocol) {
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

/** Client callback function for 'peers' RPC request send by core RPC
 * client to a remote core */
void peers_callback(rpc_client_req* req, void *context, uint8_t *payload, size_t payload_len) {
    wish_connection_t *connection = context;
    wish_core_t* core = req->client->context;
    
    /* When obtaining a peer response from the remote core,
     * go through the list of our local wish apps (services), and see
     * which of the protocols match the peer message's protocol field.
     * If it matches, we now have a peer to report up to the wish_app! 
     */
    /* FIXME should we be infact be supplying only "data" element to this the cb function?? */

    uint8_t *outer_data_doc = NULL;
    int32_t outer_data_doc_len = 0;
    if (bson_get_document(payload, "data", &outer_data_doc, &outer_data_doc_len) == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "No outer 'data' document");
        return;
    }

    char *type_str = NULL;
    int32_t type_str_len = 0;
    if (bson_get_string(outer_data_doc, "type", &type_str, &type_str_len) == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "No 'type' in peer document");
        return;
    }
    
    uint8_t *inner_data_doc = NULL;
    int32_t inner_data_doc_len = 0;
    if (bson_get_document(outer_data_doc, "data", &inner_data_doc, &inner_data_doc_len) == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "No inner 'data' document");
        return;
    }

    uint8_t *rsid = NULL;
    int32_t rsid_len = 0;
    if (bson_get_binary(inner_data_doc, "rsid", &rsid, &rsid_len) == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "No rsid in inner 'data' document");
        return;
    }

    char *protocol = NULL;
    int32_t protocol_len = 0;
    if (bson_get_string(inner_data_doc, "protocol", &protocol, &protocol_len) == BSON_FAIL) {
        bson_visit("peers_callback: No protocol in inner 'data' document", payload);
        return;
    }

    bool online = false;
    if ( strncmp(type_str, "D", 2) == 0 ) {
        // this peer has been deleted (not only offline)
    } else {
        if (bson_get_boolean(inner_data_doc, "online", &online)
                == BSON_FAIL) {
            WISHDEBUG(LOG_CRITICAL, "No online information");
            return;

        }
    }

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

static void send_op_handler(struct wish_rpc_context *rpc_ctx, uint8_t *args_array) {
    //bson_visit("Handling send request from remote core!", args_array);
    wish_core_t* core = rpc_ctx->server->context;

   
    /* The remote wsid, the originator of this message, is element "0" */
    uint8_t *rsid = NULL;
    int32_t rsid_len = 0;
    if (bson_get_binary(args_array, "0", &rsid, &rsid_len)
            == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Could not get rsid");
        return;
    }

    /* Take element 1 of args_array. That is the destination wsid */
    uint8_t *dst_wsid = NULL;
    int32_t dst_wsid_len = 0;
    if (bson_get_binary(args_array, "1", &dst_wsid, &dst_wsid_len) 
            == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Could not get destination wsid");
        return;

    }
 

    /* The protocol is element 2 */
    char *protocol = NULL;
    int32_t protocol_len = 0;
    if (bson_get_string(args_array, "2", &protocol, &protocol_len)
            == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Could not get protocol");
        return;
    }

    /* Create new document 
     * Add a type:frame element, and build a peer document:
     * { luid, ruid, rhid, rsid, protocol } and add it add peer element.
     * Then add the payload data (element 3 of args_array), as element
     * "data".
     */

    /* luid, ruid, rhid are obtained from the wish_context */
    size_t peer_doc_max_len = 2*WISH_ID_LEN + WISH_WSID_LEN + WISH_WHID_LEN
        + WISH_PROTOCOL_NAME_MAX_LEN + 100;
    uint8_t peer_doc[peer_doc_max_len];
    bson_init_doc(peer_doc, peer_doc_max_len);

    wish_connection_t* ctx = rpc_ctx->ctx;
    
    bson_write_binary(peer_doc, peer_doc_max_len, "luid", ctx->luid, WISH_ID_LEN);
    bson_write_binary(peer_doc, peer_doc_max_len, "ruid", ctx->ruid, WISH_ID_LEN);
    bson_write_binary(peer_doc, peer_doc_max_len, "rhid", ctx->rhid, WISH_WHID_LEN);
    bson_write_binary(peer_doc, peer_doc_max_len, "rsid", rsid, WISH_WSID_LEN);
    bson_write_string(peer_doc, peer_doc_max_len, "protocol", protocol);

    uint8_t *payload = NULL;
    int32_t payload_len = 0;
    if (bson_get_binary(args_array, "3", &payload, &payload_len) 
            == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Could not get payload");
        return;
    }
    
    size_t upcall_doc_max_len = peer_doc_max_len + payload_len + 100;
    uint8_t upcall_doc[upcall_doc_max_len];
    bson_init_doc(upcall_doc, upcall_doc_max_len);
    
    bson_write_string(upcall_doc, upcall_doc_max_len, "type", "frame");
    bson_write_embedded_doc_or_array(upcall_doc, upcall_doc_max_len,
        "peer", peer_doc, BSON_KEY_DOCUMENT);

    bson_write_binary(upcall_doc, upcall_doc_max_len, "data", payload, payload_len); 
    
    send_core_to_app(core, dst_wsid, upcall_doc, bson_get_doc_len(upcall_doc));
}


static void core_directory(rpc_server_req* req, uint8_t* args) {
    wish_rpc_server_error(req, 500, "Not implemented.");
}

/**
 * This is the core2core RPC server handler for the method "friendRequest"
 * 
 * @param req
 * @param args a BSON object, like this: [ 0: { data: <Buffer> cert, meta: <Buffer> transports, signatures: { } } ]
 */
static void core_friend_req(rpc_server_req* req, uint8_t* args) {
    wish_connection_t *connection = req->send_context;
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
    
    if (bson_find_fieldpath_value("transports.0", &meta_it) == BSON_STRING) {
        WISHDEBUG(LOG_CRITICAL, "Found transports array in meta field! %s", bson_iterator_string(&meta_it));
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

    wish_populate_id_from_cert(new_id, cert);

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

static void friend_req_callback(rpc_client_req* req, void *context, uint8_t *payload, size_t payload_len) {
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

    wish_populate_id_from_cert(&new_friend_id, cert_data);
    
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
 [ 0: {
  data: BSON(document),
  meta: BSON({ transports: ['123.234.123.234:40000'] })
  signatures: [ // 0..n
    { uid: Buffer(32), sign: Buffer(64), claim: BSON({ msg: 'This guy is good!', timestamp: Date.now(), trust: 'VERIFIED', (algo: 'sha256-ed25519') }) }
    { uid: Buffer(32), sign: Buffer(64), claim: BSON({ trust: 'NONE', (algo: 'sha256-ed25519') }) }
  ]
 }]
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
    
    size_t request_max_len = 1024;
    uint8_t request[request_max_len];
    
    bson_init_doc(request, request_max_len);
    bson_write_embedded_doc_or_array(request, request_max_len, "req", buffer, BSON_KEY_DOCUMENT);
    wish_core_send_message(core, ctx, request, bson_get_doc_len(request));
}




typedef struct wish_rpc_server_handler handler;

handler core_directory_h =                             { .op_str = "directory",                           .handler = core_directory };
handler core_friend_req_h =                            { .op_str = "friendRequest",                       .handler = core_friend_req };

void wish_core_init_rpc(wish_core_t* core) {
    core->core_api = wish_platform_malloc(sizeof(wish_rpc_server_t));
    memset(core->core_api, 0, sizeof(wish_rpc_server_t));
    
    core->core_api->request_list_head = NULL;
    core->core_api->rpc_ctx_pool = wish_platform_malloc(sizeof(struct wish_rpc_context_list_elem)*10);
    memset(core->core_api->rpc_ctx_pool, 0, sizeof(struct wish_rpc_context_list_elem)*10);
    core->core_api->rpc_ctx_pool_num_slots = 10;
    
    strncpy(core->core_api->server_name, "core-to-core", 13);
    core->core_api->context = core;
    
    wish_rpc_server_add_handler(core->core_api, "peers", peers_op_handler);
    wish_rpc_server_add_handler(core->core_api, "send", send_op_handler);
    wish_rpc_server_register(core->core_api, &core_directory_h);
    
    /* Initialize core "friend request API" RPC server */
    core->friend_req_api = wish_platform_malloc(sizeof(wish_rpc_server_t));
    memset(core->friend_req_api, 0, sizeof(wish_rpc_server_t));
  
    core->friend_req_api->request_list_head = NULL;
    
    core->friend_req_api->rpc_ctx_pool = wish_platform_malloc(sizeof(struct wish_rpc_context_list_elem)*10);
    memset(core->friend_req_api->rpc_ctx_pool, 0, sizeof(struct wish_rpc_context_list_elem)*10);
    core->friend_req_api->rpc_ctx_pool_num_slots = 10;
    
    strncpy(core->friend_req_api->server_name, "c2c unsecure", 13);
    core->friend_req_api->context = core;
    
    wish_rpc_server_register(core->friend_req_api, &core_friend_req_h);
}

void wish_core_connection_send(void* ctx, uint8_t *payload, int payload_len) {
    wish_connection_t* wish_ctx = ctx;
    wish_core_t* core = wish_ctx->core;

    bson bp;
    bson_init_buffer(&bp, payload, payload_len);
    
    int buffer_len = payload_len + 128;
    uint8_t buffer[buffer_len];
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_bson(&bs, "res", &bp);
    bson_finish(&bs);
    
    if (bs.err) {
        WISHDEBUG(LOG_CRITICAL, "BSON write error, buffer in wish_core_connection_send");
        return;
    }

    //bson_visit("actual outgoing data:", (uint8_t*)bson_data(&bs));
    //WISHDEBUG(LOG_CRITICAL, "(end)");

    wish_core_send_message(core, wish_ctx, (uint8_t*)bson_data(&bs), bson_size(&bs));
}

/* Feed to core's RPC server. You should feed the document which is as the
 * element 'req' 
 */
void wish_core_feed_to_rpc_server(wish_core_t* core, wish_connection_t *connection, uint8_t *data, size_t len) {

    char *op_str = NULL;
    int32_t op_str_len = 0;
    if (bson_get_string(data, "op", &op_str, &op_str_len) == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Unexpected: no op");
        return;
    }

    uint8_t *args = NULL;
    int32_t args_len = 0;
    if (bson_get_array(data, "args", &args, &args_len) == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Unexpected: no args");
        return;
    }

    int32_t id = 0;
    bool ack_needed = false;
    if (bson_get_int32(data, "id", &id) == BSON_SUCCESS) {
        ack_needed = true;
    }
    else {
        /* We could not get the id, no ack is requested */
        ack_needed = false;
    }

    struct wish_rpc_context_list_elem *list_elem = wish_rpc_server_get_free_rpc_ctx_elem(core->core_api);
    if (list_elem == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Could not save the rpc context. Failing in wish_core_rpc_func.");
        return;
    } else {
        rpc_server_req *req = &(list_elem->request_ctx);
        if (connection->friend_req_connection) {
            /* Friend request connection: Feed to the message to the special untrusted friend request RPC server */
            req->server = core->friend_req_api;
        } else {
            /* Normal Wish connection: feed the message to the normal "core to core" RPC server */
            req->server = core->core_api;
        }
        req->send = wish_core_connection_send;
        req->send_context = connection;
        memset(req->op_str, 0, MAX_RPC_OP_LEN);
        strncpy(req->op_str, op_str, op_str_len);
        req->id = id;
        req->ctx = connection;
    
        if (wish_rpc_server_handle(core->core_api, req, args)) {
            WISHDEBUG(LOG_CRITICAL, "RPC server fail: wish_core_rpc_func");
        }
    }
}

/* Feed to core's RPC client response handler. 
 * You should feed the document which is as the element 'res' 
 */

void wish_core_feed_to_rpc_client(wish_core_t* core, wish_connection_t *ctx, uint8_t *data, size_t len) {
    wish_rpc_client_handle_res(core->core_rpc_client, ctx, data, len);
}


void wish_core_send_peers_rpc_req(wish_core_t* core, wish_connection_t *ctx) {
    size_t request_max_len = 100;
    uint8_t request[request_max_len];
    size_t buffer_max_len = 75;
    uint8_t buffer[buffer_max_len];
    wish_rpc_id_t id = wish_rpc_client(core->core_rpc_client, "peers", NULL, 0, peers_callback,
        buffer, buffer_max_len);

    rpc_client_req* mreq = find_request_entry(core->core_rpc_client, id);
    mreq->cb_context = ctx;
    
    
    bson_init_doc(request, request_max_len);
    bson_write_embedded_doc_or_array(request, request_max_len,
        "req", buffer, BSON_KEY_DOCUMENT);
    wish_core_send_message(core, ctx, request, bson_get_doc_len(request));
}

/* Build and send a peer 'offline' message 
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
        bson_init_doc(core_to_app, core_to_app_max_len);
        
        /*
        if (online) {
            WISHDEBUG(LOG_CRITICAL, "Building upstream online peer message");
        }
        else {
            WISHDEBUG(LOG_CRITICAL, "Building upstream offline peer message");
        }
        */
        
        bson_write_string(core_to_app, core_to_app_max_len, "type", "peer");
        int32_t peer_info_max_len = 256;
        uint8_t peer_info[peer_info_max_len];


        bson_init_doc(peer_info, peer_info_max_len);
        /* luid, ruid and rhid come from the wish context */
        bson_write_binary(peer_info, peer_info_max_len, "luid", ctx->luid, WISH_ID_LEN);
        bson_write_binary(peer_info, peer_info_max_len, "ruid", ctx->ruid, WISH_ID_LEN);
        bson_write_binary(peer_info, peer_info_max_len, "rhid", ctx->rhid, WISH_WHID_LEN);
        /* rsid and protocol are from the rsid list of the context */
        if (bson_write_binary(peer_info, peer_info_max_len,
                "rsid", service->rsid, WISH_WSID_LEN) == BSON_FAIL) {
            WISHDEBUG(LOG_CRITICAL, "Failed writing rsid to upstream peer message");
            return;
        }
        if (bson_write_string(peer_info, peer_info_max_len,
                "protocol", service->protocol) == BSON_FAIL) {
            WISHDEBUG(LOG_CRITICAL, "Failed writing service to upstream peer message");
            return;
        }

        /* Depending on if it is an online or offline, set typecode to 
         * N (signifying "new") or D (signifying "delete") */
        char *type_code = "N";
        if (online == false) {
            type_code = "D";
        }
        if (bson_write_string(peer_info, peer_info_max_len,
                "type", type_code) == BSON_FAIL) {
            WISHDEBUG(LOG_CRITICAL, "Failed writing type to upstream peer message");

            return;
        }
        /* Encode 'online' as indicated to indicate peer online/offline message */
        if (bson_write_boolean(peer_info, peer_info_max_len,
                "online", online) == BSON_FAIL) {

            WISHDEBUG(LOG_CRITICAL, "peer info buffer is too small!");
            return;
        }
        if (bson_write_embedded_doc_or_array(core_to_app, core_to_app_max_len,
                "peer", peer_info, BSON_KEY_DOCUMENT) == BSON_FAIL) {
            WISHDEBUG(LOG_CRITICAL, "core to app buffer is too small!");
            return;
        }

        /* Send the peer offline information to all the services of this core */
        struct wish_service_entry *registry = wish_service_get_registry(core);
        if (registry == NULL) {
            WISHDEBUG(LOG_CRITICAL, "App registry is null");
            return;
        }
        else {
            WISHDEBUG(LOG_DEBUG, "Registry seems valid");
        }
        int i = 0;
        for (i = 0; i < WISH_MAX_SERVICES; i++) {
            if (wish_service_entry_is_valid(core, &(registry[i]))) {
                //bson_visit("This is peer info", peer_info);
                WISHDEBUG(LOG_CRITICAL, "wish_core_rpc_func: wish_send_online_offline_signal_to_apps: (len %d)", bson_get_doc_len(core_to_app));
                send_core_to_app(core, registry[i].wsid, core_to_app, bson_get_doc_len(core_to_app));
            }
        }

        if (online == false) {
            /* Delete service from list */
            LL_DELETE(ctx->rsid_list_head, service);
            wish_platform_free(service);
        }
    }

}

/* 
 This function is used to clean up the core RPC server from old requests when a connection to a remote core is severed 
 @param ctx the core connection context of the severed link
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

