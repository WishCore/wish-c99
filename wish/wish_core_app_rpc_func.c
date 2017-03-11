#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "wish_rpc.h"
#include "wish_utils.h"
#include "wish_version.h"
#include "wish_identity.h"
#include "wish_event.h"
#include "wish_core_signals.h"
#include "wish_io.h"
#include "wish_core_app_rpc_func.h"
#include "wish_core.h"

#include "wish_acl.h"
#include "wish_directory.h"

#include "wish_service_registry.h"
#include "core_service_ipc.h"
#include "wish_local_discovery.h"
#include "wish_connection_mgr.h"
#include "wish_dispatcher.h"
#include "ed25519.h"
#include "bson.h"
#include "cbson.h"
#include "bson_visitor.h"
#include "utlist.h"

#include "mbedtls/sha256.h"

//#include <netinet/in.h>
#include <arpa/inet.h>
#include "stdlib.h"

#include "wish_debug.h"
#include "wish_port_config.h"
#include "wish_relationship.h"

typedef struct wish_rpc_server_handler handler;

/* FIXME each Wish connection must have its own RCP client, so this has to be moved to ctx */
wish_rpc_client_t core2remote_rpc_client;

// NBUFL and nbuf are used for writing BSON array indexes
#define NBUFL 8
uint8_t nbuf[NBUFL];


/* 
 * Enumerate available methods in RPC
 */
static void methods(rpc_server_req* req, uint8_t* args) {
    wish_core_t* core = (wish_core_t*) req->server->context;
    
    handler *h = core->app_api->list_head;
    
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

/*
 * Return core version string  
 * 
 * Example return values:
 * 
 *   v0.6.8-alpha-37-g85643-dirty
 *   v0.6.8-alpha-37-g85643
 *   v0.6.8
 */
static void version(rpc_server_req* req, uint8_t* args) {
    
    bson bs; 
    bson_init(&bs);
    bson_append_string(&bs, "data", WISH_CORE_VERSION_STRING);
    bson_finish(&bs);
    
    wish_rpc_server_send(req, bs.data, bson_size(&bs));
    bson_destroy(&bs);
}

/*
 * Request to send message to peer
 */
static void services_send(rpc_server_req* req, uint8_t* args) {
    //bson_visit("Handling services.send", args);
    
    wish_core_t* core = (wish_core_t*) req->server->context;
    
    /* First, obtain the peer, as element "0" of args. This will
     * define the routing of the message. */
    uint8_t* peer = NULL;
    int32_t peer_len = 0;
    if (bson_get_document(args, "0", &peer, &peer_len) == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Could not get peer");
        return;
    }

    /* Examine the 'rhid' element of the peer. If it matches our own
     * host's rhid, then it for local delivery, and pass it directly to 
     * "send core to app" function. We use the 'core app' RPC client for
     * this. */
    uint8_t *rhid = NULL;
    int32_t rhid_len = 0;
    if (bson_get_binary(peer, "rhid", &rhid, &rhid_len) == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Could not get rhid");
        return;
    }

    //if (memcmp(rhid, this_host_rhid, WISH_WHID_LEN) == 0) { ... }
    
    /* Else, find a wish context that has a matching rhid.
     * Then, verify that luid and ruid also match the connection. If so,
     * then we can send the payload using with that context.
     * For this, use the 'core' RPC client. */
    uint8_t *luid = NULL;
    int32_t luid_len = 0;
    if (bson_get_binary(peer, "luid", &luid, &luid_len) == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Could not get luid");
        return;
    }

    uint8_t *ruid = NULL;
    int32_t ruid_len = 0;
    if (bson_get_binary(peer, "ruid", &ruid, &ruid_len) == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Could not get ruid");
        return;
    }

    uint8_t *rsid = NULL;
    int32_t rsid_len = 0;
    if (bson_get_binary(peer, "rsid", &rsid, &rsid_len) == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Could not get rsid");
        return;
    }
    char *protocol = NULL;
    int32_t protocol_len = 0;
    if (bson_get_string(peer, "protocol", &protocol, &protocol_len) == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Could not get protocol");
        return;
    }




    uint8_t *payload = NULL;
    int32_t payload_len = 0;
    if (bson_get_binary(args, "1", &payload, &payload_len) 
            == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Could not get payload");
        return;
    }

    /* First, check if message is to be delivered to some of our local services.
     * In this case we very if the message's rhid corresponds to our local core's rhid 
     */
    uint8_t local_hostid[WISH_WHID_LEN];
    wish_core_get_host_id(core, local_hostid);
    if (memcmp(rhid, local_hostid, WISH_WHID_LEN) == 0) {
        /* rhid matches to local core, message destined to a local service!
         * Now we must construct a frame, much like we do in the "core-to-core" 
         * RPC server, but in the peer document, the luid and ruid switch places,
         * and rsid is replaced by the service id which called this RPC handler
         * (that is found in the rpc context)
         *  */
        
        /* FIXME this is waisting stack space again */
        size_t upcall_doc_max_len = peer_len + payload_len + 100;
        uint8_t upcall_doc[upcall_doc_max_len];
        bson bs;
        bson_init_buffer(&bs, upcall_doc, upcall_doc_max_len);
        bson_append_string(&bs, "type", "frame");
        bson_append_start_object(&bs, "peer");
        /* luid and ruid switch places */
        bson_append_binary(&bs, "luid", ruid, WISH_ID_LEN);
        bson_append_binary(&bs, "ruid", luid, WISH_ID_LEN);
        bson_append_binary(&bs, "rhid", rhid, WISH_WHID_LEN);
        /* rsid is */
        bson_append_binary(&bs, "rsid", req->local_wsid, WISH_WSID_LEN);
        bson_append_string(&bs, "protocol", protocol);
        bson_append_finish_object(&bs);
        bson_append_binary(&bs, "data", payload, payload_len);
        bson_finish(&bs);
        if (bs.err) {
            WISHDEBUG(LOG_CRITICAL, "Error creating frame to local service");
        } else {
            //bson_visit("About to send this to local service on local core:", upcall_doc);
            send_core_to_app(core, rsid, upcall_doc, bson_get_doc_len(upcall_doc));
        }
        return;
    }
    /* Destination is determined to be a remote service on a remote core. */
    wish_connection_t *dst_ctx = wish_core_lookup_ctx_by_luid_ruid_rhid(core, luid, ruid, rhid);

    /* Build the actual on-wire message:
     *
     * req: {
     *  op: 'send'
     *  args: [ lsid, rsid, protocol, payload ]
     * }
     */
    
    size_t args_buffer_len = 2*(WISH_WSID_LEN) + protocol_len + payload_len + 128;
    uint8_t args_buffer[args_buffer_len];
    bson bs; 
    bson_init_buffer(&bs, args_buffer, args_buffer_len);
    bson_append_start_array(&bs, "args");
    bson_append_binary(&bs, "0", req->local_wsid, WISH_WSID_LEN);
    bson_append_binary(&bs, "1", rsid, WISH_WSID_LEN);
    bson_append_string(&bs, "2", protocol);
    bson_append_binary(&bs, "3", payload, payload_len);
    bson_append_finish_array(&bs);
    bson_finish(&bs);
    
    if (bs.err) {
        WISHDEBUG(LOG_CRITICAL, "BSON write error, args_buffer");
        return;
    }

    size_t client_req_len = args_buffer_len + MAX_RPC_OP_LEN + 128;
    uint8_t client_req[client_req_len];
    
    wish_rpc_client_bson(&core2remote_rpc_client, "send", (char*)bson_data(&bs), bson_size(&bs), NULL, client_req, client_req_len);

    //bson_visit("About to send this to the remote core (should be req: { op, args, id }):", client_req);

    
    //WISHDEBUG(LOG_CRITICAL, "Sending services.send");
    if (dst_ctx != NULL && dst_ctx->context_state == WISH_CONTEXT_CONNECTED) {
        
        size_t req_len = client_req_len + 128;
        uint8_t req_buf[req_len];

        bson_iterator it;
        bson_find_from_buffer(&it, client_req, "op");
        const char* op = bson_iterator_string(&it);
        
        bool has_id = false;
        bson_find_from_buffer(&it, client_req, "id");
        if(bson_iterator_type(&it) == BSON_INT) {
            // we have an id
            has_id = true;
        }
        int id = bson_iterator_int(&it);
        
        bson_find_from_buffer(&it, client_req, "args");
        
        bson b;
        bson_init_buffer(&b, req_buf, req_len);
        bson_append_start_object(&b, "req");
        bson_append_string(&b, "op", op);
        bson_append_element(&b, "args", &it);
        if (has_id == true) { bson_append_int(&b, "id", id); }
        bson_append_finish_object(&b);
        bson_finish(&b);
        
        //bson_visit("About to send this to the remote core (should be req: { op, args[, id] }):", req_buf);
        
        
        int send_ret = wish_core_send_message(core, dst_ctx, req_buf, bson_get_doc_len(req_buf));
        if (send_ret != 0) {
            /* Sending failed. Propagate RPC error */
            WISHDEBUG(LOG_CRITICAL, "Core app RPC: Sending not possible at this time");
            if(req->id != 0) {
                wish_rpc_server_error(req, 506, "Failed sending message to remote core.");
            }
        }
        else {
            /* Sending successful */
        
            if(req->id != 0) {
                // Client expecting response. Send ack to client
                wish_rpc_server_send(req, NULL, 0);
            } else {
                /* Client not expecting response */
                wish_rpc_server_delete_rpc_ctx(req);
            }
        }
    }
    else {
        WISHDEBUG(LOG_CRITICAL, "Could not find a suitable wish context to send with");
        wish_debug_print_array(LOG_DEBUG, "should be luid:", luid, WISH_ID_LEN);
        wish_debug_print_array(LOG_DEBUG, "should be ruid:", ruid, WISH_ID_LEN);
        wish_debug_print_array(LOG_DEBUG, "should be rhid:", rhid, WISH_ID_LEN);
    }
}

/*
 * return list of services on this host
 * 
 * [
 *   { name: 'Wish CLI', sid: <Buffer c9 ed ... d3 fb>, protocols: [] },
 *   { name: 'GPS',      sid: <Buffer 47 50 ... 6a 73>, protocols: ['ucp'] }
 * ]
 */
static void services_list_handler(rpc_server_req* req, uint8_t* args) {
    wish_core_t* core = req->server->context;
    wish_app_entry_t* app = req->context;
    
    int buffer_len = WISH_PORT_RPC_BUFFER_SZ;
    uint8_t buffer[buffer_len];

    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_start_array(&bs, "data");
    
    int i;
    int c = 0;
    char index[21];
    
    for (i = 0; i < WISH_MAX_SERVICES; i++) {
        if (wish_service_entry_is_valid(core, &(core->service_registry[i]))) {
            BSON_NUMSTR(index, c++);
            bson_append_start_object(&bs, index);
            bson_append_string(&bs, "name", core->service_registry[i].name);
            bson_append_binary(&bs, "sid", core->service_registry[i].wsid, WISH_WSID_LEN);
            
            int j = 0;
            int k = 0;
            char pindex[21];
            
            bson_append_start_array(&bs, "protocols");
            
            for (j = 0; j < WISH_APP_MAX_PROTOCOLS; j++) {
                if (strnlen(core->service_registry[i].protocols[j].name, WISH_PROTOCOL_NAME_MAX_LEN) > 0) {
                    BSON_NUMSTR(pindex, k++);
                    bson_append_string(&bs, pindex, core->service_registry[i].protocols[j].name);
                }
            }
            
            bson_append_finish_array(&bs);
            bson_append_finish_object(&bs);
        }
    }
    bson_append_finish_array(&bs);
    bson_finish(&bs);
    
    wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
}

/* This is the Call-back functon invoksed by the core's "app" RPC
 * server, when identity.export is received from a Wish app 
 *
 * identity.export('342ef67c822662174e67689b8b1f1ef761c8085129561372adeb9ccf6ec30c86')
 * RPC app to core { op: 'identity.export',
 *   args: [
 *   '342ef67c822662174e67689b8b1f1ef761c8085129561372adeb9ccf6ec30c86'
 *   ],
 *   id: 3 }
 * Core to app: { ack: 3,
 *       data:
 *       'H4sIAAAAAAAAA61TPW8...2d2b3GF2jAfwBaWrGAmsEAAA='
 *       }
 *
 */
static void identity_export_handler(rpc_server_req* req, uint8_t* args) {
    wish_core_t* core = req->server->context;
    wish_app_entry_t* app = req->context;
    
    /* Get the uid of identity to export, the uid is argument "0" in
     * args */
    uint8_t *arg_uid = 0;
    int32_t arg_uid_len = 0;
    if (bson_get_binary(args, "0", &arg_uid, &arg_uid_len) != BSON_SUCCESS) {
        WISHDEBUG(LOG_CRITICAL, "Could not get argument: uid");
        wish_rpc_server_error(req, 8, "Missing export uid argument");
        return;
    }

    if (arg_uid_len != WISH_ID_LEN) {
        WISHDEBUG(LOG_CRITICAL, "argument uid has illegal length");
        return;
    }

    /* Get the requested export type, element 1 of args array. 
     * This impelementation requires an
     * explicit string argument 'binary', which means that the
     * identity shall be exported as BSON document. */
    char *export_type_str = 0;
    int32_t export_type_str_len = 0;
    if (bson_get_string(args, "1", &export_type_str, &export_type_str_len) != BSON_SUCCESS) {
        WISHDEBUG(LOG_CRITICAL, "Missing export type argument");
        wish_rpc_server_error(req, 8, "Missing export type argument");
        return;
    }

    if (strcmp(export_type_str, "binary") != 0) {
        WISHDEBUG(LOG_CRITICAL, "Illegal export type");
        return;
    }

    wish_identity_t id;
    
    if ( ret_success != wish_identity_load(arg_uid, &id) ) {
        wish_rpc_server_error(req, 343, "Failed to load identity.");
        return;
    }
    
    bson bs;
    bson_init_size(&bs, 256);
    bson_append_string(&bs, "alias", id.alias);
    bson_append_binary(&bs, "uid", id.uid, WISH_UID_LEN);
    bson_append_binary(&bs, "pubkey", id.pubkey, WISH_PUBKEY_LEN);


    wish_relay_client_t* relay;

    int i = 0;

    if (core->relay_db != NULL) {
        bson_append_start_array(&bs, "transports");

        LL_FOREACH(core->relay_db, relay) {
            char index[21];
            BSON_NUMSTR(index, i++);
            char host[29];
            snprintf(host, 29, "wish://%d.%d.%d.%d:%d", relay->ip.addr[0], relay->ip.addr[1], relay->ip.addr[2], relay->ip.addr[3], relay->port);

            bson_append_string(&bs, index, host);
        }

        bson_append_finish_array(&bs);
    }

    bson_append_finish_object(&bs);
    
    if (bs.err) {
        wish_rpc_server_error(req, 349, "Export document bson too large.");
        bson_destroy(&bs);
        return;
    }

    //bson_visit("Export brand new:", bs.data);
    //WISHDEBUG(LOG_CRITICAL, "size %i", bs.dataSize);
    
    mbedtls_sha256_context sha256;
    mbedtls_sha256_init(&sha256);
    mbedtls_sha256_starts(&sha256, 0); 
    mbedtls_sha256_update(&sha256, bson_data(&bs), bson_size(&bs)); 
    int hash_len = 32;
    uint8_t hash[hash_len];
    mbedtls_sha256_finish(&sha256, hash);
    mbedtls_sha256_free(&sha256);
    
    
    uint8_t signature[ED25519_SIGNATURE_LEN];
    uint8_t privkey[WISH_PRIVKEY_LEN];
    
    if (wish_load_privkey(id.uid, privkey)) {
        WISHDEBUG(LOG_CRITICAL, "Could not load privkey for signing export %s", id.alias);
        wish_rpc_server_error(req, 345, "Could not sign exported document.");
        bson_destroy(&bs);
        return;
    } else {
        ed25519_sign(signature, hash, hash_len, privkey);
    }

    
    bson b;
    bson_init_size(&b, WISH_PORT_RPC_BUFFER_SZ);
    bson_append_start_object(&b, "data");
    bson_append_start_array(&b, "signatures");
    bson_append_start_object(&b, "0");
    bson_append_string(&b, "algo", "sha256-ed25519");
    bson_append_binary(&b, "uid", id.uid, WISH_UID_LEN);
    bson_append_binary(&b, "sign", signature, ED25519_SIGNATURE_LEN);
    bson_append_finish_array(&b);
    bson_append_finish_object(&b);
    bson_append_binary(&b, "cert", bson_data(&bs), bson_size(&bs));
    bson_append_finish_object(&b);
    bson_finish(&b);

    wish_rpc_server_send(req, bson_data(&b), bson_size(&b));
    bson_destroy(&b);
    bson_destroy(&bs);
}

/* This is the Call-back functon invoksed by the core's "app" RPC
 * server, when identity.import is received from a Wish app 
 *
 *
 * Request:
 * identity.import(Buffer<the identity document as binary>,
 * Buffer<contactForWuid>, 'binary')
 * RPC app to core 
 * { op: 'identity.import',
 *  args: [ 
 *   <buffer 342ef... (The identity BSON document in a binary *   buffer)>,
 *   <buffer 342ef67c822662174e67689b8b1f1ef761c8085129561372adeb9ccf6ec30c86>,
 *   'binary'
 *   ],
 *   id: 3 }
 *
 * The second argument is the "befriend with" argument
 *
 * Core to app Reply:
 * { ack: 3,
 *   data: { alias: 'Stina', uid: <Buffer 04735247b938c585df04d4fbaab68a1f766f00195839a36087eaa1299c491449> } 
 *   } 
 *
 *   The first arg is alias and second argument is the uid of the imported id
 *
 */
static void identity_import_handler(rpc_server_req* req, uint8_t* args) {
    int buffer_len = WISH_PORT_RPC_BUFFER_SZ;
    uint8_t buffer[buffer_len];

    WISHDEBUG(LOG_DEBUG, "Core app RPC: identity_import");
    bson_init_doc(buffer, buffer_len);

    /* Get the identity document to import, the doc is argument "0" in
     * args */
    uint8_t *new_id_doc = 0;
    int32_t new_id_doc_len = 0;
    if (bson_get_binary(args, "0", &new_id_doc, &new_id_doc_len) != BSON_SUCCESS) {
        WISHDEBUG(LOG_CRITICAL, "Could not get argument 0: id doc");
        wish_rpc_server_error(req, 70, "Could not get argument 0: identity doc");
        return;
    }

    uint8_t *befriend_wuid = 0;
    int32_t befriend_wuid_len = 0;
    if (bson_get_binary(args, "1", &befriend_wuid, &befriend_wuid_len) != BSON_SUCCESS) {
        WISHDEBUG(LOG_CRITICAL, "Could not get argument 1: befriend wuid");
        wish_rpc_server_error(req, 71, "Could not get argument 1: uid");
        return;
    }

    if (befriend_wuid_len != WISH_ID_LEN) {
        WISHDEBUG(LOG_CRITICAL, "argument 1 befriend wuid has illegal length");
        wish_rpc_server_error(req, 72, "Could not get argument 1: uid length not expected");
        return;
    }
    /* FIXME We don't have the concept of "befriend uid with new
     * contact */
 
    /* Get the requested import type, element 2 of args array. 
     * This impelementation requires an
     * explicit string argument 'binary', which means that the
     * identity is imported as BSON document (inside a BSON binary element). */
    char *import_type_str = 0;
    int32_t import_type_str_len = 0;
    if (bson_get_string(args, "2", &import_type_str, 
            &import_type_str_len) != BSON_SUCCESS) {
        WISHDEBUG(LOG_CRITICAL, "Missing import type argument");
        wish_rpc_server_error(req, 73, "Missing import type argument");
        return;
    }

    if (strcmp(import_type_str, "binary") != 0) {
        WISHDEBUG(LOG_CRITICAL, "Illegal import type");
        wish_rpc_server_error(req, 74, "Illegal import type");
        return;
    }

    /* Start to examine the imported identity doc */
    
    int32_t bson_doc_len = bson_get_doc_len(new_id_doc);
    if (bson_get_doc_len(new_id_doc) != new_id_doc_len) {
        WISHDEBUG(LOG_CRITICAL, "Malformed doc, len %d", bson_doc_len);
        wish_rpc_server_error(req, 75, "Malformed bson document.");
        return;
    }
    
    /* FIXME make other sanity checks... like the existence of different
     * elements: pubkey, alias, ... */

    char *new_id_alias = NULL;
    int32_t new_id_alias_len = 0;
    if (bson_get_string(new_id_doc, "alias", &new_id_alias, &new_id_alias_len) 
            != BSON_SUCCESS) {
        WISHDEBUG(LOG_CRITICAL, "Could not get alias element");
        wish_rpc_server_error(req, 76, "Could not get alias element");
        return;
    }
    else {
        WISHDEBUG(LOG_CRITICAL, "Importing alias %s", new_id_alias);
    }

    wish_identity_t new_id;
    memset(&new_id, 0, sizeof (wish_identity_t));
    if (wish_populate_id_from_cert(&new_id, new_id_doc)) {
        /* ...it failed somehow.. */
        WISHDEBUG(LOG_CRITICAL, "There was an error when populating the new id struct");
        wish_rpc_server_error(req, 76, "There was an error when populating the new id struct");
        return;
    }

    if (wish_identity_exists(new_id.uid)>0) {
        // it already exists, bail!
        wish_rpc_server_error(req, 202, "Identity already exists.");
        return;
    }
    
    /* The identity to be imported seems valid! */

    /* Save the new identity to database */
    //wish_save_identity_entry_bson(new_id_doc);
    int ret = wish_save_identity_entry(&new_id);
    
    if( ret != 0 ) {
        wish_rpc_server_error(req, 201, "Too many identities.");
        return;
    }

    /* Form the reply message in 'buffer' */

    int32_t data_doc_max_len = WISH_ID_LEN + 20 + WISH_MAX_ALIAS_LEN + 20;
    uint8_t data_doc[data_doc_max_len];
    bson_init_doc(data_doc, data_doc_max_len);
    
    if (bson_write_string(data_doc, data_doc_max_len, "alias", new_id_alias)
            != BSON_SUCCESS) {
        WISHDEBUG(LOG_CRITICAL, "Failed to add alias to data doc");
        wish_rpc_server_error(req, 76, "Failed to add alias to data doc");
        return;
    }

    if (bson_write_binary(data_doc, data_doc_max_len, "uid", new_id.uid, WISH_ID_LEN) != BSON_SUCCESS) {
        WISHDEBUG(LOG_CRITICAL, "Failed to to add id to data doc");
        wish_rpc_server_error(req, 76, "Failed to to add id to data doc");
        return;
    }
    
    if (bson_write_embedded_doc_or_array(buffer, buffer_len, 
            "data", data_doc, BSON_KEY_DOCUMENT) != BSON_SUCCESS) {
        WISHDEBUG(LOG_CRITICAL, "Failed to to add data doc to response");
        wish_rpc_server_error(req, 76, "Failed to to add data doc to response");
        return;
    }

    wish_rpc_server_send(req, buffer, bson_get_doc_len(buffer));
}

/* This is the Call-back functon invoksed by the core's "app" RPC
 * server, when identity.list is received from a Wish app 
 *
 *  identity.list()
 *  RPC app to core { op: 'identity.list', args: [], id: 2 }
 *  Core to app: { ack: 2,
 *    data: 
 *       [ { alias: 'Jan2',
 *           id: '342ef67c822662174e67689b8b1f1ef761c8085129561372adeb9ccf6ec30c86',
 *           pubkey:'62d5b302ef33ee27bb52781b1b3946b04f856e5cf964f6418770e859338268f7',
 *           privkey: true,
 *           hosts: [Object],
 *           contacts: [Object],
 *           transports: [Object],
 *           trust: null },
 *
 *       ]
 *
 */
static void identity_list_handler(rpc_server_req* req, uint8_t* args) {
    
    int num_uids_in_db = wish_get_num_uid_entries();
    wish_uid_list_elem_t uid_list[num_uids_in_db];
    int num_uids = wish_load_uid_list(uid_list, num_uids_in_db);

    bson bs; 
    bson_init(&bs);
    bson_append_start_array(&bs, "data");
    
    int i = 0;
    for (i = 0; i < num_uids; i++) {
        char num_str[8];
        bson_numstr(num_str, i);
        bson_append_start_object(&bs, num_str);
        /* For each uid in DB, copy the uid, alias and privkey fields */
        size_t id_bson_doc_max_len = sizeof (wish_identity_t) + 100;
        uint8_t id_bson_doc[id_bson_doc_max_len];
        int ret = wish_load_identity_bson(uid_list[i].uid, id_bson_doc,
            id_bson_doc_max_len);

        if (ret == 1) {

            int32_t uid_len = 0;
            uint8_t *uid = NULL;
            if (bson_get_binary(id_bson_doc, "uid", &uid, &uid_len) 
                    == BSON_FAIL) {
                WISHDEBUG(LOG_CRITICAL, "Unexpected: no uid");
                break;
            }
            bson_append_binary(&bs, "uid", uid, uid_len);

            int32_t alias_len = 0;
            char *alias = NULL;
            if (bson_get_string(id_bson_doc, "alias", &alias, &alias_len)
                    == BSON_FAIL) {
                WISHDEBUG(LOG_CRITICAL, "Unexpected: no alias");
                break;
            }
            bson_append_string(&bs, "alias", alias);

            int32_t privkey_len = 0;
            uint8_t *privkey = NULL;
            bool privkey_status = false;
            if (bson_get_binary(id_bson_doc, "privkey", &privkey,
                    &privkey_len) == BSON_SUCCESS) {
                /* Privkey exists in database */
                privkey_status = true;
            }
            else {
                /* Privkey not in database */
                privkey_status = false;
            }
            bson_append_bool(&bs, "privkey", privkey_status);

            bson_append_finish_object(&bs);
        }
    }
    
    bson_append_finish_array(&bs);
    bson_finish(&bs);
    
    if (bs.err) {
        WISHDEBUG(LOG_CRITICAL, "BSON error in identity_list_handler");
        wish_rpc_server_error(req, 997, "BSON error in identity_list_handler");
    } else {

        //bson_visit("identity.list response bson", bs.data);

        wish_rpc_server_send(req, bs.data, bson_size(&bs));
    }
    bson_destroy(&bs);
}

/*
 * identity.create
 *
 * App to core: { op: "identity.create", args: [ "Moster Greta" ], id: 5 }
 * Response core to App:
 *  { ack: 5, data: {
 *          alias: "Moster Greta",
 *          uid: <binary buffer containing the new wish user id>,
 *          privkey: true;
 *      }
 *  }
 *
 *  Note that privkey is always returned as 'true' when doing
 *  identity.create (An identity creation always involves creation of
 *  private key and public key)
 */
static void identity_create_handler(rpc_server_req* req, uint8_t* args) {
    wish_core_t* core = (wish_core_t*) req->server->context;
    
    int buffer_len = WISH_PORT_RPC_BUFFER_SZ;
    uint8_t buffer[buffer_len];

    bson_init_doc(buffer, buffer_len);

    /* Get the new identity's alias, it is element 0 of array 'args' */
    char *alias_str = NULL;
    int32_t alias_str_len = 0;
    bson_get_string(args, "0", &alias_str, &alias_str_len);

    WISHDEBUG(LOG_DEBUG, "Core app RPC: identity_create for alias %s", alias_str);

    /* Create the identity */
    wish_identity_t new_id;
    wish_create_local_identity(&new_id, alias_str);
    int ret = wish_save_identity_entry(&new_id);

    /* There is something wrong with this. Returns error while saving. Should be <= 0?
    if( ret != 0 ) {
        return write_bson_error(req, req_id, 201, "Too many identities.");
    }
    */

    size_t data_doc_max_len = sizeof (wish_identity_t) + 100;
    uint8_t data_doc[data_doc_max_len];
    ret = wish_load_identity_bson(new_id.uid, data_doc, data_doc_max_len);
    if (ret == 1) {
        /* Filter out the actual "privkey" element */
        size_t filtered_doc_max_len = bson_get_doc_len(data_doc);
        uint8_t filtered_doc[filtered_doc_max_len];
        if (bson_filter_out_elem("privkey", data_doc, filtered_doc)
                == BSON_FAIL) {
            WISHDEBUG(LOG_CRITICAL, "Could not filter out privkey!");
        }
        else {
            if (bson_write_boolean(filtered_doc, filtered_doc_max_len, 
                    "privkey", true) == BSON_FAIL) {
                WISHDEBUG(LOG_CRITICAL, "Could not add bool privkey!");
            }
        }

        bson_write_embedded_doc_or_array(buffer, buffer_len, 
            "data", filtered_doc, BSON_KEY_DOCUMENT);
    }

    wish_rpc_server_send(req, buffer, bson_get_doc_len(buffer));

    WISHDEBUG(LOG_CRITICAL, "Starting to advertize the new identity");
    wish_core_update_identities(core);

    wish_ldiscover_advertize(core, new_id.uid);
    wish_report_identity_to_local_services(core, &new_id, true);

    wish_core_signals_emit_string(core, "identity");
}
/*
 * identity.remove
 *
 * App to core: { op: "identity.remove", args: [ <Buffer> uid ], id: 5 }
 * Response core to App:
 *  { ack: 5, data: true }
 *
 *  Note that privkey is always returned as 'true' when doing
 *  identity.create (An identity creation always involves creation of
 *  private key and public key)
 */
static void identity_remove_handler(rpc_server_req* req, uint8_t* args) {
    wish_core_t* core = (wish_core_t*) req->server->context;
    
    int buffer_len = WISH_PORT_RPC_BUFFER_SZ;
    uint8_t buffer[buffer_len];

    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");

    if(bson_iterator_type(&it) == BSON_BINDATA && bson_iterator_bin_len(&it) == WISH_ID_LEN) {

        /* Get the uid of identity to export, the uid is argument "0" in
         * args */
        uint8_t *luid = 0;
        luid = (uint8_t *)bson_iterator_bin_data(&it);

        wish_identity_t id_to_remove;
        if (wish_identity_load(luid, &id_to_remove) == ret_success) {
            wish_report_identity_to_local_services(core, &id_to_remove, false);
        }
        
        int res = wish_identity_remove(core, luid);

        bson bs;

        bson_init_buffer(&bs, buffer, buffer_len);
        bson_append_bool(&bs, "data", res == 1 ? true : false);
        bson_finish(&bs);

        if (bs.err != 0) {
            wish_rpc_server_error(req, 344, "Failed writing reponse.");
            return;
        }

        wish_core_update_identities(core);
        wish_rpc_server_send(req, buffer, bson_get_doc_len(buffer));
        
        wish_core_signals_emit_string(core, "identity");
    } else {
        wish_rpc_server_error(req, 343, "Invalid argument. Expecting 32 byte bin data.");
    }
}

/*
 * identity.sign
 *
 * App to core: { op: "identity.sign", args: [ <Buffer> uid, <Buffer> hash ], id: 5 }
 */
static void identity_sign(rpc_server_req* req, uint8_t* args) {
    int buffer_len = WISH_PORT_RPC_BUFFER_SZ;
    uint8_t buffer[buffer_len];

    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    if(bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) != WISH_ID_LEN) {
        wish_rpc_server_error(req, 345, "Invalid uid.");
        return;
    }

    uint8_t *luid = 0;
    luid = (uint8_t *)bson_iterator_bin_data(&it);

    bson_find_from_buffer(&it, args, "1");
    
    if(bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) < 32 || bson_iterator_bin_len(&it) > 64 ) {
        wish_rpc_server_error(req, 345, "Invalid hash.");
        return;
    }
    
    char hash[64];
    int hash_len = bson_iterator_bin_len(&it);
    
    memcpy(hash, bson_iterator_bin_data(&it), hash_len);

    uint8_t signature[ED25519_SIGNATURE_LEN];
    uint8_t local_privkey[WISH_PRIVKEY_LEN];
    if (wish_load_privkey(luid, local_privkey)) {
        WISHDEBUG(LOG_CRITICAL, "Could not load privkey");
        wish_rpc_server_error(req, 345, "Could not load private key.");
        return;
    }
    else {
        ed25519_sign(signature, hash, hash_len, local_privkey);
    }

    //wish_debug_print_array(LOG_DEBUG, signature, ED25519_SIGNATURE_LEN);

    bson bs;

    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_binary(&bs, "data", signature, ED25519_SIGNATURE_LEN);
    bson_finish(&bs);

    if(bs.err != 0) {
        wish_rpc_server_error(req, 344, "Failed writing reponse.");
        return;
    }

    wish_rpc_server_send(req, buffer, bson_get_doc_len(buffer));
}

/*
 * identity.verify
 *
 * App to core: { op: "identity.verify", args: [ <Buffer> uid, <Buffer> signature, <Buffer> hash ], id: 5 }
 */
static void identity_verify(rpc_server_req* req, uint8_t* args) {
    int buffer_len = WISH_PORT_RPC_BUFFER_SZ;
    uint8_t buffer[buffer_len];

    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    if(bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) != WISH_ID_LEN) {
        wish_rpc_server_error(req, 345, "Invalid uid.");
        return;
    }

    uint8_t *luid = 0;
    luid = (uint8_t *)bson_iterator_bin_data(&it);

    bson_find_from_buffer(&it, args, "1");
    
    if(bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) != 64 ) {
        wish_rpc_server_error(req, 346, "Invalid signature.");
        return;
    }
    
    char signature[64];
    int signature_len = bson_iterator_bin_len(&it);
    
    memcpy(signature, bson_iterator_bin_data(&it), signature_len);

    bson_find_from_buffer(&it, args, "2");
    
    if(bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) < 32 || bson_iterator_bin_len(&it) > 64 ) {
        wish_rpc_server_error(req, 345, "Invalid hash.");
        return;
    }
    
    char hash[64];
    int hash_len = bson_iterator_bin_len(&it);
    
    memcpy(hash, bson_iterator_bin_data(&it), hash_len);

    bool verification = false;
    uint8_t pubkey[WISH_PUBKEY_LEN];
    if (wish_load_pubkey(luid, pubkey)) {
        WISHDEBUG(LOG_CRITICAL, "Could not load pubkey");
        wish_rpc_server_error(req, 345, "Could not load private key.");
        return;
    } else {
        verification = ed25519_verify(signature, hash, hash_len, pubkey) ? true : false;
    }

    //wish_debug_print_array(LOG_DEBUG, signature, ED25519_SIGNATURE_LEN);

    bson bs;

    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_bool(&bs, "data", verification);
    bson_finish(&bs);

    if(bs.err != 0) {
        wish_rpc_server_error(req, 344, "Failed writing reponse.");
        return;
    }

    wish_rpc_server_send(req, buffer, bson_get_doc_len(buffer));
}

/*
 * identity.friendRequestList
 *
 * App to core: { op: "identity.friendRequestList", args: [], id: 5 }
 */
static void identity_friend_request_list(rpc_server_req* req, uint8_t* args) {
    wish_core_t* core = (wish_core_t*) req->server->context;
    
    int buffer_len = WISH_PORT_RPC_BUFFER_SZ;
    uint8_t buffer[buffer_len];

    bson bs;

    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_start_array(&bs, "data");
    
    wish_relationship_req_t* elt;
    
    int i = 0;
    
    DL_FOREACH(core->relationship_req_db, elt) {
        char idx[21];
        BSON_NUMSTR(idx, i);
        bson_append_start_object(&bs, idx);
        bson_append_binary(&bs, "luid", elt->luid, WISH_UID_LEN);
        bson_append_binary(&bs, "ruid", elt->id.uid, WISH_UID_LEN);
        bson_append_string(&bs, "alias", elt->id.alias);
        bson_append_binary(&bs, "pubkey", elt->id.pubkey, WISH_PUBKEY_LEN);
        bson_append_finish_object(&bs);
    }
    
    bson_append_finish_array(&bs);
    bson_finish(&bs);

    if(bs.err != 0) {
        wish_rpc_server_error(req, 344, "Failed writing reponse.");
        return;
    }

    wish_rpc_server_send(req, buffer, bson_get_doc_len(buffer));
}

/*
 * identity.friendRequestAccept
 *
 * App to core: { op: "identity.friendRequestAccept", args: [ <Buffer> luid, <Buffer> ruid ], id: 5 }
 */
static void identity_friend_request_accept(rpc_server_req* req, uint8_t* args) {
    wish_core_t* core = (wish_core_t*) req->server->context;


    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    if(bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) != WISH_ID_LEN) {
        wish_rpc_server_error(req, 345, "Invalid luid.");
        return;
    }

    const char* luid = 0;
    luid = bson_iterator_bin_data(&it);

    bson_find_from_buffer(&it, args, "1");
    
    if(bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) != WISH_ID_LEN) {
        wish_rpc_server_error(req, 345, "Invalid ruid.");
        return;
    }

    const char* ruid = 0;
    ruid = bson_iterator_bin_data(&it);
    
    wish_relationship_req_t* elt;
    wish_relationship_req_t* tmp;
    
    bool found = false;
    
    DL_FOREACH_SAFE(core->relationship_req_db, elt, tmp) {
        if ( memcmp(elt->luid, luid, WISH_UID_LEN) == 0 
                && memcmp(elt->id.uid, ruid, WISH_UID_LEN) == 0 ) {
            found = true;
            DL_DELETE(core->relationship_req_db, elt);
            break;
        }
    }
    
    if (!found) {
        wish_rpc_server_error(req, 356, "No such friend request found.");
        return;
    }
    
    // Find the connection which was used for receiving the friend request   
    
    int i = 0;
    found = false;
    
    wish_connection_t* wish_connection = NULL;

    for (i = 0; i < WISH_CONTEXT_POOL_SZ; i++) {
        if (core->connection_pool[i].context_state == WISH_CONTEXT_FREE) {
            continue;
        }

        if (memcmp(core->connection_pool[i].luid, luid, WISH_ID_LEN) == 0) {
            if (memcmp(core->connection_pool[i].ruid, ruid, WISH_ID_LEN) == 0) {
                found = true;
                WISHDEBUG(LOG_CRITICAL, "Found the connection used for friend request, cnx state %i proto state: %i", core->connection_pool[i].context_state, core->connection_pool[i].curr_protocol_state);
                wish_connection = &core->connection_pool[i];
                break;
            }
            else {
                WISHDEBUG(LOG_DEBUG, "ruid mismatch");
            }
        }
        else {
            WISHDEBUG(LOG_DEBUG, "luid mismatch");
        }

    }

    if (!found) {
        wish_rpc_server_error(req, 344, "Friend request connection not found while trying to accept.");
        return;
    }
    
    // found the connection (wish_connection)

    // Check if identity is already in db

    int num_uids_in_db = wish_get_num_uid_entries();
    wish_uid_list_elem_t uid_list[num_uids_in_db];
    int num_uids = wish_load_uid_list(uid_list, num_uids_in_db);


    found = false;
    i = 0;
    for (i = 0; i < num_uids; i++) {
        if ( memcmp(&uid_list[i].uid, ruid, WISH_ID_LEN) == 0 ) {
            WISHDEBUG(LOG_CRITICAL, "Identity already in DB, we wont add it multiple times.");
            found = true;
            break;
        }
    }

    if(!found) {
        wish_save_identity_entry(&elt->id);
    }

    
    WISHDEBUG(LOG_CRITICAL, "Accepting friend request");
    struct wish_event new_evt = {
        .event_type = WISH_EVENT_ACCEPT_FRIEND_REQUEST,
        .context = wish_connection,
    };
    wish_message_processor_notify(&new_evt);

    
    int buffer_len = WISH_PORT_RPC_BUFFER_SZ;
    uint8_t buffer[buffer_len];

    bson bs;

    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_bool(&bs, "data", true);
    bson_finish(&bs);

    if(bs.err != 0) {
        wish_rpc_server_error(req, 344, "Failed writing reponse.");
        return;
    }

    wish_rpc_server_send(req, buffer, bson_get_doc_len(buffer));
    wish_platform_free(elt);
}

/*
 * identity.friendRequestDecline
 *
 * App to core: { op: "identity.friendRequestDecline", args: [ <Buffer> luid, <Buffer> ruid ], id: 5 }
 */
static void identity_friend_request_decline(rpc_server_req* req, uint8_t* args) {
    wish_core_t* core = (wish_core_t*) req->server->context;


    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    if(bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) != WISH_ID_LEN) {
        wish_rpc_server_error(req, 345, "Invalid luid.");
        return;
    }

    const char* luid = 0;
    luid = bson_iterator_bin_data(&it);

    bson_find_from_buffer(&it, args, "1");
    
    if(bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) != WISH_ID_LEN) {
        wish_rpc_server_error(req, 345, "Invalid ruid.");
        return;
    }

    const char* ruid = 0;
    ruid = bson_iterator_bin_data(&it);
    
    wish_relationship_req_t* elt;
    wish_relationship_req_t* tmp;
    
    bool found = false;
    
    DL_FOREACH_SAFE(core->relationship_req_db, elt, tmp) {
        if ( memcmp(elt->luid, luid, WISH_UID_LEN) == 0 
                && memcmp(elt->id.uid, ruid, WISH_UID_LEN) == 0 ) {
            found = true;
            DL_DELETE(core->relationship_req_db, elt);
            break;
        }
    }
    
    if (!found) {
        wish_rpc_server_error(req, 356, "No such friend request found.");
        return;
    }
    
    // Find the connection which was used for receiving the friend request   
    
    int i = 0;
    found = false;
    
    wish_connection_t* wish_connection = NULL;

    for (i = 0; i < WISH_CONTEXT_POOL_SZ; i++) {
        if (core->connection_pool[i].context_state == WISH_CONTEXT_FREE) {
            continue;
        }

        if (memcmp(core->connection_pool[i].luid, luid, WISH_ID_LEN) == 0) {
            if (memcmp(core->connection_pool[i].ruid, ruid, WISH_ID_LEN) == 0) {
                found = true;
                WISHDEBUG(LOG_CRITICAL, "Found the connection used for friend request, cnx state %i proto state: %i", core->connection_pool[i].context_state, core->connection_pool[i].curr_protocol_state);
                wish_connection = &core->connection_pool[i];
                break;
            }
            else {
                WISHDEBUG(LOG_DEBUG, "ruid mismatch");
            }
        }
        else {
            WISHDEBUG(LOG_DEBUG, "luid mismatch");
        }

    }

    if (!found) {
        wish_rpc_server_error(req, 344, "Friend request connection not found while trying to accept.");
        return;
    }
    
    // found the connection (wish_connection)
    
    WISHDEBUG(LOG_CRITICAL, "Declining friend request (informing requester)");
    struct wish_event new_evt = {
        .event_type = WISH_EVENT_DECLINE_FRIEND_REQUEST,
        .context = wish_connection,
    };
    wish_message_processor_notify(&new_evt);

    
    int buffer_len = WISH_PORT_RPC_BUFFER_SZ;
    uint8_t buffer[buffer_len];

    bson bs;

    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_bool(&bs, "data", true);
    bson_finish(&bs);

    if(bs.err != 0) {
        wish_rpc_server_error(req, 344, "Failed writing reponse.");
        return;
    }

    wish_rpc_server_send(req, buffer, bson_get_doc_len(buffer));
    wish_platform_free(elt);
}

/*
 * identity.get
 *
 * App to core: { op: "identity.get", args: [ Buffer(32) uid ], id: 5 }
 * Response core to App:
 *  { ack: 5, data: {
 *          alias: "Moster Greta",
 *          uid: <binary buffer containing the new wish user id>,
 *          privkey: true,
 *          pubkey: Buffer
 *      }
 *  }
 *
 *  Note that privkey is always returned as 'true' when doing
 *  identity.create (An identity creation always involves creation of
 *  private key and public key)
 */
static void identity_get_handler(rpc_server_req* req, uint8_t* args) {
    WISHDEBUG(LOG_DEBUG, "In identity_get_handler");

    bson bs; 
    bson_init(&bs);
    bson_append_start_object(&bs, "data");
    
    /* Get the uid of identity to get, the uid is argument "0" in
     * args */
    uint8_t *arg_uid = 0;
    int32_t arg_uid_len = 0;
    if (bson_get_binary(args, "0", &arg_uid, &arg_uid_len) != BSON_SUCCESS) {
        WISHDEBUG(LOG_CRITICAL, "Could not get argument: uid");
        return;
    }

    if (arg_uid_len != WISH_ID_LEN) {
        WISHDEBUG(LOG_CRITICAL, "argument uid has illegal length");
        return;
    }


    int num_uids_in_db = wish_get_num_uid_entries();
    wish_uid_list_elem_t uid_list[num_uids_in_db];
    int num_uids = wish_load_uid_list(uid_list, num_uids_in_db);

    int i = 0;
    for (i = 0; i < num_uids; i++) {
        if( memcmp(uid_list[i].uid, arg_uid, 32) != 0 ) {
            continue;
        }
        
        /* For each uid in DB, copy the uid, alias and privkey fields */
        size_t id_bson_doc_max_len = sizeof (wish_identity_t) + 100;
        uint8_t id_bson_doc[id_bson_doc_max_len];
        int ret = wish_load_identity_bson(uid_list[i].uid, id_bson_doc,
            id_bson_doc_max_len);
        
        if (ret == 1) {

            int32_t uid_len = 0;
            uint8_t *uid = NULL;
            if (bson_get_binary(id_bson_doc, "uid", &uid, &uid_len) 
                    == BSON_FAIL) {
                WISHDEBUG(LOG_CRITICAL, "Unexpected: no uid");
                break;
            }
            bson_append_binary(&bs, "uid", uid, uid_len);

            int32_t alias_len = 0;
            char *alias = NULL;
            if (bson_get_string(id_bson_doc, "alias", &alias, &alias_len)
                    == BSON_FAIL) {
                WISHDEBUG(LOG_CRITICAL, "Unexpected: no alias");
                break;
            }
            bson_append_string(&bs, "alias", alias);

            int32_t privkey_len = 0;
            uint8_t *privkey = NULL;
            bool privkey_status = false;
            if (bson_get_binary(id_bson_doc, "privkey", &privkey,
                    &privkey_len) == BSON_SUCCESS) {
                /* Privkey exists in database */
                privkey_status = true;
            }
            else {
                /* Privkey not in database */
                privkey_status = false;
            }
            bson_append_bool(&bs, "privkey", privkey_status);
            
            int32_t pubkey_len = 0;
            uint8_t *pubkey = NULL;
            if (bson_get_binary(id_bson_doc, "pubkey", &pubkey, &pubkey_len) == BSON_FAIL) {
                WISHDEBUG(LOG_CRITICAL, "Error while reading pubkey");
                wish_rpc_server_error(req, 509, "This is fail!");
                break;
            }
            bson_append_binary(&bs, "pubkey", pubkey, pubkey_len);
        } else {
            WISHDEBUG(LOG_CRITICAL, "Could not load identity");
            wish_rpc_server_error(req, 997, "Could not load identity");
        }
        
        break;
    }
    
    if (i >= num_uids) {
        WISHDEBUG(LOG_CRITICAL, "The identity was not found");
        wish_rpc_server_error(req, 997, "The identity was not found");
    } else {
        bson_append_finish_object(&bs);
        bson_finish(&bs);

        if (bs.err) {
            WISHDEBUG(LOG_CRITICAL, "BSON error in identity_get_handler");
            wish_rpc_server_error(req, 997, "BSON error in identity_get_handler");
        } else {
            wish_rpc_server_send(req, bs.data, bson_size(&bs));
        }
    }
    bson_destroy(&bs);
}

static void connections_list_handler(rpc_server_req* req, uint8_t* args) {
    wish_core_t* core = (wish_core_t*) req->server->context;
    
    int buffer_len = WISH_PORT_RPC_BUFFER_SZ;
    uint8_t buffer[buffer_len];
    
    wish_connection_t *db = wish_core_get_connection_pool(core);
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_start_array(&bs, "data");
    
    int i;
    int p = 0;
    for(i=0; i< WISH_CONTEXT_POOL_SZ; i++) {
        if(db[i].context_state != WISH_CONTEXT_FREE) {
            if (db[i].curr_protocol_state != PROTO_STATE_WISH_RUNNING) { continue; }
            
            bson_numstrn((char *)nbuf, NBUFL, p);
            //bson_append_start_object(&bs, nbuf);
            bson_append_start_object(&bs, (char *)nbuf);
            bson_append_int(&bs, "cid", i);
            bson_append_binary(&bs, "luid", db[i].luid, WISH_ID_LEN);
            bson_append_binary(&bs, "ruid", db[i].ruid, WISH_ID_LEN);
            bson_append_binary(&bs, "rhid", db[i].rhid, WISH_ID_LEN);
            //bson_append_bool(&bs, "online", true);
            bson_append_bool(&bs, "outgoing", db[i].outgoing);
            //bson_append_bool(&bs, "relay", db[i].via_relay);
            //bson_append_bool(&bs, "authenticated", true);
            /*
            bson_append_start_object(&bs, "transport");
            bson_append_string(&bs, "type", "tcp");
            bson_append_string(&bs, "localAddress", "5.5.5.5:5555");
            bson_append_string(&bs, "remoteAddress", "6.6.6.6:6666");
            bson_append_finish_object(&bs);
            */
            bson_append_finish_object(&bs);
            p++;
        }
    }

    bson_append_finish_array(&bs);
    bson_finish(&bs);
    
    if (bs.err) {
        wish_rpc_server_error(req, 303, "Failed writing bson.");
        return;
    }
    
    wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
}

static void connections_disconnect_handler(rpc_server_req* req, uint8_t* args) {
    wish_core_t* core = (wish_core_t*) req->server->context;
    
    int buffer_len = 1400;
    uint8_t buffer[buffer_len];
    
    wish_connection_t *db = wish_core_get_connection_pool(core);

    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    if (bson_iterator_type(&it) == BSON_INT) {

        int idx = bson_iterator_int(&it);
        
        wish_close_connection(core, &db[idx]);

        bson bs;

        bson_init_buffer(&bs, buffer, buffer_len);
        bson_append_bool(&bs, "data", true);
        bson_finish(&bs);

        if(bs.err != 0) {
            wish_rpc_server_error(req, 344, "Failed writing reponse.");
            return;
        }
        
        wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    } else {
        wish_rpc_server_error(req, 343, "Invalid argument. Int index.");
    }
}

/**
 *  
 */
static void connections_check_connections(rpc_server_req* req, uint8_t* args) {
    wish_core_t* core = (wish_core_t*) req->server->context;
    
    int buffer_len = 1400;
    uint8_t buffer[buffer_len];
    
    wish_connections_check(core);
    
    bson bs;

    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_bool(&bs, "data", true);
    bson_finish(&bs);

    if(bs.err != 0) {
        wish_rpc_server_error(req, 344, "Failed writing reponse.");
        return;
    }
    wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
}

/*
 * Wish Local Discovery
 *
 * App to core: { op: "wld.list", args: [ <Buffer> uid ], id: 5 }
 * Response core to App:
 *  { ack: 5, data: [item] }
 *
 *  item: {
 *   ruid: Buffer<>,
 *   rhid: Buffer<>,
 *   [pubkey: Buffer<>] // optional
 * }
 * 
 */
static void wld_list_handler(rpc_server_req* req, uint8_t* args) {
    wish_core_t* core = (wish_core_t*) req->server->context;
    
    int buffer_len = WISH_PORT_RPC_BUFFER_SZ;
    uint8_t buffer[buffer_len];
    
    wish_ldiscover_t *db = wish_ldiscover_get(core);

    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_start_array(&bs, "data");
    
    int i;
    int p = 0;
    for(i=0; i< WISH_LOCAL_DISCOVERY_MAX; i++) {
        if(db[i].occupied) {
            bson_numstrn((char *)nbuf, NBUFL, p);
            //bson_append_start_object(&bs, nbuf);
            bson_append_start_object(&bs, (char *)nbuf);
            bson_append_string(&bs, "alias", db[i].alias);
            bson_append_binary(&bs, "ruid", db[i].ruid, WISH_ID_LEN);
            bson_append_binary(&bs, "rhid", db[i].rhid, WISH_ID_LEN);
            bson_append_binary(&bs, "pubkey", db[i].pubkey, WISH_PUBKEY_LEN);
            bson_append_finish_object(&bs);
            p++;
        }
    }

    bson_append_finish_array(&bs);
    bson_finish(&bs);
    
    if (bs.err) {
        wish_rpc_server_error(req, 303, "Failed writing bson.");
        return;
    }
    
    wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
}

/**
 * Wish Local Discovery
 *
 * App to core: { op: "wld.announce", args: [], id: 5 }
 * Response core to App:
 *  { ack: 5, data: true }
 */
static void wld_announce_handler(rpc_server_req* req, uint8_t* args) {
    wish_core_t* core = (wish_core_t*) req->server->context;

    wish_ldiscover_announce_all(core);
    
    int buffer_len = WISH_PORT_RPC_BUFFER_SZ;
    uint8_t buffer[buffer_len];

    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_bool(&bs, "data", true);
    bson_finish(&bs);
    
    if (bs.err) {
        wish_rpc_server_error(req, 303, "Failed writing bson.");
        return;
    }
    
    wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
}

/*
 * Wish Local Discovery
 *
 * App to core: { op: "wld.list", args: [ <Buffer> uid ], id: 5 }
 * Response core to App:
 *  { ack: 5, data: [item] }
 *
 *  item: {
 *   ruid: Buffer<>,
 *   rhid: Buffer<>,
 *   [pubkey: Buffer<>] // optional
 * }
 * 
 */
static void wld_clear_handler(rpc_server_req* req, uint8_t* args) {
    wish_core_t* core = (wish_core_t*) req->server->context;
    
    int buffer_len = WISH_PORT_RPC_BUFFER_SZ;
    uint8_t buffer[buffer_len];
    
    wish_ldiscover_clear(core);

    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_bool(&bs, "data", true);
    bson_finish(&bs);
    
    if (bs.err) {
        wish_rpc_server_error(req, 303, "Failed writing bson.");
    }
    
    wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
}

/*
 * Wish Local Discovery
 *
 * App to core: { op: "wld.list", args: [ <Buffer> uid ], id: 5 }
 * Response core to App:
 *  { ack: 5, data: [item] }
 *
 *  item: {
 *   ruid: Buffer<>,
 *   rhid: Buffer<>,
 *   [pubkey: Buffer<>] // optional
 * }
 * 
 */



static void wld_friend_request_handler(rpc_server_req* req, uint8_t* args) {
    wish_core_t* core = (wish_core_t*) req->server->context;
    
    int buffer_len = WISH_PORT_RPC_BUFFER_SZ;
    uint8_t buffer[buffer_len];

    /* Get the uid of identity to export, the uid is argument "0" in
     * args */
    uint8_t *luid = 0;
    int32_t luid_len = 0;
    if (bson_get_binary(args, "0", &luid, &luid_len) != BSON_SUCCESS) {
        WISHDEBUG(LOG_CRITICAL, "Could not get argument: luid");
        return;
    }

    if (luid_len != WISH_ID_LEN) {
        WISHDEBUG(LOG_CRITICAL, "argument luid has illegal length");
        return;
    }

    uint8_t *ruid = 0;
    int32_t ruid_len = 0;
    if (bson_get_binary(args, "1", &ruid, &ruid_len) != BSON_SUCCESS) {
        WISHDEBUG(LOG_CRITICAL, "Could not get argument: ruid");
        return;
    }

    if (ruid_len != WISH_ID_LEN) {
        WISHDEBUG(LOG_CRITICAL, "argument ruid has illegal length");
        return;
    }

    uint8_t *rhid = 0;
    int32_t rhid_len = 0;
    if (bson_get_binary(args, "2", &rhid, &rhid_len) != BSON_SUCCESS) {
        WISHDEBUG(LOG_CRITICAL, "Could not get argument: rhid");
        return;
    }

    if (rhid_len != WISH_ID_LEN) {
        WISHDEBUG(LOG_CRITICAL, "argument rhid has illegal length");
        return;
    }

    // now check if we have the wld details for this entry
    
    wish_ldiscover_t *db = wish_ldiscover_get(core);

    bool found = false;
    
    int i;
    for(i=0; i< WISH_LOCAL_DISCOVERY_MAX; i++) {
        if( db[i].occupied && 
                memcmp(&db[i].ruid, ruid, WISH_ID_LEN) == 0 &&
                memcmp(&db[i].rhid, rhid, WISH_ID_LEN) == 0) {
            WISHDEBUG(LOG_CRITICAL, "Found in slot %d", i);
            found = true;
            break;
        }
    }
    
    if(!found) {
        wish_rpc_server_error(req, 304, "Wld entry not found.");
        return;
    }

    wish_connection_t *friend_req_ctx = wish_connection_init(core, luid, ruid);
    friend_req_ctx->friend_req_connection = true;
    uint8_t *ip = db[i].transport_ip.addr;
    
    WISHDEBUG(LOG_CRITICAL, "Will start a friend req connection to: %u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);

    wish_open_connection(core, friend_req_ctx, &(db[i].transport_ip), db[i].transport_port, false);

    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_bool(&bs, "data", true);
    bson_finish(&bs);
    
    if (bs.err) {
        wish_rpc_server_error(req, 303, "Failed writing bson.");
    }
    
    wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
}

static void host_config(rpc_server_req* req, uint8_t* args) {
    int buffer_len = WISH_PORT_RPC_BUFFER_SZ;
    uint8_t buffer[buffer_len];
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_start_object(&bs, "data");
    // FIXME version is shown in the separate version rpc command, consider removing this
    bson_append_string(&bs, "version", WISH_CORE_VERSION_STRING);
    bson_append_finish_object(&bs);
    bson_finish(&bs);

    if (bs.err) {
        wish_rpc_server_error(req, 305, "Failed writing bson.");
    }
    
    wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
}

static void relay_list(rpc_server_req* req, uint8_t* args) {
    wish_core_t* core = req->server->context;
    wish_app_entry_t* app = req->context;

    uint8_t buffer[WISH_PORT_RPC_BUFFER_SZ];
    
    bson bs;
    bson_init_buffer(&bs, buffer, WISH_PORT_RPC_BUFFER_SZ);
    bson_append_start_array(&bs, "data");
    
    wish_relay_client_t* relay;
    
    int i = 0;
    
    LL_FOREACH(core->relay_db, relay) {
        char index[21];
        BSON_NUMSTR(index, i);
        
        char host[22];
        
        snprintf(host, 22, "%d.%d.%d.%d:%d", relay->ip.addr[0], relay->ip.addr[1], relay->ip.addr[2], relay->ip.addr[3], relay->port);
        
        bson_append_start_object(&bs, index);
        bson_append_string(&bs, "host", host);
        bson_append_bool(&bs, "connected", relay->curr_state == WISH_RELAY_CLIENT_WAIT);
        bson_append_finish_object(&bs);
    }
    
    bson_append_finish_array(&bs);
    bson_finish(&bs);

    if (bs.err) {
        wish_rpc_server_error(req, 305, "Failed writing bson.");
        return;
    }
    
    wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
}

static void relay_add(rpc_server_req* req, uint8_t* args) {
    wish_core_t* core = req->server->context;
    wish_app_entry_t* app = req->context;

    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    if ( BSON_STRING != bson_iterator_type(&it) ) {
        wish_rpc_server_error(req, 306, "Could not add relay. Expecting string parameter host: 92.12.33.221:40000.");
        return;
    }
    
    const char* addr = bson_iterator_string(&it);
    int addr_len = bson_iterator_string_len(&it); 

    wish_relay_client_add(core, addr);
    
    uint8_t buffer[WISH_PORT_RPC_BUFFER_SZ];
    
    bson bs;
    bson_init_buffer(&bs, buffer, WISH_PORT_RPC_BUFFER_SZ);
    bson_append_bool(&bs, "data", true);
    bson_append_finish_array(&bs);
    bson_finish(&bs);

    if (bs.err) {
        wish_rpc_server_error(req, 305, "Failed writing bson.");
        return;
    }
    
    wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    
    wish_core_config_save(core);
}

static void relay_remove(rpc_server_req* req, uint8_t* args) {
    wish_core_t* core = req->server->context;
    wish_app_entry_t* app = req->context;

    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    if ( BSON_STRING != bson_iterator_type(&it) ) {
        wish_rpc_server_error(req, 306, "Could not remove relay. Expecting string parameter host: 92.12.33.221:40000.");
        return;
    }
    
    const char* addr = bson_iterator_string(&it);
    int addr_len = bson_iterator_string_len(&it); 

    wish_relay_client_t ctx;
    wish_parse_transport_ip_port(addr, addr_len, &ctx.ip, &ctx.port);
    
    wish_relay_client_t* relay;
    wish_relay_client_t* tmp;
    
    LL_FOREACH_SAFE(core->relay_db, relay, tmp) {
        if ( memcmp(&relay->ip.addr, &ctx.ip.addr, 4) != 0 || relay->port != ctx.port ) { continue; }
        LL_DELETE(core->relay_db, relay);
        wish_platform_free(relay);
    }
    
    uint8_t buffer[WISH_PORT_RPC_BUFFER_SZ];
    
    bson bs;
    bson_init_buffer(&bs, buffer, WISH_PORT_RPC_BUFFER_SZ);
    bson_append_bool(&bs, "data", true);
    bson_append_finish_array(&bs);
    bson_finish(&bs);

    if (bs.err) {
        wish_rpc_server_error(req, 305, "Failed writing bson.");
        return;
    }
    
    wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
}

/*
static void debug_enable(struct wish_rpc_context* req, 
                                uint8_t *args, wish_rpc_id_t req_id,
                                uint8_t *buffer, size_t buffer_len) {
    bool enable = true;
    bson_iterator it;
    bson_find_from_buffer(&it, args, "1");
    if (bson_iterator_type(&it) == BSON_BOOL) {
        if ( false == bson_iterator_bool(&it) ) {
            enable = false;
        }
    }
    bson_find_from_buffer(&it, args, "0");
    
    if (bson_iterator_type(&it) == BSON_INT) {

        int stream = bson_iterator_int(&it);
        
        wish_debug_set_stream(stream, enable);
        
        bson bs;

        bson_init_buffer(&bs, buffer, buffer_len);
        bson_append_bool(&bs, "data", true);
        bson_append_int(&bs, "ack", req_id);
        bson_finish(&bs);

        if(bs.err != 0) {
            write_bson_error(req, req_id, 344, "Failed writing reponse.");
        }
    } else {
        write_bson_error(req, req_id, 343, "Invalid argument. Int index.");
    }
}

static void debug_disable(struct wish_rpc_context* req, 
                                uint8_t *args, wish_rpc_id_t req_id,
                                uint8_t *buffer, size_t buffer_len) {
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    if (bson_iterator_type(&it) == BSON_INT) {

        int stream = bson_iterator_int(&it);
        
        wish_debug_set_stream(stream, false);
        
        bson bs;

        bson_init_buffer(&bs, buffer, buffer_len);
        bson_append_bool(&bs, "data", true);
        bson_append_int(&bs, "ack", req_id);
        bson_finish(&bs);

        if(bs.err != 0) {
            write_bson_error(req, req_id, 344, "Failed writing reponse.");
        }
    } else {
        write_bson_error(req, req_id, 343, "Invalid argument. Int index.");
    }
}
*/

handler methods_handler =                             { .op_str = "methods",                           .handler = methods };
handler signals_handler =                             { .op_str = "signals",                           .handler = wish_core_signals };
handler version_handler =                             { .op_str = "version",                           .handler = version };

handler services_send_handler =                       { .op_str = "services.send",                     .handler = services_send };

handler identity_sign_handler =                       { .op_str = "identity.sign",                     .handler = identity_sign };
handler identity_verify_handler =                     { .op_str = "identity.verify",                   .handler = identity_verify };
handler identity_friend_request_list_handler =        { .op_str = "identity.friendRequestList",        .handler = identity_friend_request_list };
handler identity_friend_request_accept_handler =      { .op_str = "identity.friendRequestAccept",      .handler = identity_friend_request_accept };
handler identity_friend_request_decline_handler =     { .op_str = "identity.friendRequestDecline",     .handler = identity_friend_request_decline };

handler directory_find_handler =                      { .op_str = "directory.find",                    .handler = wish_api_directory_find };

handler api_acl_check_h =                                 { .op_str = "acl.check",                         .handler = wish_api_acl_check };
handler api_acl_allow_h =                                 { .op_str = "acl.allow",                         .handler = wish_api_acl_allow };
handler api_acl_remove_allow_h =                          { .op_str = "acl.removeAllow",                   .handler = wish_api_acl_remove_allow };
handler api_acl_add_user_roles_h =                        { .op_str = "acl.addUserRoles",                  .handler = wish_api_acl_add_user_roles };
handler api_acl_remove_user_roles_h =                     { .op_str = "acl.removeUserRoles",               .handler = wish_api_acl_remove_user_roles };
handler api_acl_user_roles_h =                            { .op_str = "acl.userRoles",                     .handler = wish_api_acl_user_roles };
handler api_acl_what_resources_h =                        { .op_str = "acl.whatResources",                 .handler = wish_api_acl_what_resources };
handler api_acl_allowed_permissions_h =                   { .op_str = "acl.allowedPermissions",            .handler = wish_api_acl_allowed_permissions };
        
handler relay_list_handler =                          { .op_str = "relay.list",                        .handler = relay_list };
handler relay_add_handler =                           { .op_str = "relay.add",                         .handler = relay_add };
handler relay_remove_handler =                        { .op_str = "relay.remove",                      .handler = relay_remove };

handler host_config_handler =                         { .op_str = "host.config",                       .handler = host_config };

void wish_core_app_rpc_init(wish_core_t* core) {
    core->app_api = wish_platform_malloc(sizeof(wish_rpc_server_t));
    memset(core->app_api, 0, sizeof(wish_rpc_server_t));
    core->app_api->request_list_head = NULL;
    core->app_api->rpc_ctx_pool = wish_platform_malloc(sizeof(struct wish_rpc_context_list_elem)*10);
    memset(core->app_api->rpc_ctx_pool, 0, sizeof(struct wish_rpc_context_list_elem)*10);
    core->app_api->rpc_ctx_pool_num_slots = 10;
    strncpy(core->app_api->server_name, "core-from-app", 16);
    core->app_api->context = core;
    
    wish_rpc_server_register(core->app_api, &methods_handler);
    wish_rpc_server_register(core->app_api, &signals_handler);
    wish_rpc_server_register(core->app_api, &version_handler);
    
    wish_rpc_server_register(core->app_api, &services_send_handler);
    wish_rpc_server_add_handler(core->app_api, "services.list", services_list_handler);
    
    wish_rpc_server_add_handler(core->app_api, "identity.list", identity_list_handler);
    wish_rpc_server_add_handler(core->app_api, "identity.export", identity_export_handler);
    wish_rpc_server_add_handler(core->app_api, "identity.import", identity_import_handler);
    wish_rpc_server_add_handler(core->app_api, "identity.create", identity_create_handler);
    wish_rpc_server_add_handler(core->app_api, "identity.get", identity_get_handler);
    wish_rpc_server_add_handler(core->app_api, "identity.remove", identity_remove_handler);
    wish_rpc_server_register(core->app_api, &identity_sign_handler);
    wish_rpc_server_register(core->app_api, &identity_verify_handler);
    wish_rpc_server_register(core->app_api, &identity_friend_request_list_handler);
    wish_rpc_server_register(core->app_api, &identity_friend_request_accept_handler);
    wish_rpc_server_register(core->app_api, &identity_friend_request_decline_handler);
    wish_rpc_server_register(core->app_api, &directory_find_handler);
    
    wish_rpc_server_add_handler(core->app_api, "connections.list", connections_list_handler);
    wish_rpc_server_add_handler(core->app_api, "connections.disconnect", connections_disconnect_handler);
    wish_rpc_server_add_handler(core->app_api, "connections.checkConnections", connections_check_connections);

    wish_rpc_server_register(core->app_api, &api_acl_check_h);
    wish_rpc_server_register(core->app_api, &api_acl_allow_h);
    wish_rpc_server_register(core->app_api, &api_acl_remove_allow_h);
    wish_rpc_server_register(core->app_api, &api_acl_add_user_roles_h);
    wish_rpc_server_register(core->app_api, &api_acl_remove_user_roles_h);
    wish_rpc_server_register(core->app_api, &api_acl_user_roles_h);
    wish_rpc_server_register(core->app_api, &api_acl_what_resources_h);
    wish_rpc_server_register(core->app_api, &api_acl_allowed_permissions_h);

    wish_rpc_server_register(core->app_api, &relay_list_handler);
    wish_rpc_server_register(core->app_api, &relay_add_handler);
    wish_rpc_server_register(core->app_api, &relay_remove_handler);
    
    wish_rpc_server_add_handler(core->app_api, "wld.list", wld_list_handler);
    wish_rpc_server_add_handler(core->app_api, "wld.clear", wld_clear_handler);
    wish_rpc_server_add_handler(core->app_api, "wld.announce", wld_announce_handler);
    wish_rpc_server_add_handler(core->app_api, "wld.friendRequest", wld_friend_request_handler);
    
    wish_rpc_server_register(core->app_api, &host_config_handler);
    
    //wish_rpc_server_add_handler(core->core_app_rpc_server, "debug.enable", debug_enable);
    //wish_rpc_server_add_handler(core->core_app_rpc_server, "debug.disable", debug_disable);
}

static void wish_core_app_rpc_send(void *ctx, uint8_t *data, int len) {
    rpc_server_req* req = (rpc_server_req*) ctx;

    uint8_t* wsid = req->local_wsid;
    wish_core_t* core = (wish_core_t*) req->server->context;
    
    //bson_visit("wish_core_app_rpc_send:", data);
    
    send_core_to_app(core, wsid, data, len);
}

void wish_core_app_rpc_handle_req(wish_core_t* core, uint8_t src_wsid[WISH_ID_LEN], uint8_t *data) {
    wish_app_entry_t* app = wish_service_get_entry(core, src_wsid);
    
    char *op = NULL;
    int32_t op_str_len = 0;
    bson_get_string(data, "op", &op, &op_str_len);

    if (app==NULL) {
        // failed to find app, deny service
        WISHDEBUG(LOG_CRITICAL, "DENY op %s from unknown app", op);
        return;
    }

    //WISHDEBUG(LOG_CRITICAL, "op %s from app %s", op, app->service_name);
    
    uint8_t *args = NULL;
    int32_t args_len = 0;
    if (bson_get_array(data, "args", &args, &args_len) == BSON_FAIL) {
        WISHDEBUG(LOG_DEBUG, "Could not get args of incoming RPC message");
    }


    bool ack_required = false;
    int32_t id = 0;
    if (bson_get_int32(data, "id", &id)) {
        ack_required = true;
    }

    struct wish_rpc_context_list_elem *list_elem = wish_rpc_server_get_free_rpc_ctx_elem(core->app_api);
    if (list_elem == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Core app RPC: Could not save the rpc context. Failing in wish_core_app_rpc_func.");
        return;
    } else {
        struct wish_rpc_context *rpc_ctx = &(list_elem->request_ctx);
        rpc_ctx->server = core->app_api;
        rpc_ctx->send = wish_core_app_rpc_send;
        rpc_ctx->send_context = rpc_ctx;
        memcpy(rpc_ctx->op_str, op, MAX_RPC_OP_LEN);
        rpc_ctx->id = id;
        rpc_ctx->context = app;
        memcpy(rpc_ctx->local_wsid, src_wsid, WISH_WSID_LEN);
    
        if (wish_rpc_server_handle(core->app_api, rpc_ctx, args)) {
            WISHDEBUG(LOG_DEBUG, "RPC server fail: wish_core_app_rpc_func");
        }
    }
}

void wish_core_app_rpc_cleanup_requests(wish_core_t* core, uint8_t *wsid) {
    struct wish_rpc_context_list_elem *list_elem = NULL;
    struct wish_rpc_context_list_elem *tmp = NULL;
    LL_FOREACH_SAFE(core->app_api->request_list_head, list_elem, tmp) {
        if (memcmp(list_elem->request_ctx.local_wsid, wsid, WISH_WSID_LEN)) {
            WISHDEBUG(LOG_CRITICAL, "App rpc server clean up: request op %s", list_elem->request_ctx.op_str);
#ifdef WISH_RPC_SERVER_STATIC_REQUEST_POOL
            memset(&(list_elem->request_ctx), 0, sizeof(rpc_server_req));
#else
#error not implemented
            //wish_platform_free....
#endif
            LL_DELETE(core->app_api->request_list_head, list_elem);
        }
    }
}

void wish_send_peer_update_locals(wish_core_t* core, uint8_t *dst_wsid, struct wish_service_entry *service_entry, bool online) {
    WISHDEBUG(LOG_DEBUG, "In update locals");
    if (memcmp(dst_wsid, service_entry->wsid, WISH_ID_LEN) == 0) {
        /* Don't send any peer online/offline messages regarding service itself */
        return;
    }
    
    wish_uid_list_elem_t local_id_list[WISH_NUM_LOCAL_IDS];
    int num_local_ids = wish_get_local_identity_list(local_id_list, WISH_NUM_LOCAL_IDS);
    if (num_local_ids == 0) {
        WISHDEBUG(LOG_CRITICAL, "Unexpected: no local identities");
        return;
    } else {
        WISHDEBUG(LOG_DEBUG, "Local id list: %i", num_local_ids);
    }
    
    uint8_t local_hostid[WISH_WHID_LEN];
    wish_core_get_host_id(core, local_hostid);
            
            
    int i = 0;
    int j = 0;
    for (i = 0; i < num_local_ids; i++) {
        for (j = 0; j < num_local_ids; j++) {
            bson bs;
            int buffer_len = 2 * WISH_ID_LEN + WISH_WSID_LEN + WISH_WHID_LEN + WISH_PROTOCOL_NAME_MAX_LEN + 200;
            uint8_t buffer[buffer_len];
            bson_init_buffer(&bs, buffer, buffer_len);
            
            bson_append_string(&bs, "type", "peer");
            bson_append_start_object(&bs, "peer");
            bson_append_binary(&bs, "luid", (uint8_t*) local_id_list[i].uid, WISH_ID_LEN);
            bson_append_binary(&bs, "ruid", (uint8_t*) local_id_list[j].uid, WISH_ID_LEN);
            bson_append_binary(&bs, "rsid", (uint8_t*) service_entry->wsid, WISH_WSID_LEN);
            bson_append_binary(&bs, "rhid", (uint8_t*) local_hostid, WISH_ID_LEN);
            /* FIXME support more protocols than just one */
            bson_append_string(&bs, "protocol", service_entry->protocols[0].name);   
            bson_append_string(&bs, "type", "N");
            bson_append_bool(&bs, "online", online);
            bson_append_finish_object(&bs);
           
            bson_finish(&bs);
            if (bs.err) {
                WISHDEBUG(LOG_CRITICAL, "BSON error when creating peer message: %i %s len %i", bs.err, bs.errstr, bs.dataSize);
            }
            else {
                send_core_to_app(core, dst_wsid, (uint8_t *) bson_data(&bs), bson_size(&bs));
            }
        }
    }
}

/** Report the existence of the new identity to local services:
 *
 * Let the new identity to be i.
 * Let the local host identity to be h.
 * For every service "s" present in the local service registry, do;
 *    For every service "r" present in the local service registry, do:
 *      Construct "type: peer", "online: true", message with: <luid=i, ruid=i, rsid=r, rhid=h> and send it to s. If r == s, skip to avoid sending online message to service itself.
 *    done
 * done.      
 * 
 * @param identity the identity to send updates for
 * @param online true, if the identity is online (e.g. true when identity is created, false when identity is deleted)
 */
void wish_report_identity_to_local_services(wish_core_t* core, wish_identity_t* identity, bool online) {
    uint8_t local_hostid[WISH_WHID_LEN];
    wish_core_get_host_id(core, local_hostid);
    struct wish_service_entry *service_registry = wish_service_get_registry(core);
    int i = 0;
    for (i = 0; i < WISH_MAX_SERVICES; i++) {
        if (wish_service_entry_is_valid(core, &(service_registry[i]))) {
            int j = 0;
            for (j = 0; j < WISH_MAX_SERVICES; j++) {
                if (wish_service_entry_is_valid(core, &(service_registry[j]))) {
                    if (memcmp(service_registry[i].wsid, service_registry[j].wsid, WISH_WSID_LEN) != 0) {
                        bson bs;
                        int buffer_len = 2 * WISH_ID_LEN + WISH_WSID_LEN + WISH_WHID_LEN + WISH_PROTOCOL_NAME_MAX_LEN + 200;
                        uint8_t buffer[buffer_len];
                        bson_init_buffer(&bs, buffer, buffer_len);

                        bson_append_string(&bs, "type", "peer");
                        
                        bson_append_start_object(&bs, "peer");
                        bson_append_binary(&bs, "luid", (uint8_t*) identity->uid, WISH_ID_LEN);
                        bson_append_binary(&bs, "ruid", (uint8_t*) identity->uid, WISH_ID_LEN);
                        bson_append_binary(&bs, "rsid", (uint8_t*) service_registry[j].wsid, WISH_WSID_LEN);
                        bson_append_binary(&bs, "rhid", (uint8_t*) local_hostid, WISH_ID_LEN);
                        /* FIXME support more protocols than just one */
                        bson_append_string(&bs, "protocol", service_registry[j].protocols[0].name);
                        
                        bson_append_string(&bs, "type", "N");   /* FIXME will be type:"D" someday when deleting identity? */
                        bson_append_bool(&bs, "online", online);
                        bson_append_finish_object(&bs);

                        bson_finish(&bs);
                        if (bs.err) {
                            WISHDEBUG(LOG_CRITICAL, "BSON error when creating peer message: %i %s len %i", bs.err, bs.errstr, bs.dataSize);
                        }
                        else {
                            //WISHDEBUG(LOG_CRITICAL, "Sending peer message to app %s:", service_registry[i].service_name);
                            //bson_visit("Sending peer message to app:", buffer);
                            send_core_to_app(core, service_registry[i].wsid, (uint8_t *) bson_data(&bs), bson_size(&bs));
                        }
                    }
                }
            }
        }
    }
}
