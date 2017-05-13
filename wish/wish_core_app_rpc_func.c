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
        if (h->args) { bson_append_string(&bs, "args", h->args); }
        if (h->doc) { bson_append_string(&bs, "doc", h->doc); }
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
static void services_list(rpc_server_req* req, uint8_t* args) {
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

/* This is the Call-back function invoked by the core's "app" RPC
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
static void identity_export(rpc_server_req* req, uint8_t* args) {
    wish_core_t* core = req->server->context;
    wish_app_entry_t* app = req->context;
    
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    if ( bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) != WISH_UID_LEN ) {
        WISHDEBUG(LOG_CRITICAL, "Could not get argument[0]: uid, expecting Buffer(32)");
        wish_rpc_server_error(req, 8, "Missing export uid argument, expecting Buffer(32)");
        return;
    }

    const uint8_t* uid = bson_iterator_bin_data(&it);
    
    wish_identity_t id;
    
    if ( RET_SUCCESS != wish_identity_load(uid, &id) ) {
        wish_rpc_server_error(req, 343, "Failed to load identity.");
        return;
    }

    char buf_base[WISH_PORT_RPC_BUFFER_SZ];
    
    bin buf;
    buf.base = buf_base;
    buf.len = WISH_PORT_RPC_BUFFER_SZ;
    
    if ( RET_SUCCESS != wish_identity_export(core, &id, &buf) ) {
        wish_rpc_server_error(req, 92, "Internal export failed.");
        return;
    }
    
    bson bs;
    bson_init_with_data(&bs, buf.base);

    char buf_base2[WISH_PORT_RPC_BUFFER_SZ];
    
    bin buf2;
    buf2.base = buf_base2;
    buf2.len = WISH_PORT_RPC_BUFFER_SZ;
    
    bson b;
    bson_init_buffer(&b, buf2.base, buf2.len);
    bson_append_bson(&b, "data", &bs);
    bson_finish(&b);
    
    wish_rpc_server_send(req, bson_data(&b), bson_size(&b));
}

/* This is the Call-back function invoked by the core's "app" RPC
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
static void identity_import(rpc_server_req* req, uint8_t* args) {
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

/* This is the Call-back function invoked by the core's "app" RPC
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
static void identity_list(rpc_server_req* req, uint8_t* args) {
    
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
static void identity_create(rpc_server_req* req, uint8_t* args) {
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
static void identity_remove(rpc_server_req* req, uint8_t* args) {
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
        if (wish_identity_load(luid, &id_to_remove) == RET_SUCCESS) {
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
        return;
    }
}

/*
 * identity.sign
 *
 * App to core: { op: "identity.sign", args: [ <Buffer> uid, <Buffer> hash ], id: 5 }
 */
static void identity_sign(rpc_server_req* req, uint8_t* args) {
    wish_core_t* core = (wish_core_t*) req->server->context;
    
    int buffer_len = WISH_PORT_RPC_BUFFER_SZ;
    uint8_t buffer[buffer_len];

    // allocate space for signature and privkey
    uint8_t signature_base[ED25519_SIGNATURE_LEN];
    
    bin signature;
    signature.base = signature_base;
    signature.len = ED25519_SIGNATURE_LEN;

    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    if(bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) != WISH_ID_LEN) {
        wish_rpc_server_error(req, 345, "Invalid uid.");
        return;
    }

    uint8_t* luid = (uint8_t *)bson_iterator_bin_data(&it);
    
    wish_identity_t uid;
    
    // check if we can make a signature with this identity
    if (wish_identity_load(luid, &uid) != RET_SUCCESS) {
        WISHDEBUG(LOG_CRITICAL, "Could not load identity");
        wish_rpc_server_error(req, 345, "Could not load identity.");
        return;
    }
    
    bin claim;
    claim.base = NULL;
    claim.len = 0;

    bson_find_from_buffer(&it, args, "2");

    if(bson_iterator_type(&it) == BSON_BINDATA && bson_iterator_bin_len(&it) >= 5 && bson_iterator_bin_len(&it) <= 512 ) {
        claim.base = (char*) bson_iterator_bin_data(&it);
        claim.len = bson_iterator_bin_len(&it);
        WISHDEBUG(LOG_CRITICAL, "Sign with claim. %p %i", claim.base, claim.len);
    }
    
    bson_find_from_buffer(&it, args, "1");
    
    if(bson_iterator_type(&it) == BSON_BINDATA && bson_iterator_bin_len(&it) >= 32 && bson_iterator_bin_len(&it) <= 64 ) {
        // sign hash
        char hash[64];
        int hash_len = bson_iterator_bin_len(&it);

        memcpy(hash, bson_iterator_bin_data(&it), hash_len);

        //wish_debug_print_array(LOG_DEBUG, signature, ED25519_SIGNATURE_LEN);

        bson bs;

        bson_init_buffer(&bs, buffer, buffer_len);
        bson_append_binary(&bs, "data", signature.base, ED25519_SIGNATURE_LEN);
        bson_finish(&bs);

        if(bs.err != 0) {
            wish_rpc_server_error(req, 344, "Failed writing reponse.");
            return;
        }

        wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    } else if (bson_iterator_type(&it) == BSON_OBJECT) {
        // sign object { data: Buffer(n) }

        bson b;

        bson_init_buffer(&b, buffer, buffer_len);
        bson_append_start_object(&b, "data");
        
        bson_iterator_from_buffer(&it, args);
        
        if ( bson_find_fieldpath_value("1.data", &it) != BSON_BINDATA ) {
            WISHDEBUG(LOG_CRITICAL, "1.data not bin data");
            
            wish_rpc_server_error(req, 345, "Second arg object does not have { data: <Buffer> }.");
            return;
        }

        // copy the data blob to response
        bin data;
        data.base = (char*) bson_iterator_bin_data(&it);
        data.len = bson_iterator_bin_len(&it);
        
        bson_append_binary(&b, "data", data.base, data.len);
        
        bson_append_field_from_iterator(&it, &b);

        bson_iterator_from_buffer(&it, args);
        
        if ( bson_find_fieldpath_value("1.meta", &it) != BSON_EOO ) {
            WISHDEBUG(LOG_CRITICAL, "1.meta");
            bson_append_field_from_iterator(&it, &b);
        }

        bson_iterator_from_buffer(&it, args);

        bson_append_start_array(&b, "signatures");

        char index[21];
        int i = 0;
        
        // copy signatures already present
        if ( bson_find_fieldpath_value("1.signatures.0", &it) != BSON_EOO ) {
            
            do {
                BSON_NUMSTR(index, i++);
                WISHDEBUG(LOG_CRITICAL, "1.signatures.0 already present, should be copied. %i", i);
                bson_append_element(&b, index, &it);
            } while ( bson_iterator_next(&it) != BSON_EOO );
        }
        
        // add signature by uid
        wish_identity_sign(core, &uid, &data, &claim, &signature);
        
        BSON_NUMSTR(index, i++);

        bson_append_start_object(&b, index);
        bson_append_string(&b, "algo", "sha256-ed25519");
        bson_append_binary(&b, "uid", luid, WISH_UID_LEN);
        bson_append_binary(&b, "sign", signature.base, ED25519_SIGNATURE_LEN);
        if (claim.base != NULL && claim.len > 0) {
            bson_append_binary(&b, "claim", claim.base, claim.len);
        }
        
        bson_append_finish_object(&b);
        bson_append_finish_array(&b);
        
        bson_append_finish_object(&b);
        bson_finish(&b);

        if(b.err != 0) {
            wish_rpc_server_error(req, 344, "Failed writing reponse.");
            return;
        }
        
        wish_rpc_server_send(req, bson_data(&b), bson_size(&b));
        return;
    } else {
        wish_rpc_server_error(req, 345, "Second arg not valid hash or object.");
        return;
    }
}

/*
 * identity.verify
 *
 * args: BSON(
 *   [ { 
 *     data: <Buffer>,
 *     meta: <Buffer>,
 *     signatures: [{ 
 *       uid: Buffer,
 *       sign: Buffer,
 *       claim?: Buffer }] ] })
 * 
 * return: BSON(
 *   [ { 
 *     data: <Buffer>,
 *     meta: <Buffer>,
 *     signatures: [{ 
 *       uid: Buffer,
 *       sign: bool | null, // bool: verification result, null: unable to verify signature
 *       claim?: Buffer }] ] })
 */
static void identity_verify(rpc_server_req* req, uint8_t* args) {
    wish_core_t* core = (wish_core_t*) req->server->context;
    
    uint8_t buffer[WISH_PORT_RPC_BUFFER_SZ];

    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    if(bson_iterator_type(&it) != BSON_OBJECT) {
        wish_rpc_server_error(req, 345, "Expected object");
        return;
    }

    bson b;

    bson_init_buffer(&b, buffer, WISH_PORT_RPC_BUFFER_SZ);
    bson_append_start_object(&b, "data");

    bson_iterator_from_buffer(&it, args);

    if ( bson_find_fieldpath_value("0.data", &it) != BSON_BINDATA ) {
        WISHDEBUG(LOG_CRITICAL, "0.data not bin data");

        wish_rpc_server_error(req, 345, "Object does not have { data: <Buffer> }.");
        return;
    }

    // copy the data blob to response
    bin data;
    data.base = (char*) bson_iterator_bin_data(&it);
    data.len = bson_iterator_bin_len(&it);

    bson_append_binary(&b, "data", data.base, data.len);

    bson_append_field_from_iterator(&it, &b);

    bson_iterator_from_buffer(&it, args);

    if ( bson_find_fieldpath_value("0.meta", &it) != BSON_EOO ) {
        WISHDEBUG(LOG_CRITICAL, "0.meta");
        bson_append_field_from_iterator(&it, &b);
    }

    bson_iterator_from_buffer(&it, args);

    bson_append_start_array(&b, "signatures");

    char index[21];
    int i = 0;

    // parse signature array
    if ( bson_find_fieldpath_value("0.signatures.0", &it) == BSON_OBJECT ) {
        do {
            BSON_NUMSTR(index, i++);
            bson_append_start_object(&b, index);
            
            WISHDEBUG(LOG_CRITICAL, "0.signatures.0 already present, should be verified. %i %s", bson_iterator_type(&it), bson_iterator_key(&it));
            bson obj;
            bson_iterator_subobject(&it, &obj);
            bson_iterator sit;
            bson_iterator_init(&sit, &obj);
            
            const char* uid = NULL;
            
            bin claim;
            memset(&claim, 0, sizeof(bin));
            
            bin signature;
            memset(&signature, 0, sizeof(bin));
            
            while ( bson_iterator_next(&sit) != BSON_EOO ) {
                WISHDEBUG(LOG_CRITICAL, "  sub object %i: %s", bson_iterator_type(&sit), bson_iterator_key(&sit));
                if (strncmp("sign", bson_iterator_key(&sit), 5) == 0 && bson_iterator_type(&sit) == BSON_BINDATA && bson_iterator_bin_len(&sit) == WISH_SIGNATURE_LEN ) {
                    signature.base = (char*) bson_iterator_bin_data(&sit);
                    signature.len = bson_iterator_bin_len(&sit);
                } else if (strncmp("uid", bson_iterator_key(&sit), 4) == 0 && bson_iterator_type(&sit) == BSON_BINDATA && bson_iterator_bin_len(&sit) == WISH_UID_LEN ) {
                    uid = bson_iterator_bin_data(&sit);
                    bson_append_element(&b, bson_iterator_key(&sit), &sit);
                } else if (strncmp("claim", bson_iterator_key(&sit), 6) == 0 && bson_iterator_type(&sit) == BSON_BINDATA ) {
                    claim.base = (char*) bson_iterator_bin_data(&sit);
                    claim.len = bson_iterator_bin_len(&sit);
                    bson_append_element(&b, bson_iterator_key(&sit), &sit);
                } else {
                    bson_append_element(&b, bson_iterator_key(&sit), &sit);
                }
            }
            
            if (signature.base != NULL && uid != NULL) {
                wish_identity_t id;
                
                if ( RET_SUCCESS == wish_identity_load(uid, &id) ) {
                    if ( RET_SUCCESS == wish_identity_verify(core, &id, &data, &claim, &signature) ) {
                        bson_append_bool(&b, "sign", true);
                    } else {
                        bson_append_bool(&b, "sign", false);
                    }
                } else {
                    bson_append_null(&b, "sign");
                }
            }
            
            bson_append_finish_object(&b);
        } while ( bson_iterator_next(&it) != BSON_EOO );
    }

    bson_append_finish_array(&b);

    bson_append_finish_object(&b);
    bson_finish(&b);

    if(b.err != 0) {
        wish_rpc_server_error(req, 344, "Failed writing reponse.");
        return;
    }

    wish_rpc_server_send(req, bson_data(&b), bson_size(&b));
}

/*
 * identity.friendRequest
 *
 * args: [{ 
    data: Buffer,
    meta?: Buffer,
    signatures?: any[] }]
 */
static void identity_friend_request(rpc_server_req* req, uint8_t* args) {
    wish_core_t* core = (wish_core_t*) req->server->context;
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");

    const char* luid = NULL;
    
    if (bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) != WISH_UID_LEN ) {
        wish_rpc_server_error(req, 345, "Expected luid: Buffer(32)");
        return;
    }
    
    luid = bson_iterator_bin_data(&it);

    bson_find_from_buffer(&it, args, "1");
    
    if(bson_iterator_type(&it) != BSON_OBJECT) {
        wish_rpc_server_error(req, 345, "Expected object");
        return;
    }

    bson_iterator_from_buffer(&it, args);

    if ( bson_find_fieldpath_value("1.data", &it) != BSON_BINDATA ) {
        WISHDEBUG(LOG_CRITICAL, "1.data not bin data");

        wish_rpc_server_error(req, 345, "Object does not have { data: <Buffer> }.");
        return;
    }

    bson_iterator data;
    bson_iterator_from_buffer(&data, bson_iterator_bin_data(&it));
    
    const char* ruid = NULL;
    const char* pubkey = NULL;
    const char* alias = NULL;
    
    bson_find_fieldpath_value("uid", &data);
    
    if (bson_iterator_type(&data) != BSON_BINDATA || bson_iterator_bin_len(&data) != WISH_UID_LEN ) {
        wish_rpc_server_error(req, 351, "uid not Buffer(32)");
        return;
    }

    ruid = bson_iterator_bin_data(&data);
    
    bson_iterator_from_buffer(&data, bson_iterator_bin_data(&it));
    bson_find_fieldpath_value("pubkey", &data);
    
    if (bson_iterator_type(&data) != BSON_BINDATA || bson_iterator_bin_len(&data) != WISH_PUBKEY_LEN ) {
        wish_rpc_server_error(req, 351, "pubkey not Buffer(32)");
        return;
    }

    pubkey = bson_iterator_bin_data(&data);
    
    bson_iterator_from_buffer(&data, bson_iterator_bin_data(&it));
    bson_find_fieldpath_value("alias", &data);
    
    if (bson_iterator_type(&data) != BSON_STRING) {
        wish_rpc_server_error(req, 351, "alias not string");
        return;
    }

    alias = bson_iterator_string(&data);

    const char* transport = NULL;
    bson_iterator_from_buffer(&it, args);

    if ( bson_find_fieldpath_value("1.meta", &it) == BSON_BINDATA ) {
        WISHDEBUG(LOG_CRITICAL, "1.meta");
        bson_iterator meta;
        bson_iterator_from_buffer(&meta, bson_iterator_bin_data(&it));


        bson_find_fieldpath_value("transports.0", &meta);

        if (bson_iterator_type(&meta) != BSON_STRING) {
            wish_rpc_server_error(req, 351, "transports not string");
            return;
        }

        if ( memcmp("wish://", bson_iterator_string(&meta), 7) ) {
            transport = bson_iterator_string(&meta) + 7;
        } else {
            transport = bson_iterator_string(&meta);
        }
    }
    
    if (transport == NULL) {
        wish_rpc_server_error(req, 351, "No transports available.");
    }
    
    WISHDEBUG(LOG_CRITICAL, "alias for remote friend req: %s", alias);
    WISHDEBUG(LOG_CRITICAL, "tranport for remote friend req: %s", transport);


    
    wish_connection_t* friend_req_ctx = wish_connection_init(core, luid, ruid);
    friend_req_ctx->friend_req_connection = true;
    //memcpy(friend_req_ctx->rhid, rhid, WISH_ID_LEN);
        
    //uint8_t *ip = db[i].transport_ip.addr;
    
    wish_ip_addr_t ip;
    uint16_t port;
    
    wish_parse_transport_ip_port(transport, strnlen(transport, 32), &ip, &port);
    
    WISHDEBUG(LOG_CRITICAL, "Will start a friend req connection to: %u.%u.%u.%u\n", ip.addr[0], ip.addr[1], ip.addr[2], ip.addr[3]);

    wish_open_connection(core, friend_req_ctx, &ip, port, false);
    
    
    
    
    
    
    uint8_t buffer[WISH_PORT_RPC_BUFFER_SZ];

    bson b;
    bson_init_buffer(&b, buffer, WISH_PORT_RPC_BUFFER_SZ);
    bson_append_bool(&b, "data", true);
    bson_finish(&b);

    if(b.err != 0) {
        wish_rpc_server_error(req, 344, "Failed writing reponse.");
        return;
    }

    wish_rpc_server_send(req, bson_data(&b), bson_size(&b));
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
    
    /* The friend request has been accepted, send our certificate as a RPC response to the remote core that originally sent us the core-to-core friend request. */
    size_t signed_cert_buffer_len = 1024;
    uint8_t signed_cert_buffer[signed_cert_buffer_len];
    bin signed_cert = { .base = signed_cert_buffer, .len = signed_cert_buffer_len };
    
    if (wish_build_signed_cert(core, elt->luid, &signed_cert) == RET_FAIL) {
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
    bson_append_bson(&b, "data", &cert);
    bson_finish(&b);
    
    bson_visit("Signed cert buffer: ", bson_data(&b));

    wish_rpc_server_send(&(elt->friend_rpc_req), bson_data(&b), bson_size(&b));
    
    WISHDEBUG(LOG_CRITICAL, "Send friend req reply, closing connection now");
    wish_close_connection(core, wish_connection);
            
    
    /* Send RPC reply to the App that performed the friendRequestAccept RPC*/
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
    
    WISHDEBUG(LOG_CRITICAL, "Declining friend request (informing requester) and closing connection");
    
    /* Send a relationship decline notification to remote core, as an RPC error */
    wish_rpc_server_error(&(elt->friend_rpc_req), 123, "Declining friend request.");
    wish_close_connection(core, wish_connection);
    
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
static void identity_get(rpc_server_req* req, uint8_t* args) {
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

static void connections_list(rpc_server_req* req, uint8_t* args) {
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

static void connections_disconnect(rpc_server_req* req, uint8_t* args) {
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
static void wld_list(rpc_server_req* req, uint8_t* args) {
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
            if (db[i].claim) {
                bson_append_bool(&bs, "claim", true);
            }
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
static void wld_announce(rpc_server_req* req, uint8_t* args) {
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
static void wld_clear(rpc_server_req* req, uint8_t* args) {
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



static void wld_friend_request(rpc_server_req* req, uint8_t* args) {
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
    memcpy(friend_req_ctx->rhid, rhid, WISH_ID_LEN);
        
    uint8_t *ip = db[i].transport_ip.addr;
    
    WISHDEBUG(LOG_CRITICAL, "Will start a friend req connection to: %u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);

    wish_open_connection(core, friend_req_ctx, &(db[i].transport_ip), db[i].transport_port, false);

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
        return;
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
    
    wish_relay_client_t* relay = NULL;
    
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
    
    bool found = false;
    
    LL_FOREACH_SAFE(core->relay_db, relay, tmp) {
        if ( memcmp(&relay->ip.addr, &ctx.ip.addr, 4) != 0 || relay->port != ctx.port ) { continue; }

        found = true;
        
        // close the underlying connection
        wish_relay_client_close(core, relay);
        
        LL_DELETE(core->relay_db, relay);
        wish_platform_free(relay);
    }
    
    uint8_t buffer[WISH_PORT_RPC_BUFFER_SZ];
    
    bson bs;
    bson_init_buffer(&bs, buffer, WISH_PORT_RPC_BUFFER_SZ);
    bson_append_bool(&bs, "data", found);
    bson_append_finish_array(&bs);
    bson_finish(&bs);

    if (bs.err) {
        wish_rpc_server_error(req, 305, "Failed writing bson.");
        return;
    }

    wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    
    wish_core_config_save(core);
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


handler methods_h =                                   { .op_str = "methods",                           .handler = methods, .args = "(void): string" };
handler signals_h =                                   { .op_str = "signals",                           .handler = wish_core_signals, .args = "(filter?: string): Signal" };
handler version_h =                                   { .op_str = "version",                           .handler = version, .args = "(void): string", .doc = "Returns core version." };

handler services_send_h =                             { .op_str = "services.send",                     .handler = services_send, .args = "(peer: Peer, payload: Buffer): bool", .doc = "Send payload to peer." };
handler services_list_h =                             { .op_str = "services.list",                     .handler = services_list, .args = "(void): Service[]", .doc = "List local services." };

handler identity_list_h =                             { .op_str = "identity.list",                     .handler = identity_list, .args="(void): Identity[]" };
handler identity_export_h =                           { .op_str = "identity.export",                   .handler = identity_export, .args="(void): Document" };
handler identity_import_h =                           { .op_str = "identity.import",                   .handler = identity_import, .args="(identity: Document): Identity" };
handler identity_create_h =                           { .op_str = "identity.create",                   .handler = identity_create, .args="(alias: string): Identity" };
handler identity_get_h =                              { .op_str = "identity.get",                      .handler = identity_get, .args="(uid: Uid): Identity" };
handler identity_remove_h =                           { .op_str = "identity.remove",                   .handler = identity_remove, .args="(uid: Uid): bool" };

handler identity_sign_h =                             { .op_str = "identity.sign",                     .handler = identity_sign, .args="(uid: Uid, document: Document): Document" };
handler identity_verify_h =                           { .op_str = "identity.verify",                   .handler = identity_verify, .args = "(document: Document): Document" };
handler identity_friend_request_h =                   { .op_str = "identity.friendRequest",            .handler = identity_friend_request, .args = "(luid: Uid, contact: Contact): bool" };
handler identity_friend_request_list_h =              { .op_str = "identity.friendRequestList",        .handler = identity_friend_request_list, .args = "(void): FriendRequest[]" };
handler identity_friend_request_accept_h =            { .op_str = "identity.friendRequestAccept",      .handler = identity_friend_request_accept, .args = "(luid: Uid, ruid: Uid): bool" };
handler identity_friend_request_decline_h =           { .op_str = "identity.friendRequestDecline",     .handler = identity_friend_request_decline, .args = "(luid: Uid, ruid: Uid): bool" };

handler connections_list_h =                          { .op_str = "connections.list",                  .handler = connections_list, .args = "(void): Connection[]" };
handler connections_disconnect_h =                    { .op_str = "connections.disconnect",            .handler = connections_disconnect, .args = "(id: number): bool" };
handler connections_check_connections_h =             { .op_str = "connections.checkConnections",      .handler = connections_check_connections, .args = "(id: number): bool" };

handler directory_find_h =                            { .op_str = "directory.find",                    .handler = wish_api_directory_find, .args = "(filter?: string): DirectoryEntry" };

handler api_acl_check_h =                             { .op_str = "acl.check",                         .handler = wish_api_acl_check };
handler api_acl_allow_h =                             { .op_str = "acl.allow",                         .handler = wish_api_acl_allow };
handler api_acl_remove_allow_h =                      { .op_str = "acl.removeAllow",                   .handler = wish_api_acl_remove_allow };
handler api_acl_add_user_roles_h =                    { .op_str = "acl.addUserRoles",                  .handler = wish_api_acl_add_user_roles };
handler api_acl_remove_user_roles_h =                 { .op_str = "acl.removeUserRoles",               .handler = wish_api_acl_remove_user_roles };
handler api_acl_user_roles_h =                        { .op_str = "acl.userRoles",                     .handler = wish_api_acl_user_roles };
handler api_acl_what_resources_h =                    { .op_str = "acl.whatResources",                 .handler = wish_api_acl_what_resources };
handler api_acl_allowed_permissions_h =               { .op_str = "acl.allowedPermissions",            .handler = wish_api_acl_allowed_permissions };
        
handler relay_list_h =                                { .op_str = "relay.list",                        .handler = relay_list, .args = "(void): Relay[]" };
handler relay_add_h =                                 { .op_str = "relay.add",                         .handler = relay_add, .args = "(relay: string): bool" };
handler relay_remove_h =                              { .op_str = "relay.remove",                      .handler = relay_remove, .args = "(relay: string): bool" };

handler wld_list_h =                                  { .op_str = "wld.list",                          .handler = wld_list, .args = "(void): Identity[]" };
handler wld_clear_h =                                 { .op_str = "wld.clear",                         .handler = wld_clear, .args = "(void): bool" };
handler wld_announce_h =                              { .op_str = "wld.announce",                      .handler = wld_announce, .args = "(void): bool" };
handler wld_friend_request_h =                        { .op_str = "wld.friendRequest",                 .handler = wld_friend_request, .args = "(luid: Uid, ruid: Uid, rhid: Hid): bool" };

handler host_config_h =                               { .op_str = "host.config",                       .handler = host_config };

void wish_core_app_rpc_init(wish_core_t* core) {
    core->app_api = wish_platform_malloc(sizeof(wish_rpc_server_t));
    memset(core->app_api, 0, sizeof(wish_rpc_server_t));
    core->app_api->request_list_head = NULL;
    core->app_api->rpc_ctx_pool = wish_platform_malloc(sizeof(struct wish_rpc_context_list_elem)*WISH_PORT_APP_RPC_POOL_SZ);
    memset(core->app_api->rpc_ctx_pool, 0, sizeof(struct wish_rpc_context_list_elem)*WISH_PORT_APP_RPC_POOL_SZ);
    core->app_api->rpc_ctx_pool_num_slots = WISH_PORT_APP_RPC_POOL_SZ;
    strncpy(core->app_api->server_name, "core-from-app", 16);
    core->app_api->context = core;
    
    wish_rpc_server_register(core->app_api, &methods_h);
    wish_rpc_server_register(core->app_api, &signals_h);
    wish_rpc_server_register(core->app_api, &version_h);
    
    wish_rpc_server_register(core->app_api, &services_send_h);
    wish_rpc_server_register(core->app_api, &services_list_h);
    
    wish_rpc_server_register(core->app_api, &identity_list_h);
    wish_rpc_server_register(core->app_api, &identity_create_h);
    wish_rpc_server_register(core->app_api, &identity_export_h);
    wish_rpc_server_register(core->app_api, &identity_import_h);
    wish_rpc_server_register(core->app_api, &identity_get_h);
    wish_rpc_server_register(core->app_api, &identity_remove_h);
    wish_rpc_server_register(core->app_api, &identity_sign_h);
    wish_rpc_server_register(core->app_api, &identity_verify_h);
    wish_rpc_server_register(core->app_api, &identity_friend_request_h);
    wish_rpc_server_register(core->app_api, &identity_friend_request_list_h);
    wish_rpc_server_register(core->app_api, &identity_friend_request_accept_h);
    wish_rpc_server_register(core->app_api, &identity_friend_request_decline_h);
    wish_rpc_server_register(core->app_api, &directory_find_h);
    
    wish_rpc_server_register(core->app_api, &connections_list_h);
    wish_rpc_server_register(core->app_api, &connections_disconnect_h);
    wish_rpc_server_register(core->app_api, &connections_check_connections_h);

    wish_rpc_server_register(core->app_api, &api_acl_check_h);
    wish_rpc_server_register(core->app_api, &api_acl_allow_h);
    wish_rpc_server_register(core->app_api, &api_acl_remove_allow_h);
    wish_rpc_server_register(core->app_api, &api_acl_add_user_roles_h);
    wish_rpc_server_register(core->app_api, &api_acl_remove_user_roles_h);
    wish_rpc_server_register(core->app_api, &api_acl_user_roles_h);
    wish_rpc_server_register(core->app_api, &api_acl_what_resources_h);
    wish_rpc_server_register(core->app_api, &api_acl_allowed_permissions_h);

    wish_rpc_server_register(core->app_api, &relay_list_h);
    wish_rpc_server_register(core->app_api, &relay_add_h);
    wish_rpc_server_register(core->app_api, &relay_remove_h);
    
    wish_rpc_server_register(core->app_api, &wld_list_h);
    wish_rpc_server_register(core->app_api, &wld_clear_h);
    wish_rpc_server_register(core->app_api, &wld_announce_h);
    wish_rpc_server_register(core->app_api, &wld_friend_request_h);
    
    wish_rpc_server_register(core->app_api, &host_config_h);
    
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
    
    int end = 0;
    
    char *op = NULL;
    int32_t op_str_len = 0;
    if (bson_get_string(data, "op", &op, &op_str_len) == BSON_FAIL) {
        if (bson_get_int32(data, "end", &end) == BSON_FAIL) {
            bson_visit("There was no 'op' or 'end':", data);
            return;
        } else {
            WISHDEBUG(LOG_CRITICAL, "%s sent end signal for request %i", app->name, end);
            wish_rpc_server_end(core->app_api, end);
            return;
        }
    }

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
        
        rpc_server_req err_req;
        err_req.server = core->app_api;
        err_req.send = wish_core_app_rpc_send;
        err_req.send_context = &err_req;
        err_req.id = id;
        err_req.context = app;
        memcpy(err_req.local_wsid, src_wsid, WISH_WSID_LEN);
        
        wish_rpc_server_error(&err_req, 63, "Core requests full for apps.");
        return;
    } else {
        rpc_server_req* req = &(list_elem->request_ctx);
        req->server = core->app_api;
        req->send = wish_core_app_rpc_send;
        req->send_context = req;
        memcpy(req->op_str, op, MAX_RPC_OP_LEN);
        req->id = id;
        req->context = app;
        memcpy(req->local_wsid, src_wsid, WISH_WSID_LEN);
    
        if (wish_rpc_server_handle(core->app_api, req, args)) {
            WISHDEBUG(LOG_DEBUG, "RPC server fail: wish_core_app_rpc_func");
        }
    }
}

void wish_core_app_rpc_cleanup_requests(wish_core_t* core, struct wish_service_entry *service_entry_offline) {
    WISHDEBUG(LOG_CRITICAL, "App rpc server clean up starting");
    struct wish_rpc_context_list_elem *list_elem = NULL;
    struct wish_rpc_context_list_elem *tmp = NULL;
    LL_FOREACH_SAFE(core->app_api->request_list_head, list_elem, tmp) {
        if (list_elem->request_ctx.context == service_entry_offline) {
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
    WISHDEBUG(LOG_CRITICAL, "In update locals");
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
                WISHDEBUG(LOG_CRITICAL, "wish_core_app_rpc_func: wish_send_peer_update_locals: online");
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
                            WISHDEBUG(LOG_CRITICAL, "wish_core_app_rpc_func: Sending online message to app %s:", service_registry[i].name);
                            //bson_visit("Sending peer message to app:", buffer);
                            send_core_to_app(core, service_registry[i].wsid, (uint8_t *) bson_data(&bs), bson_size(&bs));
                        }
                    }
                }
            }
        }
    }
}
