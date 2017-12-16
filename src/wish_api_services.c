#include "wish_api_services.h"
#include "utlist.h"
#include "core_service_ipc.h"
#include "wish_service_registry.h"
#include "wish_dispatcher.h"
#include "wish_debug.h"
#include "string.h"
#include "bson_visit.h"

/**
 * Request to send message to peer
 * 
 *     args: [
 *         { luid: Buffer(32), ruid: Buffer(32), rhid: Buffer(32), rsid: Buffer(32), protocol: string  },
 *         payload: Buffer
 *     ]
 */
void wish_api_services_send(rpc_server_req* req, const uint8_t* args) {
    //bson_visit("Handling services.send", args);
    
    wish_core_t* core = (wish_core_t*) req->server->context;
    wish_app_entry_t* app = (wish_app_entry_t*) req->context;
    uint8_t* wsid = app->wsid;    

    bson_iterator it;
    
    bson_iterator_from_buffer(&it, args);

    if ( bson_find_fieldpath_value("0.luid", &it) != BSON_BINDATA ) {
        rpc_server_error_msg(req, 311, "Invalid peer. (luid not BSON_BINDATA)");
        return;
    }
    
    if ( bson_iterator_bin_len(&it) != WISH_UID_LEN ) {
        rpc_server_error_msg(req, 311, "Invalid peer. (luid length)");
        return;
    }
    
    const uint8_t* luid = bson_iterator_bin_data(&it);
    
    bson_iterator_from_buffer(&it, args);

    if ( bson_find_fieldpath_value("0.ruid", &it) != BSON_BINDATA ) {
        rpc_server_error_msg(req, 311, "Invalid peer. (ruid not BSON_BINDATA)");
        return;
    }
    
    if ( bson_iterator_bin_len(&it) != WISH_UID_LEN ) {
        rpc_server_error_msg(req, 311, "Invalid peer. (ruid length)");
        return;
    }
    
    const uint8_t* ruid = bson_iterator_bin_data(&it);
    
    bson_iterator_from_buffer(&it, args);

    if ( bson_find_fieldpath_value("0.rhid", &it) != BSON_BINDATA ) {
        rpc_server_error_msg(req, 311, "Invalid peer. (rhid not BSON_BINDATA)");
        return;
    }
    
    if ( bson_iterator_bin_len(&it) != WISH_UID_LEN ) {
        rpc_server_error_msg(req, 311, "Invalid peer. (rhid length)");
        return;
    }
    
    const uint8_t* rhid = bson_iterator_bin_data(&it);
    
    bson_iterator_from_buffer(&it, args);

    if ( bson_find_fieldpath_value("0.rsid", &it) != BSON_BINDATA ) {
        rpc_server_error_msg(req, 311, "Invalid peer. (rsid not BSON_BINDATA)");
        return;
    }
    
    if ( bson_iterator_bin_len(&it) != WISH_UID_LEN ) {
        rpc_server_error_msg(req, 311, "Invalid peer. (rsid length)");
        return;
    }
    
    const uint8_t* rsid = bson_iterator_bin_data(&it);
    
    bson_iterator_from_buffer(&it, args);

    if ( bson_find_fieldpath_value("0.protocol", &it) != BSON_STRING ) {
        rpc_server_error_msg(req, 311, "Invalid peer. (protocol not BSON_STRING)");
        return;
    }
    
    int protocol_len = bson_iterator_string_len(&it);
    
    if ( protocol_len > WISH_PROTOCOL_NAME_MAX_LEN ) {
        rpc_server_error_msg(req, 311, "Invalid peer. (protocol name length)");
        return;
    }
    
    const uint8_t* protocol = bson_iterator_string(&it);
    
    bson_iterator_from_buffer(&it, args);

    if ( bson_find_fieldpath_value("1", &it) != BSON_BINDATA ) {
        rpc_server_error_msg(req, 311, "Invalid payload.");
        return;
    }
    
    int payload_len = bson_iterator_bin_len(&it);
    const uint8_t* payload = bson_iterator_bin_data(&it);
    //bson_visit("Handling services.send, payload:", payload);

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
        
        /* FIXME this is wasting stack space again */
        size_t upcall_doc_max_len = (5+4*32+10) + payload_len + 100;
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
        bson_append_binary(&bs, "rsid", wsid, WISH_WSID_LEN);
        bson_append_string(&bs, "protocol", protocol);
        bson_append_finish_object(&bs);
        bson_append_binary(&bs, "data", payload, payload_len);
        bson_finish(&bs);
        if (bs.err) {
            WISHDEBUG(LOG_CRITICAL, "Error creating frame to local service");
        } else {
            //bson_visit("About to send this to local service on local core:", upcall_doc);
            send_core_to_app(core, rsid, bson_data(&bs), bson_size(&bs));
        }
        return;
    }
    /* Destination is determined to be a remote service on a remote core. */
    wish_connection_t* connection = wish_core_lookup_connected_ctx_by_luid_ruid_rhid(core, luid, ruid, rhid);

    // We will just send data and not expect response, not registering a request
    //  wish_rpc_client_request(core->core_rpc_client, &bs, NULL);

    if (connection != NULL && connection->context_state == WISH_CONTEXT_CONNECTED) {
        
        /* Build the actual on-wire message:
         *
         * req: {
         *  op: 'send'
         *  args: [ lsid, rsid, protocol, payload ]
         * }
         */

        size_t buf_len = 2*(WISH_WSID_LEN) + protocol_len + payload_len + 128;
        uint8_t buf[buf_len];
        bson bs; 
        bson_init_buffer(&bs, buf, buf_len);
        bson_append_start_object(&bs, "req");
        bson_append_string(&bs, "op", "send");
        bson_append_start_array(&bs, "args");
        bson_append_binary(&bs, "0", wsid, WISH_WSID_LEN);
        bson_append_binary(&bs, "1", rsid, WISH_WSID_LEN);
        bson_append_string(&bs, "2", protocol);
        bson_append_binary(&bs, "3", payload, payload_len);
        bson_append_finish_array(&bs);
        bson_append_finish_object(&bs);
        bson_finish(&bs);

        if (bs.err) {
            WISHDEBUG(LOG_CRITICAL, "BSON write error, args_buffer");
            return;
        }
        
        int send_ret = wish_core_send_message(core, connection, bson_data(&bs), bson_size(&bs));
        
        if (send_ret != 0) {
            /* Sending failed. Propagate RPC error */
            WISHDEBUG(LOG_CRITICAL, "Core app RPC: Sending not possible at this time");
            rpc_server_error_msg(req, 506, "Failed sending message to remote core.");
        } else {
            /* Sending successful */
            rpc_server_send(req, NULL, 0);
        }
    } else {
        WISHDEBUG(LOG_CRITICAL, "Could not find a suitable wish connection to send data.");
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
void wish_api_services_list(rpc_server_req* req, const uint8_t* args) {
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
    
    rpc_server_send(req, bson_data(&bs), bson_size(&bs));
}
