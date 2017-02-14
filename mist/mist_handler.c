#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "wish_debug.h"
#include "wish_rpc.h"
#include "wish_app.h"


#include "mist_handler.h"
#include "mist_model.h"
#include "mist_follow.h"
#include "bson_visitor.h"
#include "bson.h"
#include "cbson.h"
#include "wish_app.h"
#include "mist_mapping.h"
#include "wish_port_config.h"


static void handle_control_model(wish_rpc_ctx *req, uint8_t *args) {
    mist_app_t *mist_app = (mist_app_t *)req->context;

    /* This defines the maximum model size in bytes */
    size_t data_doc_max_len = WISH_PORT_RPC_BUFFER_SZ;
    uint8_t data_doc[data_doc_max_len];
    
    bson bs;
    bson_init_buffer(&bs, data_doc, data_doc_max_len);
    
    bson_append_start_object(&bs, "data");
    model_generate_bson(&(mist_app->model), &bs);
    bson_append_finish_object(&bs);
    bson_finish(&bs);
    if (bs.err) {
        WISHDEBUG(LOG_CRITICAL, "BSON error %d in handle control model", bs.err);
        wish_rpc_server_error(req, 999, "BSON error in handle_control_model");
    } else {
    
        wish_rpc_server_send(req, (uint8_t *) bson_data(&bs), bson_size(&bs));
    }
}


static void handle_control_write(wish_rpc_ctx *req, uint8_t *args) {
    mist_app_t *mist_app = req->context;
    struct mist_model *model = &(mist_app->model);

    /* Get the endpoint and value from "args" array */
    char* endpoint = 0;
    int endpoint_len = 0;
    bson_get_string(args, "0", &endpoint, &endpoint_len);
    
    mist_ep* ep;
    if (mist_find_endpoint_by_name(model, endpoint, &ep)) {
        WISHDEBUG(LOG_DEBUG, "control.write: Could not find endpoint %s, aborting!", endpoint);
        wish_rpc_server_error(req, 104, "Endpoint not found or permission denied.");
        return;
    }
    if ( !ep->writable ) {
        WISHDEBUG(LOG_DEBUG, "control.write: Endpoint %s not writable, aborting!", endpoint);
        wish_rpc_server_error(req, 105, "Endpoint not writable or permission denied.");
        return;
    }

    /* Read the data type of the received value; it is the element
     * named "1" of the array */
    uint8_t* value_ptr;
    int value_len = 0;
    uint8_t value_type = 0;
    /* The value is always encoded to send element of the "args"
     * array. That element is named "1" according to BSON spec. */
    bson_get_elem_by_name(args, "1", &value_type, &value_ptr, &value_len);

    if (ep->type == MIST_TYPE_FLOAT) {
        switch (value_type) {
            case BSON_KEY_DOUBLE: {
                double double_value;
                bson_get_double(args, "1", &double_value);

                if (MIST_NO_ERROR == ep->write(ep, &double_value)) {
                    mist_value_changed(model, endpoint);
                }
                break; }
            case BSON_KEY_INT32: {
                int32_t int32_value;
                bson_get_int32(args, "1", &int32_value);
                
                double v = (double) int32_value;

                if (MIST_NO_ERROR == ep->write(ep, &v)) {
                    mist_value_changed(model, endpoint);
                }
                break; }
            case BSON_KEY_BOOLEAN: {
                wish_rpc_server_error(req, 76, "Cannot write boolean value to float endpoint.");
                return;
                break; }                
            default:
                WISHDEBUG(LOG_DEBUG, "Write %s: Can't handle BSON datatype %d\n\r", endpoint, value_type);
                wish_rpc_server_error(req, 105, "Data type not supported.");
                return;
                break;
        }
    } else if (ep->type == MIST_TYPE_BOOL) {
        switch (value_type) {
            case BSON_KEY_DOUBLE: {
                double double_value;
                bson_get_double(args, "1", &double_value);

                if (MIST_NO_ERROR == ep->write(ep, &double_value)) {
                    mist_value_changed(model, endpoint);
                }
                break; }
            case BSON_KEY_INT32: {
                int32_t int32_value;
                bson_get_int32(args, "1", &int32_value);
                
                bool v = int32_value != 0;

                if (MIST_NO_ERROR == ep->write(ep, &v)) {
                    mist_value_changed(model, endpoint);
                }
                break; }
            case BSON_KEY_BOOLEAN: {
                bool bool_value;
                bson_get_boolean(args, "1", &bool_value);

                if (MIST_NO_ERROR == ep->write(ep, &bool_value)) {
                    mist_value_changed(model, endpoint);
                }
                break; }                
            default:
                WISHDEBUG(LOG_DEBUG, "Write %s: Can't handle BSON datatype %d\n\r", endpoint, value_type);
                wish_rpc_server_error(req, 105, "Data type not supported.");
                return;
                break;
        }
    } else if (ep->type == MIST_TYPE_INT) {
        switch (value_type) {
            case BSON_KEY_DOUBLE: {
                double double_value;
                bson_get_double(args, "1", &double_value);
                if (MIST_NO_ERROR == ep->write(ep, &double_value)) {
                    mist_value_changed(model, endpoint);
                }
                break; }
            case BSON_KEY_INT32: {
                int int_value;
                bson_get_int32(args, "1", &int_value);
                if (MIST_NO_ERROR == ep->write(ep, &int_value)) {
                    mist_value_changed(model, endpoint);
                }

                break;}
            case BSON_KEY_BOOLEAN: {
                bool bool_value;
                bson_get_boolean(args, "1", &bool_value);
                if (MIST_NO_ERROR == ep->write(ep, &bool_value)) {
                    mist_value_changed(model, endpoint);
                }
                break;}
            default:
                wish_rpc_server_error(req, 105, "Data type not supported.");
                WISHDEBUG(LOG_DEBUG, "Write %s: Can't handle BSON datatype %d\n\r", endpoint, value_type);
                return;
        }
    } else if (ep->type == MIST_TYPE_STRING) {
        switch (value_type) {
            case BSON_KEY_DOUBLE: {
                wish_rpc_server_error(req, 78, "Cannot write double to string endpoint.");
                return;
                break; }
            case BSON_KEY_INT32: {
                wish_rpc_server_error(req, 78, "Cannot write int to string endpoint.");
                return;
                break;}
            case BSON_KEY_BOOLEAN: {
                wish_rpc_server_error(req, 78, "Cannot write bool to string endpoint.");
                break;}
            case BSON_KEY_STRING: {
                char *str_value;
                int str_len = 0;
                if (BSON_SUCCESS == bson_get_string(args, "1", &str_value, &str_len)) {
                    if (MIST_NO_ERROR == ep->write(ep, str_value)) {
                        mist_value_changed(model, endpoint);
                    }
                }

                break;}
            default:
                wish_rpc_server_error(req, 79, "Cannot write such bson type to string endpoint.");
                WISHDEBUG(LOG_CRITICAL, "Write %s: Can't handle BSON datatype %d\n\r", endpoint, value_type);
        }
    }

    size_t data_doc_max_len = 10;
    uint8_t data_doc[data_doc_max_len];
    
    bson bs;
    bson_init_buffer(&bs, data_doc, data_doc_max_len);
    
    bson_append_start_object(&bs, "data");
    bson_append_finish_object(&bs);
    bson_finish(&bs);
    wish_rpc_server_send(req, NULL, 0);
}

static void handle_control_follow(wish_rpc_ctx *req, uint8_t *args) {
    /* Got message control.follow indicating somebody wants to follow how our
     * endpoint value changes. 
     * FIXME In the future, we will allow "endpoint masks" (argument to this RPC)
     * so that only a subset of endpoints can be followed if needed.
     * However for now, we just allow follow on the whole device model   */
    
    mist_app_t *mist_app = req->context;
    //wish_protocol_peer_t* peer = req->ctx;
    struct mist_model *model = &(mist_app->model);
    
    /* Now, send one "follow" reply for each endpoint, for initial syncing. */

    mist_ep* ep = model->endpoint_list;

    while (ep != NULL) {
        generate_mist_follow_msg(mist_app, ep);
        ep = ep->next;
    }
}

static void handle_control_read(wish_rpc_ctx *req, uint8_t *args) {
    int buffer_len = 1400;
    uint8_t buffer[buffer_len];

    mist_app_t *mist_app = req->context;
    struct mist_model *model = &(mist_app->model);

    /* Get the endpoint and value from "args" array */
    char* endpoint = 0;
    int endpoint_len = 0;
    bson_get_string(args, "0", &endpoint, &endpoint_len);
    
    mist_ep* ep;
    if (mist_find_endpoint_by_name(model, endpoint, &ep)) {
        WISHDEBUG(LOG_CRITICAL, "control.read: Could not find endpoint %s, aborting!", endpoint);
        return;
    }

    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);

    if(!ep->readable) {
        wish_rpc_server_error(req, 569, "Endpoint not readable.");
        return;
    }
    
    switch (ep->type) {
       case MIST_TYPE_BOOL:
           {
               bool value = false;
               ep->read(ep, &value);
               bson_append_bool(&bs, "data", value);
           }
           break;
       case MIST_TYPE_INT:
           {
               double value = 0.0;
               ep->read(ep, &value);
               bson_append_int(&bs, "data", value*1.0);
           }
           break;
       case MIST_TYPE_FLOAT:
           {
               double value = 0.0;
               ep->read(ep, &value);
               bson_append_double(&bs, "data", value*1.0);
           }
           break;
       case MIST_TYPE_STRING:
           {
               /* FIXME This situation clearly illustrates that we should
                * pass the length of the object down the reader function.
                * Now we need to define that string endpoints have a
                * maximum length! */
               char string[MIST_STRING_EP_MAX_LEN + 1];
               ep->read(ep, string);
               string[MIST_STRING_EP_MAX_LEN] = 0; /* Ensure null termination */
               bson_append_string(&bs, "data", string);
           }
           break;
        default:
            break;
    }
    
    bson_finish(&bs);
    if (bs.err) {
        WISHDEBUG(LOG_CRITICAL, "BSON error in handle_control_read");
        wish_rpc_server_error(req, 999, "BSON error in handle_control_read");
    } else {
        wish_rpc_server_send(req, (uint8_t *) bson_data(&bs), bson_size(&bs));
    }
}

static void handle_control_invoke(wish_rpc_ctx *req, uint8_t *args) {
    mist_app_t *mist_app = req->context;
    struct mist_model *model = &(mist_app->model);

    /* Get the endpoint and value from "args" array */
    char* endpoint = 0;
    int endpoint_len = 0;
    bson_get_string(args, "0", &endpoint, &endpoint_len);
    
    mist_ep* ep;
    if (mist_find_endpoint_by_name(model, endpoint, &ep)) {
        WISHDEBUG(LOG_CRITICAL, "control.invoke: Could not find endpoint %s, aborting!", endpoint);
        return;
    }
    if ( !ep->invokable ) {
        WISHDEBUG(LOG_CRITICAL, "control.invoke: Endpoint %s not invokable, aborting!", endpoint);
        return;
    }

    //WISHDEBUG(LOG_CRITICAL, "Invoke to endpoint %s.", endpoint);

    //WISHDEBUG(LOG_CRITICAL, "control.invoke arguments:");
    //bson_visit(args, elem_visitor);

    if (ep->invoke != NULL) {
        bson_iterator it;
        bson_find_from_buffer(&it, args, "1");

        //WISHDEBUG(LOG_CRITICAL, "Iterator type is %i", bson_iterator_type(&it));
        
        mist_buf invoke_args;
        bson invoke_args_bs;
        size_t args_buffer_len = bson_get_doc_len(args)+200;
        uint8_t args_buffer[args_buffer_len];
        bson_init_buffer(&invoke_args_bs, args_buffer, args_buffer_len);
        
        bson_append_string(&invoke_args_bs, "epid", endpoint);
        bson_append_int(&invoke_args_bs, "id", req->id);
        
        if (bson_iterator_type(&it) == BSON_EOO) {
            WISHDEBUG(LOG_CRITICAL, "Invoke with no arguments.");
        } else {
            //bson_append_start_object(&new_bs, "args");

            switch (bson_iterator_type(&it)) {
                case BSON_OBJECT:
                case BSON_ARRAY:
                case BSON_STRING:

                    bson_append_element(&invoke_args_bs, "args", &it);
                    break;
                case BSON_BOOL:
                    bson_append_bool(&invoke_args_bs, "args", bson_iterator_bool(&it));
                    break;
                case BSON_INT:
                    bson_append_int(&invoke_args_bs, "args", bson_iterator_int(&it));
                    break;
                case BSON_DOUBLE:
                    bson_append_double(&invoke_args_bs, "args", bson_iterator_double(&it));
                    break;
                default:
                    WISHDEBUG(LOG_CRITICAL, "Unhandled BSON type in invoke");
            }
            bson_finish(&invoke_args_bs);
            

        }

        invoke_args.base = (char*) bson_data(&invoke_args_bs);
        invoke_args.len = bson_size(&invoke_args_bs);
        
        enum mist_error err = ep->invoke(ep, invoke_args);
        
        if (err == MIST_ASYNC) {
            WISHDEBUG(LOG_CRITICAL, "Invoke function should be asynchronous, don't send response immediately.");
        }        
    } else {
        WISHDEBUG(LOG_CRITICAL, "Invoke function is null");
    }
}

void mist_invoke_response(wish_rpc_server_t* s, int id, uint8_t* data) {
    wish_rpc_ctx *req = wish_rpc_server_req_by_id(s, id);
    
    if (req == NULL) {
        return;
    }
    
    // copy the data property from input bson
    
    int buf_len = WISH_PORT_RPC_BUFFER_SZ;
    uint8_t buf[buf_len];
    
    bson b;
    bson_init_buffer(&b, buf, buf_len);

    bson_iterator it;
    bson_find_from_buffer(&it, data, "data");
    
    if (bson_iterator_type(&it) == BSON_EOO) {
        WISHDEBUG(LOG_CRITICAL, "Invoke with no arguments.");
    } else {
        switch (bson_iterator_type(&it)) {
            case BSON_OBJECT:
            case BSON_ARRAY:
            case BSON_STRING:
                bson_append_element(&b, "data", &it);
                break;
            case BSON_BOOL:
                bson_append_bool(&b, "data", bson_iterator_bool(&it));
                break;
            case BSON_INT:
                bson_append_int(&b, "data", bson_iterator_int(&it));
                break;
            case BSON_DOUBLE:
                bson_append_double(&b, "data", bson_iterator_double(&it));
                break;
            default:
                WISHDEBUG(LOG_CRITICAL, "Unhandled BSON type in invoke response");
        }
    }
    
    bson_finish(&b);
    
    wish_rpc_server_send(req, bson_data(&b), bson_size(&b));
}

/*
map: function(req, res, context) { 
    var srcEpid = req.args[0]; // axis1
    var srcOpts = req.args[1];
    var dstEpid = req.args[2];

    var dstUrl = 'wish://'+context.peer.luid+'>'+context.peer.ruid+'@'+context.peer.rhid+'/'+context.peer.rsid;
    var key = crypto.createHash('sha1').update(JSON.stringify(req)).digest('hex').substr(0, 8);

    var settings = { 
        epid: dstEpid, 
        url: dstUrl, 
        opts: srcOpts };

    self.map(key, srcEpid, settings, { peer: context.peer }, function(err, data) {
        if (err) { return res.error(data); }
        res.send(data);
    });
},
*/

static void handle_control_map(wish_rpc_ctx *req, uint8_t *args) {
    WISHDEBUG(LOG_CRITICAL, "Control map");
    mist_app_t *mist_app = req->context;
    struct mist_model *model = &(mist_app->model);

    bson_iterator it;
    
    bson_find_from_buffer(&it, args, "0");
    char* src_epid = (char*)bson_iterator_string(&it);

    bson_find_from_buffer(&it, args, "1");
    char* src_opts = (char*)bson_iterator_value(&it);

    bson_find_from_buffer(&it, args, "2");
    char* dst_epid = (char*)bson_iterator_string(&it);
    
    
    mist_ep* ep;
    if (mist_find_endpoint_by_name(model, src_epid, &ep)) {
        WISHDEBUG(LOG_CRITICAL, "control.invoke: Could not find endpoint %s, aborting!", src_epid);
        return;
    }
    if ( !ep->readable ) {
        WISHDEBUG(LOG_CRITICAL, "control.map: Endpoint %s not readable, aborting!", src_epid);
        return;
    }

    WISHDEBUG(LOG_CRITICAL, "control.map arguments:");
    bson_visit(args, elem_visitor);

    int buffer_len = 400;
    uint8_t buffer[buffer_len];

    bson b;
    bson_init_buffer(&b, buffer, buffer_len);
    
    // FIXME create unique mapping identifier (gobl) and store it along with opts and epids
    char mapping_id[MAPPING_ID_LEN] = { 0 };
    wish_platform_sprintf(mapping_id, "m%i", mist_mapping_get_new_id((mist_app_t*) req->context));
    bool mapping_ret = mist_mapping_save((mist_app_t*) req->context, (wish_protocol_peer_t *)req->ctx, mapping_id, src_epid, dst_epid);
    if (mapping_ret == false) {
        /* Making of the mapping failed! */
        WISHDEBUG(LOG_CRITICAL, "Cannot make the mapping!");
        wish_rpc_server_error(req, 99, "Cannot map at this time.");
    } else {
        bson_append_string(&b, "data", mapping_id);
    
        bson_finish(&b);
    
        wish_rpc_server_send(req, buffer, buffer_len);
    }
}

/*
requestMapping: function(req, res, context) {
    // add ACL checks here
    var key = crypto.createHash('sha1').update(JSON.stringify(req)).digest('hex').substr(0, 8);

    var from = req.args[0];     // j
    var fromEpid = req.args[1]; // axis1
    var fromOpts = req.args[2]; // { type: 'direct', interval: 'change' }
    var toEpid = req.args[3];   // vibrateStrong
    var toOpts = req.args[4];   // { type: 'write' }

    //d.control.requestMapping(j, 'axis1', { type: 'direct', interval: 'change' }, 'vibrateStrong', { type: 'write' });

    from.luid = context.peer.luid;
    if (from.rhid === 'localhost'){
        from.rhid = context.peer.rhid;
    }            
    var url = 'wish://'+from.luid+'>'+from.ruid+'@'+from.rhid+'/'+from.rsid; 
    var peer = { luid: from.luid, ruid: from.ruid, rhid: from.rhid, rsid: from.rsid };

    //j.control.map('axis1', { type: 'direct', interval: 'change' }, 'vibrateStrong', function(err, key) {})
    self.ucp.request(peer, 'control.map', [fromEpid, fromOpts, toEpid], function(err, key) {
        if (err) { return res.error(key); }
        //console.log("control map response(err,data):", err, key);

        var settings = {
            epid: fromEpid,
            url: url,
            opts: toOpts };

        // key, toEpid, toOpts
        self.map(key, toEpid, settings, { peer: context.peer }, function (err, data) {
            res.send(data);
        });
    });
},        
*/

static void handle_control_map_response(rpc_client_req* req, void* context, uint8_t* payload, size_t payload_len) {
    wish_rpc_ctx *orig_req = req->cb_context;
    WISHDEBUG(LOG_CRITICAL, "control.requestMapping got response from map request and has context pointer %p", req->cb_context);
    bson_visit(payload, elem_visitor);
    
    bson_iterator res;
    bson_find_from_buffer(&res, payload, "data");
    if (bson_iterator_type(&res) != BSON_STRING) {
        WISHDEBUG(LOG_CRITICAL, "control.requestMapping got invalid response from map request");
        wish_rpc_server_error(orig_req, 13, "Invalid response from map request.");
        return;
    }
    
    int buffer_len = 400;
    uint8_t buffer[buffer_len];
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    
    bson_append_element(&bs, "data", &res);
    
    bson_finish(&bs);
    
    if (bs.err) {
        WISHDEBUG(LOG_CRITICAL,  "BSON error in handle_control_map_response");
        wish_rpc_server_error(orig_req, 999,  "BSON error in handle_control_map_response");
    } else {
        WISHDEBUG(LOG_CRITICAL, "control.requestMapping sending back data to original requestor.");
        bson_visit(buffer, elem_visitor);

        wish_rpc_server_send(orig_req, bson_data(&bs), bson_size(&bs));
    }
}

static void handle_control_request_mapping(wish_rpc_ctx *req, uint8_t *args) {
    wish_protocol_peer_t* peer = (wish_protocol_peer_t *)req->ctx;
    mist_app_t *mist_app = req->context;
    struct mist_model *model = &(mist_app->model);
    
    bson_iterator it;
    
    // signal source peer
    bson_find_from_buffer(&it, args, "0");
    if ( bson_iterator_type(&it) != BSON_OBJECT ) { return; }

    /* Create a BSON object from the peer document we got as args element "0" */
    bson peer_bs;
    bson_iterator_subobject(&it, &peer_bs);
    
    char* peer_ruid;
    char* peer_rhid;
    char* peer_rsid;
    char* peer_protocol;
    
    bson_find(&it, &peer_bs, "ruid");
    
    if (bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) != WISH_ID_LEN) {
        wish_rpc_server_error(req, 67, "Invalid peer ruid.");
        return;
    }
    
    peer_ruid = (char*) bson_iterator_bin_data(&it);
    
    bson_find(&it, &peer_bs, "rhid");
    
    if (bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) != WISH_ID_LEN) {
        wish_rpc_server_error(req, 67, "Invalid peer rhid.");
        return;
    }

    peer_rhid = (char*) bson_iterator_bin_data(&it);
    
    bson_find(&it, &peer_bs, "rsid");
    
    if (bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) != WISH_ID_LEN) {
        wish_rpc_server_error(req, 67, "Invalid peer rsid.");
        return;
    }

    peer_rsid = (char*) bson_iterator_bin_data(&it);
    
    bson_find(&it, &peer_bs, "protocol");
    
    if (bson_iterator_type(&it) != BSON_STRING || bson_iterator_string_len(&it) > WISH_PROTOCOL_NAME_MAX_LEN) {
        WISHDEBUG(LOG_CRITICAL, "Invalid peer protocol string: type: %i, len: %i\n", bson_iterator_type(&it), bson_iterator_string_len(&it));
        wish_rpc_server_error(req, 67, "Invalid peer protocol.");
        return;
    }

    peer_protocol = (char*) bson_iterator_string(&it);
    
    int buf_len = 300;
    char buf[buf_len];
    
    bson bs;
    bson_init_buffer(&bs, buf, buf_len);
    bson_append_binary(&bs, "luid", peer->luid, WISH_ID_LEN);
    bson_append_binary(&bs, "ruid", peer_ruid, WISH_ID_LEN);
    bson_append_binary(&bs, "rhid", peer_rhid, WISH_ID_LEN);
    bson_append_binary(&bs, "rsid", peer_rsid, WISH_ID_LEN);
    bson_append_string(&bs, "protocol", peer_protocol);
    bson_finish(&bs);
    
    
    WISHDEBUG(LOG_CRITICAL, "subobj peer:");
    bson_visit( (uint8_t*)bson_data(&peer_bs), elem_visitor);
    
    WISHDEBUG(LOG_CRITICAL, "subobj peer (luid overwritten):");
    bson_visit( (uint8_t*)bson_data(&bs), elem_visitor);
    
    wish_protocol_peer_t* src_peer = wish_protocol_peer_find_from_bson(&mist_app->ucp_handler, (uint8_t*) bson_data(&bs));
     
    if (src_peer == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: control.requestMapping handler: peer is unknown to me!");
        wish_rpc_server_error(req, 60, "Error: control.requestMapping handler: peer is unknown to me!");
        return;
    } else {
        WISHDEBUG(LOG_CRITICAL, "control.requestMapping found peer: %p", src_peer);
    }
    //bson_visit(args, elem_visitor);
    

    // signal source epid
    bson_find_from_buffer(&it, args, "1");
    char* src_epid = (char*)bson_iterator_string(&it);

    // signal source opts
    bson_iterator src_opts;
    bson_find_from_buffer(&src_opts, args, "2");
    WISHDEBUG(LOG_CRITICAL, "Src opts bson type in requestMapping %i", bson_iterator_type(&src_opts));

    // signal destination epid
    bson_find_from_buffer(&it, args, "3");
    char* dst_epid = (char*)bson_iterator_string(&it);

    // signal destination opts
    bson_find_from_buffer(&it, args, "4");
    char* dst_opts = (char*)bson_iterator_value(&it);
    
    
    mist_ep* ep;
    if (mist_find_endpoint_by_name(model, dst_epid, &ep)) {
        WISHDEBUG(LOG_CRITICAL, "control.requestMapping: Could not find endpoint %s, aborting!", dst_epid);
        wish_rpc_server_error(req, 61, "Invalid endpoint.");
        return;
    }
    if ( !ep->writable ) {
        WISHDEBUG(LOG_CRITICAL, "control.requestMapping: Endpoint %s not writable, aborting!", dst_epid);
        wish_rpc_server_error(req, 62, "Destination endpoint not writable.");
        return;
    }

    WISHDEBUG(LOG_CRITICAL, "control.requestMapping arguments:");
    bson_visit(args, elem_visitor);
    
    int map_buf_len = 300;
    char map_buf[map_buf_len];

    /*
    self.ucp.request(peer, 'control.map', [fromEpid, fromOpts, toEpid], function(err, key) {
        if (err) { return res.error(key); }
        //console.log("control map response(err,data):", err, key);

        var settings = {
            epid: fromEpid,
            url: url,
            opts: toOpts };

        // key, toEpid, toOpts
        self.map(key, toEpid, settings, { peer: context.peer }, function (err, data) {
            res.send(data);
        });
    });
    */
    
    // send control.map request to the map signal source node
    bson map;
    bson_init_buffer(&map, map_buf, map_buf_len);
    bson_append_start_array(&map, "args");
    bson_append_string(&map, "0", src_epid);
    bson_append_element(&map, "1", &src_opts);
    bson_append_string(&map, "2", dst_epid);
    bson_append_finish_array(&map);
    bson_finish(&map);
    
    int obuf_len = 400;
    char obuf[obuf_len];
    
    wish_rpc_id_t id = wish_rpc_client_bson(&mist_app->ucp_handler.rpc_client, "control.map", (uint8_t*)bson_data(&map), bson_size(&map), handle_control_map_response, obuf, obuf_len);
    rpc_client_req* mreq = find_request_entry(&mist_app->ucp_handler.rpc_client, id);
    mreq->cb_context = req;
    
    bson obson;
    bson_init_buffer(&obson, obuf, obuf_len);

    WISHDEBUG(LOG_CRITICAL, "The actual map message sent forward (context pointer %p):", req);
    bson_visit(obuf, elem_visitor);
    
    wish_app_send(mist_app->app, src_peer, obuf, bson_size(&obson), NULL);
    // response will be sent to this request from handle_control_map_response
}

static void handle_control_notify(wish_rpc_ctx *req, uint8_t *args) {
    mist_app_t *mist_app = req->context;
    struct mist_model *model = &(mist_app->model);
    
    WISHDEBUG(LOG_CRITICAL, "control.notify from peer: %p, said:", req->ctx);
    bson_visit(args, elem_visitor);

    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    char* endpoint = (char*)bson_iterator_string(&it);
    
    mist_ep* ep;
    if (mist_find_endpoint_by_name(model, endpoint, &ep)) {
        WISHDEBUG(LOG_CRITICAL, "control.write: Could not find endpoint %s, aborting!", endpoint);
        return;
    }
    if ( !ep->writable ) {
        WISHDEBUG(LOG_CRITICAL, "control.write: Endpoint %s not writable, aborting!", endpoint);
        return;
    }
    
    bson_find_from_buffer(&it, args, "1");
    char *mapping_id = NULL;
    if (bson_iterator_type(&it) == BSON_STRING) {
        mapping_id = (char *) bson_iterator_string(&it);
        WISHDEBUG(LOG_CRITICAL, "Mapping id: %s", mapping_id);
    }
    
    /* Find element 2 - this could be a value, or the string 'del' which means that the mapping should be deleted */
    bson_find_from_buffer(&it, args, "2");
    
    bson_type type = bson_iterator_type(&it);
    if (type == BSON_STRING) {
        /* Could be a request to delete the mapping, or a write to string endpoint! */
        char *str = (char *) bson_iterator_string(&it);
        WISHDEBUG(LOG_DEBUG, "elem 2 value %s",str);
        if (strncmp(str, "del", 4) == 0) {
            /* Request to delete mapping! */
        
            WISHDEBUG(LOG_CRITICAL, "Deleting mapping with id: %s", mapping_id);
            mist_mapping_delete((mist_app_t*) req->context, (wish_protocol_peer_t *)req->ctx, mapping_id);
            return;
        }
    }
    
    if(ep->type == MIST_TYPE_FLOAT) {
        WISHDEBUG(LOG_CRITICAL, "control.notify: ep is float, but not supported yet: %s", endpoint);
    } else if ( ep->type == MIST_TYPE_BOOL) {
        if (type == BSON_BOOL) {
            bool value = bson_iterator_bool(&it) == 0 ? false : true;
            
            if( MIST_NO_ERROR == ep->write(ep, &value) ) {
                mist_value_changed(model, endpoint);
            }
            
        } else {
            WISHDEBUG(LOG_CRITICAL, "control.notify: ep is bool, but update type is not for ep: %s", endpoint);
        }
    } else {
        WISHDEBUG(LOG_CRITICAL, "control.notify: ep type not supported yet: %s", endpoint);
    }
}

/* Make a claim on this device. The Peer should be added to the owner group, but 
 * this implementation does nothing except answers with a message:
 * 
 *   { msg: "You are the owner..." }
 */
static void handle_manage_claim(wish_rpc_ctx *req, uint8_t *args) {
    int buffer_len = 1400;
    uint8_t buffer[buffer_len];

    WISHDEBUG(LOG_CRITICAL, "MistApp: manage.claim() called");
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_start_object(&bs, "data");
    bson_append_string(&bs, "msg", "You are now the sole owner of this node");
    bson_append_finish_object(&bs);
    bson_finish(&bs);
    
    wish_rpc_server_send(req, (uint8_t *) bson_data(&bs), bson_size(&bs));
}

static void handle_manage_user_ensure_cb(rpc_client_req* req, void *ctx, uint8_t *payload, size_t payload_len) {
    WISHDEBUG(LOG_CRITICAL, "response to identity_import request: wish_app_core %i", payload_len);
    bson_visit(payload, elem_visitor);
    
    bson_iterator it;
    bson_find_from_buffer(&it, payload, "err");
    
    if (bson_iterator_type(&it) == BSON_INT) {
        // it's an error
        bson_find_from_buffer(&it, payload, "code");
        if (bson_iterator_type(&it) == BSON_INT) {
            int code = bson_iterator_int(&it);
            if (code == 202) {
                // it's ok the identity was already known. Just fall through.
            } else {
                // there was some unexpexted error
                bson_find_from_buffer(&it, payload, "msg");
                if (bson_iterator_type(&it) == BSON_STRING) {
                    WISHDEBUG(LOG_CRITICAL, "Unexpected error from identity.import, code: %i: %s", code, bson_iterator_string(&it));
                } else {
                    WISHDEBUG(LOG_CRITICAL, "Unexpected error (without msg) from identity.import code: %i", bson_iterator_int(&it));
                }
                return;
            }
        } else {
            // error without code?!
            WISHDEBUG(LOG_CRITICAL, "Unexpected error from identity.import code:");
            bson_visit(payload, elem_visitor);
            return;
        }
    }

    WISHDEBUG(LOG_CRITICAL, "Now to respond... %p %p", ctx, req->cb_context);
    
    int buffer_len = 1400;
    uint8_t buffer[buffer_len];

    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_bool(&bs, "data", true);
    bson_finish(&bs);
    
    wish_rpc_server_send(req->cb_context, (uint8_t *) bson_data(&bs), bson_size(&bs));
}

static void handle_manage_user_ensure(wish_rpc_ctx *req, uint8_t *args) {
    mist_app_t *mist_app = (mist_app_t *)req->context;
    wish_protocol_peer_t* peer = (wish_protocol_peer_t*) req->ctx;
    
    int buffer_len = 1400;
    uint8_t buffer[buffer_len];

    WISHDEBUG(LOG_CRITICAL, "MistApp: manage.user.ensure() called with following args: (original req pointer: %p)", req);
    bson_visit(args, elem_visitor);
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    if (bson_iterator_type(&it) == BSON_BINDATA) {
        WISHDEBUG(LOG_CRITICAL, "   identity to ensure:");
        bson_visit((uint8_t*)bson_iterator_bin_data(&it), elem_visitor);
    }


    bson bs; 
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_start_array(&bs, "args");
    bson_append_binary(&bs, "0", bson_iterator_bin_data(&it), bson_iterator_bin_len(&it));
    bson_append_binary(&bs, "1", peer->luid, WISH_UID_LEN);
    bson_append_string(&bs, "2", "binary");
    bson_append_finish_array(&bs);
    bson_finish(&bs);

   
#if 0
    /* Call RPC, and set cb context after that. This only works if the core/app communication is asynchronous! */
    int id = wish_app_core(mist_app->app, "identity.import", (uint8_t*) bson_data(&bs), bson_size(&bs), handle_manage_user_ensure_cb);
    wish_rpc_client_set_cb_context(&mist_app->app->rpc_client, id, req);
#else
    /* In case you have synchronous communications, this is the way to do it. Not a thing of beauty. (FIXME) */
    wish_app_core_with_cb_context(mist_app->app, "identity.import", (uint8_t*) bson_data(&bs), bson_size(&bs), handle_manage_user_ensure_cb, req);
#endif
}
 
struct wish_rpc_server_handler control_model_handler =           { .op_str = "control.model",  .handler = handle_control_model };
struct wish_rpc_server_handler control_write_handler =           { .op_str = "control.write",  .handler = handle_control_write };
struct wish_rpc_server_handler control_follow_handler =          { .op_str = "control.follow", .handler = handle_control_follow};
struct wish_rpc_server_handler control_read_handler =            { .op_str = "control.read",   .handler = handle_control_read };
struct wish_rpc_server_handler control_invoke_handler =          { .op_str = "control.invoke", .handler = handle_control_invoke };
struct wish_rpc_server_handler control_map_handler =             { .op_str = "control.map",    .handler = handle_control_map };
struct wish_rpc_server_handler control_request_mapping_handler = { .op_str = "control.requestMapping", .handler = handle_control_request_mapping };
struct wish_rpc_server_handler control_notify_handler =          { .op_str = "control.notify", .handler = handle_control_notify };
struct wish_rpc_server_handler manage_claim_handler =            { .op_str = "manage.claim",   .handler = handle_manage_claim };
struct wish_rpc_server_handler manage_user_ensure_handler =      { .op_str = "manage.user.ensure",   .handler = handle_manage_user_ensure };

void mist_device_setup_rpc_handlers(wish_rpc_server_t *device_rpc_server) {
    /* FIXME this check below is needed because the handlers are statically
     * allocated which will not work (the linked list will fail)
     * if we have several Mist apps linked into one single
     * executable (as is the situation on an embedded system)
     */
    if (control_model_handler.next != NULL) {
        device_rpc_server->list_head = &control_model_handler;
        return;
    }
    wish_rpc_server_register(device_rpc_server, &control_model_handler);
    wish_rpc_server_register(device_rpc_server, &control_read_handler);
    wish_rpc_server_register(device_rpc_server, &control_write_handler);
    wish_rpc_server_register(device_rpc_server, &control_invoke_handler);
    wish_rpc_server_register(device_rpc_server, &control_follow_handler);
    wish_rpc_server_register(device_rpc_server, &control_map_handler);
    wish_rpc_server_register(device_rpc_server, &control_request_mapping_handler);
    wish_rpc_server_register(device_rpc_server, &control_notify_handler);

    wish_rpc_server_register(device_rpc_server, &manage_claim_handler);
    wish_rpc_server_register(device_rpc_server, &manage_user_ensure_handler);
}

static void send_south(void* ctx, uint8_t* data, int len) {
    struct wish_rpc_context* req = ctx;
    mist_app_t* mist_app = req->context;
    wish_protocol_peer_t* peer = req->ctx;
    
    receive_device_southbound(mist_app, data, len, peer, NULL);
}

/* Functio for feeding Mist message to the Device API RPC server */
void receive_device_northbound(mist_app_t *mist_app, uint8_t *data, int data_len, wish_protocol_peer_t* peer) {
    //WISHDEBUG(LOG_CRITICAL, "Received to Mist device:");
    //bson_visit(bson_doc, elem_visitor);

    int32_t ack = 0;
    int32_t sig = 0;
    int32_t fin = 0;
    int32_t err = 0;
    int32_t end = 0;
    
    if ( bson_get_int32(data, "end", &end) != BSON_FAIL) {
        wish_rpc_server_end(&(mist_app->device_rpc_server), end);
        return;
    } else if (bson_get_int32(data, "ack", &ack) == BSON_FAIL && 
        bson_get_int32(data, "sig", &sig) == BSON_FAIL && 
        bson_get_int32(data, "fin", &fin) == BSON_FAIL && 
        bson_get_int32(data, "err", &err) == BSON_FAIL )
    {
        // fall through to checking for op
    } else {
        // This is a response, should go to the client
        wish_rpc_client_handle_res(&mist_app->ucp_handler.rpc_client, peer, data, data_len);
        return;
    }
    
    int32_t op_str_len = 0;
    char *op_str = NULL;
    if (BSON_FAIL == bson_get_string(data, "op", &op_str, &op_str_len)) {
        WISHDEBUG(LOG_CRITICAL, "No op string!");
        return;
    }
    
    int32_t id = 0;
    bson_get_int32(data, "id", &id);


    /* Save the op string to the RPC context - it will be passed to the
     * wish_rpc_handle function so it can know what op we are handling. */
#if 0
    struct wish_rpc_context req = {
        .server = &(mist_app->device_rpc_server),
        .send = send_south,
        .send_context = &req,
        .id = id,
        .context = mist_app,
        .ctx = peer,
        .op_str = op_str, 
        .local_wsid = mist_app->app->wsid
    };
#endif
    struct wish_rpc_context_list_elem *list_elem = wish_rpc_server_get_free_rpc_ctx_elem(&(mist_app->device_rpc_server));
    if (list_elem == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Could not save the rpc context. Failing in mist_handler.");
        return;
    } else {
        struct wish_rpc_context *rpc_ctx = &(list_elem->request_ctx);
        rpc_ctx->server = &(mist_app->device_rpc_server);
        rpc_ctx->send = send_south;
        rpc_ctx->send_context = rpc_ctx;
        rpc_ctx->id = id;
        rpc_ctx->context = mist_app;
        rpc_ctx->ctx = peer;
        memcpy(rpc_ctx->op_str, op_str, MAX_RPC_OP_LEN);
        rpc_ctx->local_wsid = mist_app->app->wsid;
        
        /* Get the arguments to the op */
        int32_t args_len = 0;
        uint8_t *args = NULL;
        if (bson_get_array(data, "args", &args, &args_len)
                == BSON_FAIL) {
            WISHDEBUG(LOG_CRITICAL, "No args array!");
            return;
        }

        if (wish_rpc_server_handle(&(mist_app->device_rpc_server), rpc_ctx, args)) {
            WISHDEBUG(LOG_CRITICAL, "Mist device RPC server fail!!");
        }
    }
}


