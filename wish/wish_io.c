/* Wish C - I/O functions for driving the Wish on-wire protocol */
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include "wish_debug.h"
#include "mbedtls/sha256.h"
#include "mbedtls/dhm.h"
#include "mbedtls/gcm.h"
#include "wish_core.h"
#include "wish_io.h"
#include "wish_identity.h"
#include "wish_local_discovery.h"
#include "ed25519.h"
#include "cbson.h"
#include "bson.h"
#include "bson_visitor.h"
#include "wish_platform.h"
#include "wish_dispatcher.h"
#include <limits.h>
#include "wish_event.h"
#include "wish_core_rpc_func.h"
#include "wish_core_app_rpc_func.h"
#include "wish_connection_mgr.h"

#include "utlist.h"


wish_context_t* wish_core_get_connection_pool(wish_core_t* core) {
    return core->wish_context_pool;
}

/* Start an instance of wish communication */
wish_context_t* wish_core_start(wish_core_t* core, uint8_t *local_wuid, uint8_t *remote_wuid) {

    wish_context_t* w;

    int i = 0;
    for (i = 0; i < WISH_CONTEXT_POOL_SZ; i++) {
        w = &(core->wish_context_pool[i]);
        if (w->context_state == WISH_CONTEXT_FREE) {
            /* We have found a context we can take into use */
            w->context_state = WISH_CONTEXT_IN_MAKING;
            /* Update timestamp */
            w->latest_input_timestamp = wish_time_get_relative(core);
            break;
        }
    }

    if (i == WISH_CONTEXT_POOL_SZ) {
        WISHDEBUG(LOG_CRITICAL, "No vacant wish context found");
        return NULL;
    }
    /* w now points to the vacant wish context we will use */

    /* Associate a connection id to the connection */
    w->connection_id = core->next_conn_id++;

    memcpy(w->local_wuid, local_wuid, WISH_ID_LEN);
    memcpy(w->remote_wuid, remote_wuid, WISH_ID_LEN);
    
    w->rx_ringbuf.max_len = RX_RINGBUF_LEN;
    w->rx_ringbuf.data = w->rx_ringbuf_backing;

    w->curr_transport_state = TRANSPORT_STATE_INITIAL;
    w->curr_protocol_state = PROTO_STATE_INITIAL;
    w->rsid_list_head = NULL;

    return w;
}


/* This function returns the pointer to the wish context corresponding
 * to the id number given as argument */
wish_context_t* wish_core_lookup_ctx_by_connection_id(wish_core_t* core, wish_connection_id_t id) {
    wish_context_t *ctx = NULL;
    int i = 0;

    for (i = 0; i < WISH_CONTEXT_POOL_SZ; i++) {
        if (core->wish_context_pool[i].connection_id == id) {
            ctx = &(core->wish_context_pool[i]);
            break;
        }
    }
    return ctx;
}

/** This function returns a pointer to the wish context which matches the
 * specified luid, ruid, rhid identities 
 *
 * Please note: The context returned here could a countext which is not
 * yet ready for use, because it is e.g. just being created.
 */
wish_context_t* 
wish_core_lookup_ctx_by_luid_ruid_rhid(wish_core_t* core, uint8_t *luid, uint8_t *ruid,
        uint8_t *rhid) {
    wish_context_t *ctx = NULL;
    int i = 0;

    for (i = 0; i < WISH_CONTEXT_POOL_SZ; i++) {
        if (core->wish_context_pool[i].context_state == WISH_CONTEXT_FREE) {
            /* If the wish context is not in use, we can safely skip it */
            //WISHDEBUG(LOG_CRITICAL, "Skipping free wish context");
            continue;
        }

        if (memcmp(core->wish_context_pool[i].local_wuid, luid, WISH_ID_LEN) == 0) {
            if (memcmp(core->wish_context_pool[i].remote_wuid, ruid, WISH_ID_LEN) 
                    == 0) {
                if (memcmp(core->wish_context_pool[i].remote_hostid, rhid, 
                        WISH_WHID_LEN) == 0) {

                    ctx = &(core->wish_context_pool[i]);
                    break;
                }
                else {
                    WISHDEBUG(LOG_DEBUG, "rhid mismatch");
                }
            }
            else {
                WISHDEBUG(LOG_DEBUG, "ruid mismatch");

            }
        }
        else {
            WISHDEBUG(LOG_DEBUG, "luid mismatch");
        }

    }
    return ctx;
}


bool wish_core_is_connected_luid_ruid(wish_core_t* core, uint8_t *luid, uint8_t *ruid) {
    int i = 0;

    for (i = 0; i < WISH_CONTEXT_POOL_SZ; i++) {
        if (core->wish_context_pool[i].context_state == WISH_CONTEXT_FREE) {
            /* If the wish context is not in use, we can safely skip it */
            //WISHDEBUG(LOG_CRITICAL, "Skipping free wish context");
            continue;
        }

        if (memcmp(core->wish_context_pool[i].local_wuid, luid, WISH_ID_LEN) == 0) {
            if (memcmp(core->wish_context_pool[i].remote_wuid, ruid, WISH_ID_LEN) == 0) {
                bool retval = false;
                switch (core->wish_context_pool[i].context_state) {
                case WISH_CONTEXT_CONNECTED:
                    retval = true;
                    break;
                case WISH_CONTEXT_IN_MAKING:
                    WISHDEBUG(LOG_CRITICAL, "Already connecting");
                    retval = true;
                    break;
                case WISH_CONTEXT_CLOSING:
                    WISHDEBUG(LOG_CRITICAL, "Found a connection which is closing down, continuing search..");
                    continue;
                    break;
                case WISH_CONTEXT_FREE:
                    WISHDEBUG(LOG_CRITICAL, "Unexpected state!");
                    break;
                }
                return retval;
            }
            else {
                WISHDEBUG(LOG_DEBUG, "ruid mismatch");
            }
        }
        else {
            WISHDEBUG(LOG_DEBUG, "luid mismatch");
        }

    }
    return false;
}


/* Feed raw data into wish core */
void wish_core_feed(wish_core_t* core, wish_context_t* h, unsigned char* data, int len) {
    WISHDEBUG(LOG_INFO, "Got data, len %d ", len);
    int i = 0;
    for (i = 0; i < len; i++) {
        WISHDEBUG2(LOG_TRIVIAL, "0x%hhx ", data[i]);
    }

    uint16_t rb_space = ring_buffer_space(&(h->rx_ringbuf));
    if (rb_space >= len) {
        /* Save the data in the rx circular buffer */
        ring_buffer_write(&(h->rx_ringbuf), data, len);
        /* Update timestamp to indicate some data was received */
        h->latest_input_timestamp = wish_time_get_relative(core);
   }
    else {
        /* There is no space for the data... */
        WISHDEBUG(LOG_CRITICAL, 
            "No space in ring buffer, for message of len = %d.\
The ringbuffer currently has %hu free bytes. Not going any further", 
            len, rb_space);
        wish_debug_die();
    }

}


/* Check if the connection attempt by a remote client presenting these
 * wish id's can be accepted or not */
bool wish_core_check_wsid(wish_core_t* core, wish_context_t* ctx, uint8_t* dst_id, uint8_t* src_id) {
    bool retval = false;

    /* Whitelist/ACL processing? */


    /* Load the source id from our DB.  */
    wish_identity_t tmp_id;

    /* Technically, we need to have the privkey for "dst_id", else we
     * cannot be communicating */
    if (wish_has_privkey(dst_id) && wish_load_identity(src_id, &tmp_id)) {
        retval = true;
    }
    else {
        retval = false;
    }

   return retval;
}

/* This defines the length of connection initialisation string send by
 * the client to the server after connection is established. */
#define WISH_CLIENT_HELLO_LEN 2+1+WISH_ID_LEN+WISH_ID_LEN

/* This function will process data saved into the ringbuffer by function
 * wish_core_feed. 
 * Returns 1 when there was data left in receive ring buffer, and futher
 * processing is possible. 
 * Returns 0 when there is no more data to be read at this time.
 */
void wish_core_process_data(wish_core_t* core, wish_context_t* h) {
again:
    ;
    /* This variable is used when the wish protocol state is 
     * PROTO_STATE_WISH_RUNNING: when the wish
     * connection is up and running, we need to ensure that also the AES
     * GCM auth tag is received, before we start processing the payload!
     * The auth_tag's length is not accounted for in the frame length
     * field of the wire protocol (variable h->expect), 
     * and therefore we need to account for it explicitly. 
     * THis will be fixed with Wish protocol level 1.
     * */
    int expect_payload_len = 0;

    /* Consume data from the ring buffer */
    switch (h->curr_transport_state) {
        case TRANSPORT_STATE_WAIT_FRAME_LEN:
            /* In this case we always expect a 2-byte long frame
             * length */
            if (ring_buffer_length(&(h->rx_ringbuf)) >= 2) {
                /* Read out the expected byte count */
                /* Note: Byte count is expressend in Big Endian format */
                uint8_t bytes[2] = { 0 };
                ring_buffer_read(&(h->rx_ringbuf), bytes, 2);
                h->expect_bytes = (bytes[0] << 8) | bytes[1];
                WISHDEBUG(LOG_INFO, "Now expecting %d bytes of payload", h->expect_bytes);
                h->curr_transport_state = TRANSPORT_STATE_WAIT_PAYLOAD;
                if (ring_buffer_length(&(h->rx_ringbuf)) >= h->expect_bytes) {
                    /* There is more data to be read, so signal that
                     * function can continue */
                    goto again;
                }
            }
            break;
        case TRANSPORT_STATE_WAIT_PAYLOAD:
            expect_payload_len = h->expect_bytes;
            if (ring_buffer_length(&(h->rx_ringbuf)) >= expect_payload_len) {
                uint8_t* buf = (uint8_t*) wish_platform_malloc(h->expect_bytes);
                if (buf != NULL) {
                    ring_buffer_read(&(h->rx_ringbuf), buf, h->expect_bytes);
                    wish_core_handle_payload(core, h, buf, h->expect_bytes);
                    wish_platform_free(buf);
                    h->curr_transport_state = TRANSPORT_STATE_WAIT_FRAME_LEN;
                    if (ring_buffer_length(&(h->rx_ringbuf)) >= 2) {
                        /* There is more data to be read */
                        goto again;
                    }
                }
                else {
                    WISHDEBUG(LOG_CRITICAL, 
                        "Could not allocate memory for payload");
                }
           }
           break;
        case TRANSPORT_STATE_SERVER_WAIT_INITIAL:
            /* This is the initial state in server mode. 
             * Wait for the handshake to appear in the ringbugger */
            {
                if (ring_buffer_length(&(h->rx_ringbuf)) 
                        >= WISH_CLIENT_HELLO_LEN) {
                    /* Step 1. Read in the expected bytes from ring buffer */
                    uint8_t buf[WISH_CLIENT_HELLO_LEN] = { 0 };
                    ring_buffer_read(&(h->rx_ringbuf), buf, WISH_CLIENT_HELLO_LEN);
                    
                    /* 2. decide if we have a Wish connection incoming */
                    if (buf[0] == 'W' && buf[1] == '.') {
                        WISHDEBUG(LOG_DEBUG, "Attempted wish connection, protocol level 0x%hhx", buf[2]);

                        /* The high nibble defines the Wish version to
                         * be used */
                        uint8_t wire_version = (buf[2] & 0xf0) >> 4;
                        if (wire_version != WISH_WIRE_VERSION) {
                            /* Client wants unsupported protocol or version */
                            WISHDEBUG(LOG_CRITICAL, "Bad version attempted");
                            wish_close_connection(core, h);
                            break;
                        }
                        else {
                            /* Wish connection wire version is OK, let's
                             * examine the connection type, in the low
                             * nibble */
                            uint8_t conn_type = buf[2] & 0xf;
                            if (conn_type == WISH_WIRE_TYPE_NORMAL) {
                                /* Normal situation, proceed */
                            }
                            else if (conn_type ==  WISH_WIRE_TYPE_FRIEND_REQ) {
                                WISHDEBUG(LOG_CRITICAL, "Friend req");
                                /* We have received a fried request.
                                 * Since we have already read in more
                                 * data than we would have needed, a
                                 * procedure must be followed:
                                 *
                                 * 1) Read out all of the unconsumed data
                                 * 2) Clear the ring buffer
                                 * 3) Write back the data we already consumed: 
                                 * buf+3, len = (WISH_CLIENT_HELLO_LEN - 3) 
                                 * 4) Write the unconsumed data to the ring buffer */
                                uint16_t unconsumed_data_len = ring_buffer_length(&(h->rx_ringbuf));
                                uint8_t unconsumed_data[unconsumed_data_len];
                                
                                ring_buffer_read(&(h->rx_ringbuf), unconsumed_data, unconsumed_data_len);
                                ring_buffer_write(&(h->rx_ringbuf), buf+3, WISH_CLIENT_HELLO_LEN-3);
                                
                                if (unconsumed_data_len > 0) {
                                    ring_buffer_write(&(h->rx_ringbuf), unconsumed_data, unconsumed_data_len);
                                }

                                /* Advance protocol states */
                                h->curr_transport_state = TRANSPORT_STATE_WAIT_FRAME_LEN;
                                h->curr_protocol_state = PROTO_SERVER_STATE_READ_FRIEND_CERT;

                                /* Place a "synthetic" notification that
                                 * there is new data available */
                                struct wish_event evt = { 
                                    .event_type = WISH_EVENT_NEW_DATA, 
                                    .context = h 
                                };
                                wish_message_processor_notify(&evt);

                                break;
                            } else {
                                WISHDEBUG(LOG_CRITICAL, "Unknown connection type");
                                wish_close_connection(core, h);
                                break;
                            }
                        }


                    }
                    else {
                        /* Error */
                        WISHDEBUG(LOG_CRITICAL, "Bad connection attempt");
                        wish_close_connection(core, h);
                        break;
                    }
                    /* 3. Decide if we want to continue, depending on
                     * the public key hashes the client submitted */
                    uint8_t* dst_id = &(buf[3]);
                    uint8_t* src_id = &(buf[3+WISH_ID_LEN]);

                    if (wish_core_check_wsid(core, h, dst_id, src_id) == false) {
                        WISHDEBUG(LOG_CRITICAL, "Refusing connection (no privkey)");
                        wish_close_connection(core, h);
                        break;
                    }
                    else {
                        wish_debug_print_array(LOG_DEBUG, "UIDs are known", src_id, WISH_ID_LEN);
                        wish_debug_print_array(LOG_DEBUG, "remote: ", dst_id, WISH_ID_LEN);
                    }

                    memcpy(h->local_wuid, dst_id, WISH_ID_LEN);
                    memcpy(h->remote_wuid, src_id, WISH_ID_LEN);

                    /* 4. Initiate DHE key exchange */
                    h->server_dhm_ctx = (mbedtls_dhm_context*)
                        wish_platform_malloc(sizeof(mbedtls_dhm_context));
                    if (h->server_dhm_ctx == 0) {
                        WISHDEBUG(LOG_CRITICAL, "Failed allocation near line %d", __LINE__);
                        wish_close_connection(core, h);
                        break;
                    }
                    mbedtls_dhm_context* server_dhm_ctx = h->server_dhm_ctx;
                    mbedtls_dhm_init(server_dhm_ctx);
                    /* Wish TCP transport is specified to use the
                     * modp15 group, which is defined in RFC3526 section 4, 
                     * and is the 3072 bit group. */
                    int ret 
                        = mbedtls_mpi_read_string(&(server_dhm_ctx->P), 16, 
                            MBEDTLS_DHM_RFC3526_MODP_3072_P);
                    if (ret) {
                        WISHDEBUG(LOG_CRITICAL, "Error setting up DHM P, closing connection");
                        wish_close_connection(core, h);
                        break;
                    }
                    ret 
                        = mbedtls_mpi_read_string(&(server_dhm_ctx->G), 16, 
                            MBEDTLS_DHM_RFC3526_MODP_3072_G);
                    if (ret) {
                        WISHDEBUG(LOG_CRITICAL, "Error setting up DHM G, closing connection");
                        wish_close_connection(core, h);
                        break;
                    }

                    server_dhm_ctx->len = mbedtls_mpi_size( &(server_dhm_ctx->P) );

                    uint8_t output[384];
                    size_t wr_len = 384;
                    ret = mbedtls_dhm_make_public(server_dhm_ctx, 2,
                        output, wr_len, wish_platform_fill_random, NULL);
                    if (ret) {
                        WISHDEBUG(LOG_CRITICAL, "Error writing DHM own public %hhx", ret);
                        wish_close_connection(core, h);
                        break;
                    }
                    /* Send our public value to the peer (the client) */
                    char frame_len_data[2] = { 0 };
                    memcpy(frame_len_data, &wr_len, 2);
                    /* FIXME byte order conversion here is not portable? */
                    uint8_t tmp = frame_len_data[0];
                    frame_len_data[0] = frame_len_data[1];
                    frame_len_data[1] = tmp;

                    unsigned char out_buffer[2+384];
                    memcpy(out_buffer, frame_len_data, 2);
                    memcpy(out_buffer+2, output, 384);
                    /* Send the frame length and the key in one go */
                    WISHDEBUG(LOG_DEBUG, "Attempting to send data");
                    (*(h->send))(h->send_arg, out_buffer, 2+384);

                    h->curr_transport_state = TRANSPORT_STATE_WAIT_FRAME_LEN;
                    h->curr_protocol_state = PROTO_SERVER_STATE_DH;
                    WISHDEBUG(LOG_DEBUG, "movint to TRANSPORT_STATE_WAIT_FRAME_LEN");
                }
            }
            break;
        case TRANSPORT_STATE_RELAY_CLIENT_SEND_SESSION_ID:
            WISHDEBUG(LOG_CRITICAL, "Sending relay session id");
            /* Just prior to entering this state the relay server has
             * told us that there is a connection waiting for us. We
             * open a connection to the relay server, send a wish
             * preabmle type 7, and then the relay session id */
            {
                const size_t msg_len = 3 + RELAY_SESSION_ID_LEN;
                uint8_t msg[msg_len];
                /* Create preabmle, type 7 */
                msg[0] = 'W';
                msg[1] = '.';
                msg[2] = (WISH_WIRE_VERSION << 4) | 
                    WISH_WIRE_TYPE_RELAY_SESSION;
                /* Copy the relay session id */
                memcpy(msg + 3, h->rctx->session_id, RELAY_SESSION_ID_LEN);

                (*(h->send))(h->send_arg, msg, msg_len);
                h->curr_transport_state = TRANSPORT_STATE_SERVER_WAIT_INITIAL;
            }

            break;
        case TRANSPORT_STATE_INITIAL:
        /* impossible */
        default:
            WISHDEBUG(LOG_CRITICAL, "Impossible transport state reached\n\r");
        break;
    }

}

/* Register a function which will be used by wish core when data is
 * to be sent.
 *
 * The send function is called with the argument given as arg */
void wish_core_register_send(wish_core_t* core, wish_context_t* h, int (*send)(void *, unsigned char*, int), void* arg) {
    h->send = send;
    h->send_arg = arg;
}

void wish_core_signal_tcp_event(wish_core_t* core, wish_context_t* h,  enum tcp_event ev) {
    WISHDEBUG(LOG_DEBUG, "TCP Event for connection id %d", h->connection_id);
    switch (ev) {
    case TCP_CONNECTED:
        WISHDEBUG(LOG_DEBUG, "Event TCP_CONNECTED\n\r");

        h->outgoing = true;
        
        if (h->friend_req_connection == false) {
            /* Start the whole show by sending the handshake bytes */
            const int buffer_len = 2+1+WISH_ID_LEN+WISH_ID_LEN;
            unsigned char buffer[buffer_len];
            buffer[0] = 'W';
            buffer[1] = '.';
            /* Protocol version and function */
            buffer[2] = (WISH_WIRE_VERSION << 4) | (WISH_WIRE_TYPE_NORMAL); 
            /* Now copy the destination id */
            memcpy(buffer+3, h->remote_wuid, WISH_ID_LEN);
            /* then copy the source id */
            memcpy(buffer+3+WISH_ID_LEN, h->local_wuid, WISH_ID_LEN);
            h->curr_transport_state = TRANSPORT_STATE_WAIT_FRAME_LEN;
            h->curr_protocol_state = PROTO_STATE_DH;

            /* Maestro, take it away please */
            (*(h->send))(h->send_arg, buffer, buffer_len);
        }
        else {
            WISHDEBUG(LOG_CRITICAL, "Sending frient request!");
            /* To send a friend request, you send 
             * W.<high_nible 1|llow nible 3> */
            const int buffer_len = 500;
            uint8_t buffer[buffer_len];
            uint8_t *handshake = buffer;
            handshake[0] = 'W';
            handshake[1] = '.';
            handshake[2] = WISH_WIRE_VERSION << 4 | WISH_WIRE_TYPE_FRIEND_REQ;

            /* Next, we will send our own certificate, but first we need
             * to wrap it inside a frame, so the next two bytes after
             * the handshake will be fill out later when we know the
             * cert frame length. 
             */

            /* Note +5, because we leave two bytes for frame len */
            uint8_t *doc = buffer+5;
            size_t doc_len = buffer_len -5;

            bson bs;
            bson_init_buffer(&bs, doc, doc_len);
            bson_append_binary(&bs, "ruid", h->remote_wuid, WISH_ID_LEN);
            int req_id_len = 7;
            uint8_t req_id[req_id_len];
            wish_platform_fill_random(NULL, req_id, req_id_len);
            int i = 0;
            for (i = 0; i < req_id_len; i++) {
                req_id[i] = req_id[i] % 26 + 'a';
            }
            req_id[6] = 0;
            bson_append_string(&bs, "id", req_id);

            /* Generate our own cert */
            size_t my_cert_max_len = 300;
            uint8_t my_identity[my_cert_max_len];
            
            if (wish_load_identity_bson(h->local_wuid, my_identity, my_cert_max_len) < 0) {
                WISHDEBUG(LOG_CRITICAL, "Identity could not be loaded");
                break;
            }
            WISHDEBUG(LOG_CRITICAL, "cert len = %d", bson_get_doc_len(my_identity));
            /* Then, filter out privkey from the identity */
            uint8_t my_cert[my_cert_max_len];
            bson_filter_out_elem("privkey", my_identity, my_cert);

            bson_append_binary(&bs, "cert", my_cert, bson_get_doc_len(my_cert));
            bson_finish(&bs);

            
            if (bs.err) {
                WISHDEBUG(LOG_CRITICAL, "Send friend request: Failed writing bson.");
            }
            else {
                int frame_len = bson_size(&bs);
                uint8_t *frame_hdr = buffer + 3;
                uint16_t frame_len_be = uint16_native2be(frame_len);
                memcpy(frame_hdr, &frame_len_be, 2);
                int ret = (*(h->send))(h->send_arg, buffer, 3+2+frame_len);
                if (ret) {
                    WISHDEBUG(LOG_CRITICAL, "Failed sending friend request");
                    break;
                }
                h->curr_transport_state = TRANSPORT_STATE_WAIT_FRAME_LEN;
                h->curr_protocol_state = PROTO_STATE_FRIEND_REQ_RESPONSE;
            }
        }
        break;
    case TCP_CLIENT_DISCONNECTED:
        WISHDEBUG(LOG_DEBUG, "Event TCP_CLIENT_DISCONNECTED\n\r");
        /* FALLTHROUGH */
    case TCP_DISCONNECTED:
        WISHDEBUG(LOG_DEBUG, "Event TCP_DISCONNECTED\n\r");

        /* Send offline signal to local services, but only if
         * there are no other connections active to the same luid, ruid,
         * rhid combination. */
        {
            wish_context_t *ctx = h;
            int i = 0;
            bool other_connection_found = false;
#if 1
            for (i = 0; i < WISH_CONTEXT_POOL_SZ; i++) {
                wish_context_t *other_ctx = &(core->wish_context_pool[i]);
                if (ctx == other_ctx) {
                    /* Don't examine our current wish context, the one
                     * that was just disconnected  */
                    continue;
                }
                else {
                    /* FIXME can this be refactored to use the
                     * "lookup-by-luid-ruid-rhid" function instead? */
                    if (memcmp(other_ctx->local_wuid, ctx->local_wuid,
                            WISH_ID_LEN) == 0) {
                        if (memcmp(other_ctx->remote_wuid,
                                ctx->remote_wuid, WISH_ID_LEN) == 0) {
                            if (other_ctx->context_state ==
                                    WISH_CONTEXT_CONNECTED) {
                                /* Found other connection, do
                                 * not send offline */
                               other_connection_found = true;
                               break;
                            }
                        }
                    }
                }
            }
#endif

            if (other_connection_found) {
                WISHDEBUG(LOG_CRITICAL, "Not sending \
offline signal because other connection luid and ruid found!");
            }
            else {
                wish_send_online_offline_signal_to_apps(core, h, false);
            }
        }
        
        /* Delete any outstanding RPC request contexts */
        wish_cleanup_core_rpc_server(core, h);

        /* Do some housework to ensure the stack is left in consistent
         * state */
        
        /* Free the list of remote services associated with this
         * connection. Note usage of LL_FOREACH_SAFE because we delete
         * the element */
        struct wish_remote_service *service;
        struct wish_remote_service *tmp;
        LL_FOREACH_SAFE(h->rsid_list_head, service, tmp) {
            LL_DELETE(h->rsid_list_head, service);
            wish_platform_free(service);
        }

        /* Empty the ring buffer */
        ring_buffer_skip(&(h->rx_ringbuf), 
            ring_buffer_length(&(h->rx_ringbuf)));
        

        /* Just set everything to zero - a reliable way to reset it */
        memset(h, 0, sizeof(wish_context_t));

        h->curr_protocol_state = PROTO_STATE_INITIAL;
        h->curr_transport_state = TRANSPORT_STATE_WAIT_FRAME_LEN;

        h->context_state = WISH_CONTEXT_FREE;

        h->close_timestamp = 0;
        h->send_arg = NULL;
        break;
    case TCP_CLIENT_CONNECTED:
        WISHDEBUG(LOG_DEBUG, "Event TCP_CLIENT_CONNECTED");
        h->outgoing = false;
        h->curr_transport_state = TRANSPORT_STATE_SERVER_WAIT_INITIAL;
        break;
    case TCP_RELAY_SESSION_CONNECTED:
        /* If this event happens, it means that the we (as a relay
         * client) have managed to open a session to the relay server
         * for the purpose of accepting an incoming connection that is waiting 
         * at the relay server */
        WISHDEBUG(LOG_DEBUG, "Event TCP_RELAY_SESSION_CONNECTED");
        h->curr_transport_state
                    = TRANSPORT_STATE_RELAY_CLIENT_SEND_SESSION_ID;
        wish_core_process_data(core, h);

        break;
    }
    
}

#include "mbedtls/bignum.h"

/*
 * Convert a 32-bit integer to/from Big Endian 
 */
static uint32_t uint32_convert_be(uint32_t net_number) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    /* Big endian architecture - pass through */
    return value_in;
#else 
    /* Little endian architecture detected */
    /* See https://sourceforge.net/p/predef/wiki/Endianness/ */

    unsigned int result = 0;
    int i;

    for (i = 0; i < (int)sizeof(result); i++) {
        result <<= CHAR_BIT;
        result += (((unsigned char *)&net_number)[i] & UCHAR_MAX);
    }
    return result;

#endif
}

#define AES_GCM_NONCE_LEN   8
/* See reference implementation in wish-core:src/connection/aes-gcm.js */
static void update_nonce(unsigned char* nonce_bin) {
    uint32_t nonce1 = 0;
    uint32_t nonce2 = 0;
    memcpy(&nonce1, nonce_bin+4, 4);
    memcpy(&nonce2, nonce_bin, 4);
    nonce1 = uint32_convert_be(nonce1);
    nonce2 = uint32_convert_be(nonce2);
    nonce1++;
    if (nonce1 == 0) {
        nonce2++;
        nonce2 = uint32_convert_be(nonce2);
        memcpy(nonce_bin, &nonce2, 4);
    }
    nonce1 = uint32_convert_be(nonce1);
    memcpy(nonce_bin+4, &nonce1, 4);

#if 0
    WISHDEBUG(LOG_CRITICAL, "Nonce after update: ");
    int i = 0;
    for (i = 0; i < AES_GCM_NONCE_LEN; i++) {
        wish_platform_printf("0x%x ", nonce_bin[i]);
    }
#endif
}

/* This function generates the "client" and "server" hashes, using the
 * DHM secret (384 byte long). The hashes are saved to the wish context.
 * */
static void build_client_and_server_hashes(wish_context_t *ctx, 
        uint8_t *secret) {
    /* Now that we have the key handy, let's build the client
     * and server hashes */
    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0); 
    /* Create the client hash: it consists of the static string
     * "client" followed by the secret session key computed
     * during the DH hanshake phase */
    const char *client_str = "client";
    mbedtls_sha256_update(&sha256_ctx, (const unsigned char*) client_str, 
        strlen(client_str)); 
    mbedtls_sha256_update(&sha256_ctx, secret, 384); 
    mbedtls_sha256_finish(&sha256_ctx, ctx->client_hash);
    mbedtls_sha256_free(&sha256_ctx);
    //wish_debug_print_array(LOG_CRITICAL, ctx->client_hash, SHA256_HASH_LEN);
    
    /* Server hash */
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0); 
    /* Create the server hash: it consists of the static string
     * "server" followed by the secret session key computed
     * during the DH hanshake phase */
    const char *server_str = "server";
    mbedtls_sha256_update(&sha256_ctx, (const unsigned char*) server_str, 
        strlen(server_str)); 
    mbedtls_sha256_update(&sha256_ctx, secret, 384); 
    mbedtls_sha256_finish(&sha256_ctx, ctx->server_hash);
    mbedtls_sha256_free(&sha256_ctx);

}


void wish_core_handle_payload(wish_core_t* core, wish_context_t* ctx, uint8_t* payload, int len) {
    switch (ctx->curr_protocol_state) {
    case PROTO_STATE_DH:
        /* Diffie-hellman key exchange */
        {
            mbedtls_dhm_context dhm_ctx;
            mbedtls_dhm_init(&dhm_ctx);
            /* Wish TCP transport is specified to use the
             * modp15 group, which is defined in RFC3526 section 4, and is the 
             * 3072 bit group. */
            int ret = mbedtls_mpi_read_string(&dhm_ctx.P, 16, MBEDTLS_DHM_RFC3526_MODP_3072_P);
            if (ret) {
                WISHDEBUG(LOG_CRITICAL, "Error setting up DHM P");
                wish_close_connection(core, ctx);
                break;
            }
            ret = mbedtls_mpi_read_string(&dhm_ctx.G, 16, MBEDTLS_DHM_RFC3526_MODP_3072_G);
            if (ret) {
                WISHDEBUG(LOG_CRITICAL, "Error setting up DHM G");
                wish_close_connection(core, ctx);
                break;
            }

            dhm_ctx.len = mbedtls_mpi_size( &dhm_ctx.P );
            WISHDEBUG(LOG_TRIVIAL, "ctx len %d ", dhm_ctx.len);
            /* Read peer's public value */
            ret = mbedtls_dhm_read_public(&dhm_ctx, payload, len);
            if (ret) {
                WISHDEBUG(LOG_CRITICAL, "Error reading DHM peer public ");
                wish_close_connection(core, ctx);
                break;
            }

            uint8_t output[384];
            size_t wr_len = 384;
            ret = mbedtls_dhm_make_public(&dhm_ctx, 2,
                output, wr_len, wish_platform_fill_random, NULL);
            if (ret) {
                WISHDEBUG(LOG_CRITICAL, "Error writing DHM own public %hhx", ret);
                wish_close_connection(core, ctx);
                break;
            }
            /* Send our public value to the peer */
            char frame_len_data[2] = { 0 };
            memcpy(frame_len_data, &wr_len, 2);
            /* byte order conversion here is not portable */
            uint8_t tmp = frame_len_data[0];
            frame_len_data[0] = frame_len_data[1];
            frame_len_data[1] = tmp;
            WISHDEBUG(LOG_TRIVIAL, "0: %hhx", frame_len_data[0]);
            WISHDEBUG(LOG_TRIVIAL, "1: %hhx", frame_len_data[1]);
            unsigned char out_buffer[2+384];
            memcpy(out_buffer, frame_len_data, 2);
            memcpy(out_buffer+2, output, 384);
            /* Send the frame length and the key in one go */
            (*(ctx->send))(ctx->send_arg, out_buffer, 2+384);

            /* Calculate shared secret */
            ret = mbedtls_dhm_calc_secret(&dhm_ctx, 
                output, 384, &wr_len, NULL, NULL);
            if (ret) {
                WISHDEBUG(LOG_CRITICAL, "Error deriving shared secret %x", ret);
                wish_close_connection(core, ctx);
                break;
            }
            else {
                /* Shared secret was calculated */
                WISHDEBUG(LOG_TRIVIAL, "shared secret, len %d: ", wr_len);
                int i = 0;
                for (i = 0; i < wr_len; i++) {
                    WISHDEBUG2(LOG_INFO, "0x%x ", output[i]);
                }
            }
            mbedtls_dhm_free(&dhm_ctx);

            /* Copy AES key and IV vectors for in the outgoing (they are
             * the same at first, but then their nonce parts are
             * separately incremented at every transmission and receive*/
            memcpy(ctx->aes_gcm_key_in, output+32, 16);
            memcpy(ctx->aes_gcm_key_out, output, 16);
            memcpy(ctx->aes_gcm_iv_in, output+32+16, 12);
            memcpy(ctx->aes_gcm_iv_out, output+16, 12);

            int i = 0;
            /* Print out key */
            WISHDEBUG(LOG_INFO, "IN key: ");
            for (i = 0; i < 16; i++) {
                WISHDEBUG2(LOG_INFO, "0x%x ", ctx->aes_gcm_key_in[i]);
            }

            /* Build the client and server hashes now, because we have
             * the secret at hand. The hashes are stored
             * in the wish context struct */
            build_client_and_server_hashes(ctx, output);

            ctx->curr_protocol_state = PROTO_STATE_ID_VERIFY_SEND_CLIENT_HASH;
        }

        break;
    case PROTO_STATE_ID_VERIFY_SEND_CLIENT_HASH:
        /* We have agreed upon a shared key, now lets use it to perform
         * a identity verification by sending the client hash */
        {
            uint8_t signature[ED25519_SIGNATURE_LEN];
            uint8_t local_privkey[WISH_PRIVKEY_LEN];
            if (wish_load_privkey(ctx->local_wuid, local_privkey)) {
                WISHDEBUG(LOG_CRITICAL, "Could not load privkey");
                wish_close_connection(core, ctx);
                break;
            }
            else {
                ed25519_sign(signature, ctx->client_hash, SHA256_HASH_LEN,
                    local_privkey);
            }

            wish_debug_print_array(LOG_DEBUG, "Signature:", signature, ED25519_SIGNATURE_LEN);
            wish_core_send_message(core, ctx, signature, ED25519_SIGNATURE_LEN);

            /* Then, check that we can read a frame whose length
             * corresponds to the server hash */

            const int server_signature_len = ED25519_SIGNATURE_LEN;
            unsigned char server_signature[server_signature_len];
            /* Length of part of incoming payload containing cipher text */
            int ciphertxt_len = len-AES_GCM_AUTH_TAG_LEN;
            WISHDEBUG(LOG_DEBUG, "ciphertxt len is %d", ciphertxt_len);

            /* Pointer to the beginning of the auth_tag */
            uint8_t* auth_tag = payload + ciphertxt_len;

            if (wish_core_decrypt(core, ctx, payload, ciphertxt_len, 
                    auth_tag, AES_GCM_AUTH_TAG_LEN, 
                        server_signature, server_signature_len)) {
                WISHDEBUG(LOG_CRITICAL, "Decryption fails in server hash check");
                wish_close_connection(core, ctx);
                break;
            }
            
            uint8_t remote_pubkey[WISH_PUBKEY_LEN] = { 0 };
            if (wish_load_pubkey(ctx->remote_wuid, remote_pubkey)) {
                WISHDEBUG(LOG_CRITICAL, "Could not load remote pubkey");
                wish_close_connection(core, ctx);
                break;
            }

            if (ed25519_verify(server_signature, ctx->server_hash,
                    SHA256_HASH_LEN, remote_pubkey) == 0) {
                WISHDEBUG(LOG_CRITICAL, "Server hash signature check fail");
                wish_close_connection(core, ctx);
                break;
            }
            else {
                WISHDEBUG(LOG_DEBUG, "Server hash signature check OK");
            }

            ctx->curr_protocol_state = PROTO_STATE_WISH_HANDSHAKE;
        }
        break;
    case PROTO_STATE_WISH_HANDSHAKE:
        /* Remote ID has been verified, lets start setting up Wish */
        {

            const int plaintxt_len = 256;
            unsigned char plaintxt[plaintxt_len];
            /* Length of part of incoming payload containing cipher text */
            int ciphertxt_len = len - AES_GCM_AUTH_TAG_LEN;
            /* Pointer to the beginning of the auth_tag */
            uint8_t* auth_tag = payload + ciphertxt_len;

            if (wish_core_decrypt(core, ctx, payload, ciphertxt_len, auth_tag,
                AES_GCM_AUTH_TAG_LEN, plaintxt, plaintxt_len)) {

                WISHDEBUG(LOG_CRITICAL, "Decrypt fails in Wish handshake");
                wish_close_connection(core, ctx);
                break;

            }

            /* Submit the decrypted message upwards in the stack */
            wish_debug_print_array(LOG_TRIVIAL, "Performing local handshake steps", plaintxt, len-AES_GCM_AUTH_TAG_LEN);
            wish_core_process_handshake(core, ctx, plaintxt);
            ctx->curr_protocol_state = PROTO_STATE_WISH_RUNNING;

            struct wish_event evt = { .event_type =
                WISH_EVENT_NEW_CORE_CONNECTION, .context = ctx };
            wish_message_processor_notify(&evt);

       }
        break;
    case PROTO_STATE_WISH_RUNNING:
        {
            WISHDEBUG(LOG_WIRE, "processing message of length %d\n\r", len);

            /* Length of part of incoming payload containing cipher text */
            int ciphertxt_len = len - AES_GCM_AUTH_TAG_LEN;
            int plaintxt_len = ciphertxt_len;
            /* Pointer to the beginning of the auth_tag */
            uint8_t* auth_tag = payload + ciphertxt_len;

            wish_debug_print_array(LOG_TRIVIAL, "Auth tag", auth_tag, AES_GCM_AUTH_TAG_LEN);

            uint8_t* plaintxt = (uint8_t*) wish_platform_malloc(plaintxt_len);
            if (plaintxt == NULL) {
                WISHDEBUG(LOG_CRITICAL, "Could not allocate memory");
                wish_close_connection(core, ctx);
                break;
            }

            int ret = wish_core_decrypt(core, ctx, payload, ciphertxt_len, 
                auth_tag, AES_GCM_AUTH_TAG_LEN, plaintxt, plaintxt_len);

            if (ret) {
                WISHDEBUG(LOG_CRITICAL, 
                    "There was an error while decrypting Wish message");
                wish_platform_free(plaintxt);
                wish_close_connection(core, ctx);
                break;
            }
            wish_debug_print_array(LOG_TRIVIAL, "Plaintext", plaintxt, len);
            wish_core_process_message(core, ctx, plaintxt);
            wish_platform_free(plaintxt);
        }
        break;
    case PROTO_SERVER_STATE_DH:
        WISHDEBUG(LOG_DEBUG, "Begin server diffie-helman");
        /* Before entering this state, we have initialised the
         * diffie-hellman key exchange, and sent our public value to the
         * client. In this state, we have the client's public value, and
         * we are ready to calculate the secret. */
        {

            mbedtls_dhm_context* server_dhm_ctx = ctx->server_dhm_ctx;
            /* Read peer's public value */
            int ret 
                = mbedtls_dhm_read_public(server_dhm_ctx, payload, len);
            if (ret) {
                WISHDEBUG(LOG_CRITICAL, "Error reading DHM peer public ");
            }

            uint8_t output[384];
            size_t wr_len = 384;
            /* Calculate shared secret */
            ret = mbedtls_dhm_calc_secret(server_dhm_ctx, 
                output, 384, &wr_len, NULL, NULL);
            if (ret) {
                WISHDEBUG(LOG_CRITICAL, "Error deriving shared secret %x", ret);
                wish_close_connection(core, ctx);
                break;
 
            }
            else {
                /* Shared secret was calculated */
                WISHDEBUG(LOG_INFO, "shared secret, len %d: ", wr_len);
                int i = 0;
                for (i = 0; i < wr_len; i++) {
                    WISHDEBUG2(LOG_INFO, "0x%x ", output[i]);
                }
            }
            mbedtls_dhm_free(server_dhm_ctx);

            /* Copy AES key and IV vectors for in the outgoing (they are
             * the same at first, but then their nonce parts are
             * separately incremented at every transmission and receive*/
            memcpy(ctx->aes_gcm_key_out, output+32, 16);
            memcpy(ctx->aes_gcm_key_in, output, 16);
            memcpy(ctx->aes_gcm_iv_out, output+32+16, 12);
            memcpy(ctx->aes_gcm_iv_in, output+16, 12);

            wish_platform_free(server_dhm_ctx);

            /* Save the client and server hashes, because we have the
             * secret at hand */
            build_client_and_server_hashes(ctx, output);

            /* We can now communicate securely, proceed to identity check.
             * First, send the server hash signature to client */
            uint8_t signature[ED25519_SIGNATURE_LEN];
            uint8_t local_privkey[WISH_PRIVKEY_LEN];
            if (wish_load_privkey(ctx->local_wuid, local_privkey)) {
                WISHDEBUG(LOG_CRITICAL, "Could not load privkey");
                wish_close_connection(core, ctx);
                break;
            }
            ed25519_sign(signature, ctx->server_hash, SHA256_HASH_LEN,
                local_privkey);

            wish_core_send_message(core, ctx, signature, ED25519_SIGNATURE_LEN);

            ctx->curr_protocol_state 
                = PROTO_SERVER_STATE_VERIFY_CLIENT_HASH;
        }
        break;
    case PROTO_SERVER_STATE_VERIFY_CLIENT_HASH:
        {
            /* Then, read the client hash and verify */
            const int client_signature_len = ED25519_SIGNATURE_LEN;
            unsigned char client_signature[client_signature_len];
            /* Length of part of incoming payload containing cipher text */
            int ciphertxt_len = len-AES_GCM_AUTH_TAG_LEN;
            WISHDEBUG(LOG_DEBUG, "ciphertxt len is %d", ciphertxt_len);

            /* Pointer to the beginning of the auth_tag */
            uint8_t* auth_tag = payload + ciphertxt_len;

            if (wish_core_decrypt(core, ctx, payload, ciphertxt_len, 
                    auth_tag, AES_GCM_AUTH_TAG_LEN, 
                        client_signature, client_signature_len)) {
                WISHDEBUG(LOG_CRITICAL, "Decryption fails in client hash check");
                wish_close_connection(core, ctx);
                break;
            }
            
            uint8_t remote_pubkey[WISH_PUBKEY_LEN] = { 0 };
            if (wish_load_pubkey(ctx->remote_wuid, remote_pubkey)) {
                WISHDEBUG(LOG_CRITICAL, "Could not load remote pubkey");
                wish_close_connection(core, ctx);
                break;
            }

            if (ed25519_verify(client_signature, ctx->client_hash,
                    SHA256_HASH_LEN, remote_pubkey) == 0) {
                WISHDEBUG(LOG_CRITICAL, "Client hash signature check fail");
                wish_close_connection(core, ctx);
                break;
            }
            else {
                WISHDEBUG(LOG_DEBUG, "Client hash signature check OK");

            }

            /* Identities have now been successfully verified */
            ctx->curr_protocol_state 
                = PROTO_SERVER_STATE_WISH_SEND_HANDSHAKE;
        }
        /* WARNING: FALLTHROUGH */
    case PROTO_SERVER_STATE_WISH_SEND_HANDSHAKE:
        {
             /* Send Wish handshake */
            WISHDEBUG(LOG_DEBUG, "Sending handshake");
            const int max_handshake_len = 500;
            uint8_t handshake_msg[max_handshake_len];

            wish_core_create_handshake_msg(core, handshake_msg, max_handshake_len);
           
            WISHDEBUG(LOG_DEBUG, "We have generated BSON message of len %d", 
                bson_get_doc_len(handshake_msg));

            if (wish_core_send_message(core, ctx, handshake_msg, 
                    bson_get_doc_len(handshake_msg))) {
                /* Send error. Skip sending this time */
                WISHDEBUG(LOG_CRITICAL, "Send fails in server state \
wish send handshake");
                break;
            }
            /* Sending OK */
            ctx->curr_protocol_state 
                = PROTO_SERVER_STATE_WISH_HANDSHAKE_READ_REPLY;
        }
        break;
    case PROTO_SERVER_STATE_WISH_HANDSHAKE_READ_REPLY:
        WISHDEBUG(LOG_DEBUG, "In server handshake read reply phase");
        {
            uint8_t* plaintxt = (uint8_t*) wish_platform_malloc(len);
            if (plaintxt == NULL) {
                WISHDEBUG(LOG_CRITICAL, "Out of memory in server handshake read reply phase");
                wish_close_connection(core, ctx);
                break;
            }
            int ciphertxt_len = len-AES_GCM_AUTH_TAG_LEN;
             /* Pointer to the beginning of the auth_tag */
            uint8_t* auth_tag = payload + ciphertxt_len;


            int ret = wish_core_decrypt(core, ctx, payload, ciphertxt_len, 
                auth_tag, AES_GCM_AUTH_TAG_LEN, plaintxt, len);

            if (ret) {
                WISHDEBUG(LOG_CRITICAL, 
                    "There was an error while decrypting Wish message");
                wish_platform_free(plaintxt);
                wish_close_connection(core, ctx);
                break;
            }

            wish_debug_print_array(LOG_TRIVIAL, "Got handshake reply OK", plaintxt, len);

            /* Recover the Host id of the client */
            uint8_t* host_id = NULL;
            int32_t host_id_len = 0;
            if (bson_get_binary(plaintxt, "host", &host_id, &host_id_len)
                        == BSON_FAIL) {
                WISHDEBUG(LOG_CRITICAL, "We could not get the host field from client handshake");
                return;
            }
            if (host_id_len == WISH_WHID_LEN) {
                memcpy(ctx->remote_hostid, host_id, WISH_WHID_LEN);
            }
            else {
                WISHDEBUG(LOG_CRITICAL, "Bad hostid length in client handshake");
                return;
            }

            /* Finished processing the handshake */
            wish_platform_free(plaintxt);

            /* Start pinging process */

            ctx->curr_protocol_state = PROTO_STATE_WISH_RUNNING;
            struct wish_event evt = { .event_type =
                WISH_EVENT_NEW_CORE_CONNECTION, .context = ctx };
            wish_message_processor_notify(&evt);


        }
        break;
    case PROTO_SERVER_STATE_READ_FRIEND_CERT:
        {
            if (len != bson_get_doc_len(payload)) {
                WISHDEBUG(LOG_CRITICAL, "Friend request: Unexpected cert len");
                wish_close_connection(core, ctx);
                break;
            }

            /* Get the recepient identity of the friend request */
            int32_t recepient_uid_len = 0;
            uint8_t *recepient_uid = NULL;
            if (bson_get_binary(payload, "ruid", &recepient_uid, &recepient_uid_len) != BSON_SUCCESS) {
                WISHDEBUG(LOG_CRITICAL, "Did not find ruid");
            }
            if (recepient_uid_len != WISH_ID_LEN) {
                WISHDEBUG(LOG_CRITICAL, "ruid len missmatch");
            }


            int32_t cert_doc_len = 0;
            uint8_t *cert_doc = NULL;
            if (bson_get_binary(payload, "cert", &cert_doc, &cert_doc_len) 
                    != BSON_SUCCESS) {
                WISHDEBUG(LOG_CRITICAL, "Did not find cert");
            }

            if (bson_get_doc_len(cert_doc) != cert_doc_len) {
                WISHDEBUG(LOG_CRITICAL, "Contradictory cert lengths");
            }

            int32_t alias_len = 0;
            char *alias = NULL;
            if (bson_get_string(cert_doc, "alias", &alias, &alias_len) != BSON_SUCCESS) {
                WISHDEBUG(LOG_CRITICAL, "Friend request: No alias");
            }
            WISHDEBUG(LOG_CRITICAL, "Friend request from %s", alias);


            /* FIXME Quarantine the identity represented by 'cert', it
             * should be released only when the user decides to allow it! */

    #ifdef WISH_ACCEPT_ANY_FRIEND_REQ_IF_NO_FRIENDS
            /* If WISH_ACCEPT_ANY_FRIEND_IF_NO_FRIENDS is defined, then we allow a
             * friend request if there is only one identity in the id
             * database. */
            {
                wish_uid_list_elem_t uid_list[2];
                memset(uid_list, 0, sizeof (uid_list));

                int num_ids = wish_load_uid_list(uid_list, 2);
                if (num_ids > 1) {
                    WISHDEBUG(LOG_CRITICAL, "Since number of identities in db is %d,\
    we deny     the friend request automatically.", num_ids);
                    break;
                }
                else {
                    WISHDEBUG(LOG_CRITICAL, "Since number of identities in db is %d \
    we accep    t the friend request automatically.", num_ids);
                }
            }
    #else
    #ifndef WISH_ALLOW_ALL_FRIEND_REQS

    #error  Stop! Unimpelemnted feature! You must have WISH_ALLOW_ALL_FRIEND_REQS or WISH_ACCEPT_ANY_FRIEND_REQ_IF_NO_FRIENDS

    #else
            WISHDEBUG(LOG_CRITICAL, "Since WISH_ALLOW_ALL_FRIEND_REQS is defined, welcoming stranger with open arms!");

    #endif  //WISH_ALLOW_ALL_FRIEND_REQS
    #endif  //WISH_ACCEPT_ANY_FRIEND_REQ_IF_NO_FRIENDS

            /* FIXME Now just saving the identity in the database and
             * allowing it in */
            wish_identity_t new_id;
            memset(&new_id, 0, sizeof (wish_identity_t));

            wish_populate_id_from_cert(&new_id, cert_doc);

            // Check if identity is already in db

            int num_uids_in_db = wish_get_num_uid_entries();
            wish_uid_list_elem_t uid_list[num_uids_in_db];
            int num_uids = wish_load_uid_list(uid_list, num_uids_in_db);

            bool found = false;
            int i = 0;
            for (i = 0; i < num_uids; i++) {
                if ( memcmp(&uid_list[i].uid, &new_id.uid, WISH_ID_LEN) == 0 ) {
                    WISHDEBUG(LOG_CRITICAL, "Identity already in DB, we wont add it multiple times.");
                    found = true;
                    break;
                }
            }

            if(!found) {
                wish_save_identity_entry(&new_id);
            }

            /* Save the 'id' element in payload to wish context. It will be
             * used later, if/when user accepts friend request, to retrieve
             * the friend request from "quarantine" and really add it to
             * contacts */
            //memcpy(ctx->pending_friend_req_id, friend_req_id, SIZEOF_ID)

            /* Save the recipient UID of the friend request as luid for the
             * context. This information will be used later when exporting
             * the cert */
            memcpy(ctx->local_wuid, recepient_uid, WISH_ID_LEN);

            struct wish_event evt = { 
                .event_type = WISH_EVENT_FRIEND_REQUEST, 
                .context = ctx 
            };
            wish_message_processor_notify(&evt);

        }
        break;
    case PROTO_SERVER_STATE_REPLY_FRIEND_REQ:
        {
            WISHDEBUG(LOG_CRITICAL, "Replying to friend request");

            /* First, load the identity... The UID of the identity that
             * the remote wish core wanted to befriend with is stored in
             * ctx->local_wuid FIXME? */
            size_t my_cert_max_len = 300;
            uint8_t my_identity[my_cert_max_len];
            
            if (wish_load_identity_bson(ctx->local_wuid, my_identity, 
                    my_cert_max_len) < 0) {
                WISHDEBUG(LOG_CRITICAL, "Identity could not be loaded");
            }
            WISHDEBUG(LOG_CRITICAL, "len = %d", bson_get_doc_len(my_identity));

            /* Then, filter out privkey from the identity */
            uint8_t my_cert[my_cert_max_len];
            bson_filter_out_elem("privkey", my_identity, my_cert);
            WISHDEBUG(LOG_CRITICAL, "len = %d", bson_get_doc_len(my_cert));

            const int32_t friend_req_frame_max_len = my_cert_max_len + 100;
            uint8_t friend_req_frame[friend_req_frame_max_len];
            bson_init_doc(friend_req_frame, friend_req_frame_max_len);
            bson_write_binary(friend_req_frame, friend_req_frame_max_len,
                "cert", my_cert, bson_get_doc_len(my_cert));

            /* Encode the length of the document in the begining, then
             * send len + the frame */
            /* FIXME REFACTOR */
            /* Sinxa LE->BE */
            uint16_t frame_len = bson_get_doc_len(friend_req_frame);
            uint8_t frame[2+frame_len];
            uint16_t frame_len_be = uint16_native2be(frame_len);
            memcpy(frame, &frame_len_be, 2);
            memcpy(frame+2, friend_req_frame, 
                bson_get_doc_len(friend_req_frame));
            /* Send the frame length and the key in one go */
            int ret = (*(ctx->send))(ctx->send_arg, frame, 2+frame_len);
 
            if (ret != 0) {
                /* Sending failed */
                WISHDEBUG(LOG_CRITICAL, "Sending failed");
            }
            wish_close_connection(core, ctx);

        }
        break;
    case PROTO_STATE_FRIEND_REQ_RESPONSE: {
        /* This state is entered after we have sent a friend request to
         * a peer, and the peer has sent some kind of a reply to us 
         * (usually a cert, if the frient request was accepted) */
        ;
        int32_t cert_len = 0;
        uint8_t *cert;
        if (bson_get_binary(payload, "cert", &cert, &cert_len)
                    == BSON_FAIL) {
            WISHDEBUG(LOG_CRITICAL, "Cannot get certificate from friend req reply");
            break;
        }

        int32_t cert_alias_len = 0;
        char *cert_alias = NULL;
        if (bson_get_string(cert, "alias", &cert_alias, &cert_alias_len)
                != BSON_SUCCESS) {
            WISHDEBUG(LOG_CRITICAL, "Friend request response: No alias");
            break;
        }
        WISHDEBUG(LOG_CRITICAL, "Yay, we are making friends with %s", cert_alias);
        
        // Read out details from cert
        wish_identity_t new_friend_id;
        memset(&new_friend_id, 0, sizeof (wish_identity_t));
        wish_populate_id_from_cert(&new_friend_id, cert);
        
        // Check if we already have this identity
        int num_uids_in_db = wish_get_num_uid_entries();
        wish_uid_list_elem_t uid_list[num_uids_in_db];
        int num_uids = wish_load_uid_list(uid_list, num_uids_in_db);

        bool found = false;
        int i = 0;
        for (i = 0; i < num_uids; i++) {
            if ( memcmp(&uid_list[i].uid, &new_friend_id.uid, WISH_ID_LEN) == 0 ) {
                WISHDEBUG(LOG_CRITICAL, "Identity already in DB, we wont add it multiple times.");
                found = true;
                break;
            }
        }

        if(!found) {
            wish_save_identity_entry(&new_friend_id);
        }
        

        /* Hang up the connection. A re-connection will happen via local
         * discovery, or via relay server once checkConnections is
         * implemented */
        wish_close_connection(core, ctx);

        break;
    }
    case PROTO_STATE_INITIAL:
        WISHDEBUG(LOG_CRITICAL, "PROTO_STATE_INITIAL: id %d", ctx->connection_id);
    default:
        WISHDEBUG(LOG_CRITICAL, "illegal protocol state reached, connection id %d\n\r", ctx->connection_id);
        break;
    }

}

uint16_t uint16_native2be(uint16_t in) {
    union be_data {
        uint16_t native_value;
        uint8_t bytes[2];
    } data;
    data.native_value = in;
    uint16_t out_native = 0;
    out_native |= data.bytes[0];
    out_native <<= 8;
    out_native |= data.bytes[1];
    return out_native;
}


/**
 * @return 0, if sending succeeds, else non-zero for an error
 */
int wish_core_send_message(wish_core_t* core, wish_context_t* ctx, uint8_t* payload_clrtxt, int payload_len) {
    mbedtls_gcm_context aes_gcm_ctx;
    mbedtls_gcm_init(&aes_gcm_ctx);
    WISHDEBUG(LOG_DEBUG, "send payload len %d", payload_len);
    int ret = mbedtls_gcm_setkey(&aes_gcm_ctx, MBEDTLS_CIPHER_ID_AES, 
                ctx->aes_gcm_key_out, AES_GCM_KEY_LEN*8);
    if (ret) {
        WISHDEBUG(LOG_CRITICAL, "Set key failed (out)");
        return 1;
    }
    /* Allocate an array of length 2 + payload_Len + auth_tag_len */
    size_t frame_len = 2+payload_len+AES_GCM_AUTH_TAG_LEN;
    WISHDEBUG(LOG_DEBUG, "frame len %d", frame_len);

    uint8_t* frame = (uint8_t*) wish_platform_malloc(frame_len);
    if (frame == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Memory allocation fail: %d", frame_len);
        return 1;
    }

    ret = mbedtls_gcm_crypt_and_tag(&aes_gcm_ctx, MBEDTLS_GCM_ENCRYPT, 
        payload_len, 
        ctx->aes_gcm_iv_out, AES_GCM_IV_LEN, NULL, 0,
        payload_clrtxt, frame+2,
        AES_GCM_AUTH_TAG_LEN, frame+2+payload_len);
    mbedtls_gcm_free(&aes_gcm_ctx);
    if (ret) {
        WISHDEBUG(LOG_CRITICAL, "Encryption fail");

        return 1;
    }

#if 0
    WISHDEBUG(LOG_TRIVIAL, "Auth tag:\n\r");
    int i = 0;
    for (i = 0; i < AES_GCM_AUTH_TAG_LEN; i++) {
        WISHDEBUG2(LOG_TRIVIAL, "0x%x ", (frame+2+payload_len)[i]);
    }
    WISHDEBUG(LOG_TRIVIAL, "");
#endif


    /* Sinxa LE->BE */
    uint16_t frame_len_be = uint16_native2be(payload_len+AES_GCM_AUTH_TAG_LEN);
    memcpy(frame, &frame_len_be, 2);
    /* Send the frame length and the key in one go */
    WISHDEBUG(LOG_DEBUG, "About to send %d", frame_len);
    ret = (*(ctx->send))(ctx->send_arg, frame, frame_len);
    if (ret == 0) {
        /* Sending not failed */
        WISHDEBUG(LOG_DEBUG, "Sent %d", frame_len);
        update_nonce(ctx->aes_gcm_iv_out+4);
    }
    else {
        WISHDEBUG(LOG_CRITICAL, "Porting layer send function reported failure");
    }
    wish_platform_free(frame);
    WISHDEBUG(LOG_DEBUG, "Exiting");
    return ret;
}


int wish_core_decrypt(wish_core_t* core, wish_context_t* ctx, uint8_t* ciphertxt, size_t 
ciphertxt_len, uint8_t* auth_tag, size_t auth_tag_len, uint8_t* plaintxt,
size_t plaintxt_len) {
    mbedtls_gcm_context aes_gcm_ctx;
    mbedtls_gcm_init(&aes_gcm_ctx);
    int ret = mbedtls_gcm_setkey(&aes_gcm_ctx, MBEDTLS_CIPHER_ID_AES, 
                ctx->aes_gcm_key_in, AES_GCM_KEY_LEN*8);
    if (ret) {
        WISHDEBUG(LOG_CRITICAL, "Set key failed (out)");
        mbedtls_gcm_free(&aes_gcm_ctx);
        return WISH_CORE_DECRYPT_FAIL;
    }

    if (ciphertxt_len > plaintxt_len) {
        WISHDEBUG(LOG_CRITICAL, "Would overwrite buffer bounds. Stop");
        mbedtls_gcm_free(&aes_gcm_ctx);
        return WISH_CORE_DECRYPT_FAIL;
    }

#if 0
    int i = 0;

    /* Print out iv */
    WISHDEBUG(LOG_TRIVIAL, "\n\riv: ");
    for (i = 0; i < AES_GCM_IV_LEN; i++) {
        WISHDEBUG2(LOG_TRIVIAL, "0x%x ", ctx->aes_gcm_iv_in[i]);
    }
    WISHDEBUG(LOG_TRIVIAL, "\n\rciphertext len=%d: ", ciphertxt_len);

    /* Print out ciphertext */
    for (i = 0; i < ciphertxt_len; i++) {
        WISHDEBUG2(LOG_TRIVIAL, "0x%x ", payload[i]);
    }
    WISHDEBUG(LOG_TRIVIAL"\n\rauth tag: ");
#endif

    /* The locally calculated auth tag is stored here - for later
     * comparison */
    unsigned char check_tag[AES_GCM_AUTH_TAG_LEN] = { 0 };
    WISHDEBUG(LOG_DEBUG, "cipher txt len=%i", ciphertxt_len);
    ret = mbedtls_gcm_crypt_and_tag(&aes_gcm_ctx, MBEDTLS_GCM_DECRYPT, 
        ciphertxt_len, 
        ctx->aes_gcm_iv_in, AES_GCM_IV_LEN, NULL, 0,
        ciphertxt, plaintxt, 
        AES_GCM_AUTH_TAG_LEN, check_tag);

    if (ret) {
        WISHDEBUG(LOG_CRITICAL, "Decrypting failed, ret=%x", ret);
        ctx->curr_protocol_state = PROTO_STATE_INITIAL;
        mbedtls_gcm_free(&aes_gcm_ctx);
        return WISH_CORE_DECRYPT_FAIL;
    }

    if (memcmp(auth_tag, check_tag, AES_GCM_AUTH_TAG_LEN) != 0) {
        wish_debug_print_array(LOG_CRITICAL, "Auth tag check fail, auth", auth_tag, auth_tag_len);
        wish_debug_print_array(LOG_CRITICAL, "Auth tag check fail, check", check_tag, AES_GCM_AUTH_TAG_LEN);
        ctx->curr_protocol_state = PROTO_STATE_INITIAL;
        mbedtls_gcm_free(&aes_gcm_ctx);
    
        return WISH_CORE_DECRYPT_FAIL;
    }

    update_nonce(ctx->aes_gcm_iv_in+4);
    mbedtls_gcm_free(&aes_gcm_ctx);

    return 0;
}

/* This function returns the wish context associated with the provided
 * remote IP, remote port, local IP, local port. If no matching wish
 * context is found, return NULL. */
wish_context_t* wish_identify_context(wish_core_t* core, uint8_t rmt_ip[4], 
    uint16_t rmt_port, uint8_t local_ip[4], uint16_t local_port) {

    bool found = false;

    int i = 0; 
    for (i = 0; i < WISH_CONTEXT_POOL_SZ; i++) {
        if (core->wish_context_pool[i].local_port != local_port) {
            continue;
        }
        if (core->wish_context_pool[i].remote_port != rmt_port) {
            continue;
        }
        int j = 0;
        for (j = 0; j < 4; j++) {
            if (core->wish_context_pool[i].rmt_ip_addr[j] !=
                    rmt_ip[j]) {
                continue;
            }
            if (core->wish_context_pool[i].local_ip_addr[j] !=
                    local_ip[j]) {
                continue;
            }
        }

        /* If we got this far, it means that we found our Wish context.
         * i is now the correct index */
        found = true;
        break;
    }

    if (found == false) {
        WISHDEBUG(LOG_CRITICAL, "Could not find the Wish context!");
        return NULL;
    }
    return &(core->wish_context_pool[i]);
}

/* 
 * This function will perform misc initting of various parts of the
 * system, mainly initting of RPC servers in the core 
 */
void wish_core_init(wish_core_t* core) {
    core->wish_server_port = core->wish_server_port == 0 ? 37009 : core->wish_server_port;
    core->wish_context_pool = wish_platform_malloc(sizeof(wish_context_t)*WISH_CONTEXT_POOL_SZ);
    core->next_conn_id = 1;
    
    wish_core_init_rpc(core);
    wish_core_app_rpc_init(core);
    
    core->core_rpc_client = wish_platform_malloc(sizeof(wish_rpc_client_t));
    core->core_rpc_client->next_id = 1;
    core->core_rpc_client->context = core;
    
    wish_ldiscover_init(core);
}


int wish_core_get_rx_buffer_free(wish_core_t* core, wish_context_t *ctx) {
    return ring_buffer_space(&(ctx->rx_ringbuf));
}


void wish_close_all_connections(wish_core_t* core) {
    int i = 0;
    for (i = 0; i < WISH_CONTEXT_POOL_SZ; i++) {
        switch (core->wish_context_pool[i].context_state) {
        case WISH_CONTEXT_FREE:
            continue;
            break;
        case WISH_CONTEXT_IN_MAKING:
            /* FALLTHROUGH */
        case WISH_CONTEXT_CONNECTED:
            wish_close_connection(core, &(core->wish_context_pool[i]));
            break;
        case WISH_CONTEXT_CLOSING:
            WISHDEBUG(LOG_CRITICAL, "Not closing connection which is already closing");
            break;
        }
    }
}
