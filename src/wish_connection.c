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
#include "wish_connection.h"
#include "wish_core_signals.h"
#include "wish_identity.h"
#include "wish_config.h"
#include "wish_relationship.h"
#include "core_service_ipc.h"
#include "wish_local_discovery.h"
#include "wish_acl.h"
#include "ed25519.h"
#include "bson.h"
#include "bson_visit.h"
#include "wish_platform.h"
#include "wish_dispatcher.h"
#include <limits.h>
#include "wish_event.h"
#include "wish_core_rpc.h"
#include "wish_core_app_rpc.h"
#include "wish_connection_mgr.h"

#include "utlist.h"


wish_connection_t* wish_core_get_connection_pool(wish_core_t* core) {
    return core->connection_pool;
}

/* Start an instance of wish communication */
wish_connection_t* wish_connection_init(wish_core_t* core, const uint8_t* luid, const uint8_t* ruid) {

    wish_connection_t* connection;

    int i = 0;
    for (i = 0; i < WISH_CONTEXT_POOL_SZ; i++) {
        connection = &(core->connection_pool[i]);
        if (connection->context_state == WISH_CONTEXT_FREE) {
            /* We have found a context we can take into use */
            connection->context_state = WISH_CONTEXT_IN_MAKING;
            /* Update timestamp */
            connection->latest_input_timestamp = wish_time_get_relative(core);
            break;
        }
    }

    if (i == WISH_CONTEXT_POOL_SZ) {
        WISHDEBUG(LOG_CRITICAL, "No vacant wish context found");
        return NULL;
    }
    /* w now points to the vacant wish context we will use */

    // 
    connection->core = core;
    
    /* Associate a connection id to the connection */
    connection->connection_id = core->next_conn_id++;

    memcpy(connection->luid, luid, WISH_ID_LEN);
    memcpy(connection->ruid, ruid, WISH_ID_LEN);
    
    connection->rx_ringbuf.max_len = RX_RINGBUF_LEN;
    connection->rx_ringbuf.data = connection->rx_ringbuf_backing;

    connection->curr_transport_state = TRANSPORT_STATE_INITIAL;
    connection->curr_protocol_state = PROTO_STATE_INITIAL;
    connection->apps = NULL;

    return connection;
}


/* This function returns the pointer to the wish context corresponding
 * to the id number given as argument */
wish_connection_t* wish_core_lookup_ctx_by_connection_id(wish_core_t* core, wish_connection_id_t id) {
    wish_connection_t *connection = NULL;
    int i = 0;

    for (i = 0; i < WISH_CONTEXT_POOL_SZ; i++) {
        if (core->connection_pool[i].connection_id == id) {
            connection = &(core->connection_pool[i]);
            break;
        }
    }
    return connection;
}

wish_connection_t* wish_connection_exists(wish_core_t *core, wish_connection_t *connection) {
    for (int i = 0; i < WISH_CONTEXT_POOL_SZ; i++) {
        if (&core->connection_pool[i] == connection) {
            
            return connection;
        }
    }
    return NULL;
}

/** This function returns a pointer to the wish context which matches the
 * specified luid, ruid, rhid identities 
 *
 * Please note: The context returned here could a countext which is not
 * yet ready for use, because it is e.g. just being created.
 * 
 */
wish_connection_t* 
wish_core_lookup_ctx_by_luid_ruid_rhid(wish_core_t* core, const uint8_t *luid, const uint8_t *ruid, const uint8_t *rhid) {
    wish_connection_t *connection = NULL;
    int i = 0;

    for (i = 0; i < WISH_CONTEXT_POOL_SZ; i++) {
        if (core->connection_pool[i].context_state == WISH_CONTEXT_FREE) {
            /* If the wish context is not in use, we can safely skip it */
            //WISHDEBUG(LOG_CRITICAL, "Skipping free wish context");
            continue;
        }

        if (memcmp(core->connection_pool[i].luid, luid, WISH_ID_LEN) == 0) {
            if (memcmp(core->connection_pool[i].ruid, ruid, WISH_ID_LEN) 
                    == 0) {
                if (memcmp(core->connection_pool[i].rhid, rhid, 
                        WISH_WHID_LEN) == 0) {

                    connection = &(core->connection_pool[i]);
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
    return connection;
}

/** This function returns a pointer to the wish connection which matches the
 * specified luid, ruid, rhid
 *
 * The returned connection is always a connected one, and in case of multiple connections, the returned context is the one which has received data the least time ago
 */
wish_connection_t* 
wish_core_lookup_connected_ctx_by_luid_ruid_rhid(wish_core_t* core, const uint8_t *luid, const uint8_t *ruid, const uint8_t *rhid) {
    wish_connection_t *connection = NULL;
    int i = 0;

    wish_time_t latest_input = 0;
    for (i = 0; i < WISH_CONTEXT_POOL_SZ; i++) {
        if (core->connection_pool[i].context_state == WISH_CONTEXT_FREE) {
            /* If the wish context is not in use, we can safely skip it */
            //WISHDEBUG(LOG_CRITICAL, "Skipping free wish context");
            continue;
        }

        if (memcmp(core->connection_pool[i].luid, luid, WISH_ID_LEN) == 0) {
            if (memcmp(core->connection_pool[i].ruid, ruid, WISH_ID_LEN) 
                    == 0) {
                if (memcmp(core->connection_pool[i].rhid, rhid, 
                        WISH_WHID_LEN) == 0) {
                    if (core->connection_pool[i].context_state == WISH_CONTEXT_CONNECTED && core->connection_pool[i].latest_input_timestamp >= latest_input) {
                        connection = &(core->connection_pool[i]);
                        latest_input = core->connection_pool[i].latest_input_timestamp;
                    }
                }
            }
        }
    }
    return connection;
}

bool wish_core_is_connected_luid_ruid(wish_core_t* core, uint8_t *luid, uint8_t *ruid) {
    int i = 0;

    for (i = 0; i < WISH_CONTEXT_POOL_SZ; i++) {
        if (core->connection_pool[i].context_state == WISH_CONTEXT_FREE) {
            /* If the wish context is not in use, we can safely skip it */
            //WISHDEBUG(LOG_CRITICAL, "Skipping free wish context");
            continue;
        }

        if (memcmp(core->connection_pool[i].luid, luid, WISH_ID_LEN) == 0) {
            if (memcmp(core->connection_pool[i].ruid, ruid, WISH_ID_LEN) == 0) {
                bool retval = false;
                switch (core->connection_pool[i].context_state) {
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
void wish_core_feed(wish_core_t* core, wish_connection_t* connection, unsigned char* data, int len) {
    WISHDEBUG(LOG_INFO, "Got data, len %d ", len);
    int i = 0;
    for (i = 0; i < len; i++) {
        WISHDEBUG2(LOG_TRIVIAL, "0x%hhx ", data[i]);
    }

    uint16_t rb_space = ring_buffer_space(&(connection->rx_ringbuf));
    if (rb_space >= len) {
        /* Save the data in the rx circular buffer */
        ring_buffer_write(&(connection->rx_ringbuf), data, len);
        /* Update timestamp to indicate some data was received */
        connection->latest_input_timestamp = wish_time_get_relative(core);
    } else {
        /* There is no space for the data... */
        WISHDEBUG(LOG_CRITICAL, "No space in ring buffer, for message of len = %d. The ringbuffer currently has %hu free bytes. Not going any further", len, rb_space);
        wish_close_connection(core, connection);
    }
}

/* Check if the connection attempt by a remote client presenting these
 * wish id's can be accepted or not */
bool wish_core_check_wsid(wish_core_t* core, wish_connection_t* ctx, uint8_t* dst_id, uint8_t* src_id) {
    /* Whitelist/ACL processing? */

    /* Load the source id from our DB.  */
    wish_identity_t tmp_id;
    
    if ( wish_identity_load(src_id, &tmp_id) != RET_SUCCESS ) {
        WISHDEBUG(LOG_CRITICAL, "We don't know to guy trying to connect to us.");
        wish_identity_destroy(&tmp_id);
        return false;
    }

    wish_identity_destroy(&tmp_id);
    
    if ( wish_identity_load(dst_id, &tmp_id) != RET_SUCCESS ) {
        WISHDEBUG(LOG_CRITICAL, "We know who is trying to connect to us, but not the one he wants to connect to. (Did we delete an identity?)");
        wish_identity_destroy(&tmp_id);
        return false;
    }

    wish_identity_destroy(&tmp_id);

    /* Technically, we need to have the privkey for "dst_id", else we
     * cannot be communicating */
    if (!wish_has_privkey(dst_id)) {
        WISHDEBUG(LOG_CRITICAL, "We know both parties of the connection but we don't have the private key to open the connection.");
        return false;
    }

    return true;
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
void wish_core_process_data(wish_core_t* core, wish_connection_t* connection) {
again:
    ;
    /* This variable is used when the wish protocol state is 
     * PROTO_STATE_WISH_RUNNING: when the wish
     * connection is up and running, we need to ensure that also the AES
     * GCM auth tag is received, before we start processing the payload!
     * The auth_tag's length is not accounted for in the frame length
     * field of the wire protocol (variable connection->expect), 
     * and therefore we need to account for it explicitly. 
     * THis will be fixed with Wish protocol level 1.
     * */
    int expect_payload_len = 0;

    /* Consume data from the ring buffer */
    switch (connection->curr_transport_state) {
        case TRANSPORT_STATE_WAIT_FRAME_LEN:
            /* In this case we always expect a 2-byte long frame
             * length */
            if (ring_buffer_length(&(connection->rx_ringbuf)) >= 2) {
                /* Read out the expected byte count */
                /* Note: Byte count is expressend in Big Endian format */
                uint8_t bytes[2] = { 0 };
                ring_buffer_read(&(connection->rx_ringbuf), bytes, 2);
                connection->expect_bytes = (bytes[0] << 8) | bytes[1];
                WISHDEBUG(LOG_INFO, "Now expecting %d bytes of payload", connection->expect_bytes);
                connection->curr_transport_state = TRANSPORT_STATE_WAIT_PAYLOAD;
                if (ring_buffer_length(&(connection->rx_ringbuf)) >= connection->expect_bytes) {
                    /* There is more data to be read, so signal that
                     * function can continue */
                    goto again;
                }
            }
            break;
        case TRANSPORT_STATE_WAIT_PAYLOAD:
            expect_payload_len = connection->expect_bytes;
            if (ring_buffer_length(&(connection->rx_ringbuf)) >= expect_payload_len) {
                uint8_t* buf = (uint8_t*) wish_platform_malloc(connection->expect_bytes);
                if (buf != NULL) {
                    ring_buffer_read(&(connection->rx_ringbuf), buf, connection->expect_bytes);
                    wish_core_handle_payload(core, connection, buf, connection->expect_bytes);
                    wish_platform_free(buf);
                    connection->curr_transport_state = TRANSPORT_STATE_WAIT_FRAME_LEN;
                    if (ring_buffer_length(&(connection->rx_ringbuf)) >= 2) {
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
                if (ring_buffer_length(&(connection->rx_ringbuf)) 
                        >= WISH_CLIENT_HELLO_LEN) {
                    /* Step 1. Read in the expected bytes from ring buffer */
                    uint8_t buf[WISH_CLIENT_HELLO_LEN] = { 0 };
                    ring_buffer_read(&(connection->rx_ringbuf), buf, WISH_CLIENT_HELLO_LEN);
                    
                    /* 2. decide if we have a Wish connection incoming */
                    if (buf[0] == 'W' && buf[1] == '.') {
                        WISHDEBUG(LOG_DEBUG, "Attempted wish connection, protocol level 0x%hhx", buf[2]);

                        /* The high nibble defines the Wish version to
                         * be used */
                        uint8_t wire_version = (buf[2] & 0xf0) >> 4;
                        if (wire_version != WISH_WIRE_VERSION) {
                            /* Client wants unsupported protocol or version */
                            WISHDEBUG(LOG_CRITICAL, "Bad version attempted");
                            wish_close_connection(core, connection);
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
                                //WISHDEBUG(LOG_CRITICAL, "Friend req");           
                                connection->friend_req_connection = true;
                            } else {
                                WISHDEBUG(LOG_CRITICAL, "Unknown connection type");
                                wish_close_connection(core, connection);
                                break;
                            }
                        }


                    }
                    else {
                        /* Error */
                        WISHDEBUG(LOG_CRITICAL, "Bad connection attempt");
                        wish_close_connection(core, connection);
                        break;
                    }
                    /* 3. Decide if we want to continue, depending on
                     * the public key hashes the client submitted */
                    uint8_t* dst_id = &(buf[3]);
                    uint8_t* src_id = &(buf[3+WISH_ID_LEN]);

                    if (connection->friend_req_connection == false) {
                        /* For a normal connection, check that we are talking with a known friend */
                        if (wish_core_check_wsid(core, connection, dst_id, src_id) == false) {
                            WISHDEBUG(LOG_CRITICAL, "Bad UIDs in handshake, closing connection");
                            wish_close_connection(core, connection);
                            break;
                        } else {
                            wish_debug_print_array(LOG_DEBUG, "UIDs are known", src_id, WISH_ID_LEN);
                            wish_debug_print_array(LOG_DEBUG, "remote: ", dst_id, WISH_ID_LEN);
                        }
                    }
                    else {
                        /* Friend request connection */
                        //WISHDEBUG(LOG_CRITICAL, "Skipping UID check in handshake, because friend request connection");
                    }

                    memcpy(connection->luid, dst_id, WISH_ID_LEN);
                    memcpy(connection->ruid, src_id, WISH_ID_LEN);

                    /* 4. Initiate DHE key exchange */
                    connection->server_dhm_ctx = (mbedtls_dhm_context*)
                        wish_platform_malloc(sizeof(mbedtls_dhm_context));
                    if (connection->server_dhm_ctx == 0) {
                        WISHDEBUG(LOG_CRITICAL, "Failed allocation near line %d", __LINE__);
                        wish_close_connection(core, connection);
                        break;
                    }
                    mbedtls_dhm_context* server_dhm_ctx = connection->server_dhm_ctx;
                    mbedtls_dhm_init(server_dhm_ctx);
                    /* Wish TCP transport is specified to use the
                     * modp15 group, which is defined in RFC3526 section 4, 
                     * and is the 3072 bit group. */
                    int ret 
                        = mbedtls_mpi_read_string(&(server_dhm_ctx->P), 16, 
                            MBEDTLS_DHM_RFC3526_MODP_3072_P);
                    if (ret) {
                        WISHDEBUG(LOG_CRITICAL, "Error setting up DHM P, closing connection");
                        wish_close_connection(core, connection);
                        break;
                    }
                    ret = mbedtls_mpi_read_string(&(server_dhm_ctx->G), 16, 
                            MBEDTLS_DHM_RFC3526_MODP_3072_G);
                    if (ret) {
                        WISHDEBUG(LOG_CRITICAL, "Error setting up DHM G, closing connection");
                        wish_close_connection(core, connection);
                        break;
                    }

                    server_dhm_ctx->len = mbedtls_mpi_size( &(server_dhm_ctx->P) );

                    uint8_t output[384];
                    size_t wr_len = 384;
                    ret = mbedtls_dhm_make_public(server_dhm_ctx, 2,
                        output, wr_len, wish_platform_fill_random, NULL);
                    if (ret) {
                        WISHDEBUG(LOG_CRITICAL, "Error writing DHM own public %hhx", ret);
                        wish_close_connection(core, connection);
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
                    connection->send(connection->send_arg, out_buffer, 2+384);

                    connection->curr_transport_state = TRANSPORT_STATE_WAIT_FRAME_LEN;
                    connection->curr_protocol_state = PROTO_SERVER_STATE_DH;
                    WISHDEBUG(LOG_DEBUG, "movint to TRANSPORT_STATE_WAIT_FRAME_LEN");
                }
            }
            break;
        case TRANSPORT_STATE_RELAY_CLIENT_SEND_SESSION_ID:
            //WISHDEBUG(LOG_CRITICAL, "Sending relay session id");
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
                memcpy(msg + 3, connection->relay->session_id, RELAY_SESSION_ID_LEN);

                connection->send(connection->send_arg, msg, msg_len);
                connection->curr_transport_state = TRANSPORT_STATE_SERVER_WAIT_INITIAL;
            }

            break;
        case TRANSPORT_STATE_INITIAL:
        /* impossible */
        default:
            WISHDEBUG(LOG_CRITICAL, "Impossible transport state reached");
        break;
    }

}

/* Register a function which will be used by wish core when data is
 * to be sent.
 *
 * The send function is called with the argument given as arg */
void wish_core_register_send(wish_core_t* core, wish_connection_t* connection, int (*send)(void *, unsigned char*, int), void* arg) {
    connection->send = send;
    connection->send_arg = arg;
}

void wish_core_signal_tcp_event(wish_core_t* core, wish_connection_t* connection,  enum tcp_event ev) {
    WISHDEBUG(LOG_DEBUG, "TCP Event for connection id %d", connection->connection_id);
    switch (ev) {
    case TCP_CONNECTED: {
        WISHDEBUG(LOG_DEBUG, "Event TCP_CONNECTED");

        connection->outgoing = true;
        
        /* Start the whole show by sending the handshake bytes */
        const int buffer_len = 2+1+WISH_ID_LEN+WISH_ID_LEN;
        unsigned char buffer[buffer_len];
        buffer[0] = 'W';
        buffer[1] = '.';
        if (connection->friend_req_connection == false) {
            buffer[2] = (WISH_WIRE_VERSION << 4) | (WISH_WIRE_TYPE_NORMAL); 
        }
        else {
            buffer[2] = (WISH_WIRE_VERSION << 4) | WISH_WIRE_TYPE_FRIEND_REQ;
        }
        /* Now copy the destination id */
        memcpy(buffer+3, connection->ruid, WISH_ID_LEN);
        /* then copy the source id */
        memcpy(buffer+3+WISH_ID_LEN, connection->luid, WISH_ID_LEN);
        connection->curr_transport_state = TRANSPORT_STATE_WAIT_FRAME_LEN;
        connection->curr_protocol_state = PROTO_STATE_DH;

        /* Maestro, take it away please */
        connection->send(connection->send_arg, buffer, buffer_len);
        break;
    }
    case TCP_CLIENT_DISCONNECTED:
        WISHDEBUG(LOG_DEBUG, "Event TCP_CLIENT_DISCONNECTED");
        /* FALLTHROUGH */
    case TCP_DISCONNECTED:
        WISHDEBUG(LOG_DEBUG, "Event TCP_DISCONNECTED");

        /* Send offline signal to local services, but only if
         * there are no other connections active to the same luid, ruid,
         * rhid combination. */
        {
            wish_connection_t *conn = connection;
            
            int i = 0;
            bool other_connection_found = false;

            for (i = 0; i < WISH_CONTEXT_POOL_SZ; i++) {
                wish_connection_t *other_conn = &(core->connection_pool[i]);
                if (conn == other_conn) {
                    /* Don't examine our current wish context, the one
                     * that was just disconnected  */
                    continue;
                }
                else {
                    /* FIXME can this be refactored to use the
                     * "lookup-by-luid-ruid-rhid" function instead? */
                    if (memcmp(other_conn->luid, conn->luid,
                            WISH_ID_LEN) == 0) {
                        if (memcmp(other_conn->ruid,
                                conn->ruid, WISH_ID_LEN) == 0) {
                            if (other_conn->context_state ==
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

            if (!other_connection_found) {
                wish_send_online_offline_signal_to_apps(core, connection, false);
            }
        }
        
        if (connection->friend_req_connection) {
            if (connection->friend_req_meta) {
                wish_platform_free(connection->friend_req_meta);
            }
        }
        
        /* Delete any outstanding RPC request contexts */
        wish_cleanup_core_rpc_server(core, connection);

        /* If the connection were to be closed when its protocol state is
         * PROTO_SERVER_STATE_DH, then we must free the server_dhm_context
         * here. Normally it is done when handling input from peer,
         * in wish_core_handle_payload() */
        if (connection->curr_protocol_state == PROTO_SERVER_STATE_DH) {
            mbedtls_dhm_free(connection->server_dhm_ctx);
            wish_platform_free(connection->server_dhm_ctx);
        }

        /* Do some housework to ensure the stack is left in consistent
         * state */
        
        /* Free the list of remote services associated with this
         * connection. Note usage of LL_FOREACH_SAFE because we delete
         * the element */
        struct wish_remote_service *service;
        struct wish_remote_service *tmp;
        LL_FOREACH_SAFE(connection->apps, service, tmp) {
            LL_DELETE(connection->apps, service);
            wish_platform_free(service);
        }

        /* Empty the ring buffer */
        ring_buffer_skip(&(connection->rx_ringbuf), 
            ring_buffer_length(&(connection->rx_ringbuf)));
        

        /* Just set everything to zero - a reliable way to reset it */
        memset(connection, 0, sizeof(wish_connection_t));

        connection->curr_protocol_state = PROTO_STATE_INITIAL;
        connection->curr_transport_state = TRANSPORT_STATE_WAIT_FRAME_LEN;

        connection->context_state = WISH_CONTEXT_FREE;

        connection->close_timestamp = 0;
        connection->send_arg = NULL;
        
        wish_core_signals_emit_string(core, "connections");
        
        break;
    case TCP_CLIENT_CONNECTED:
        WISHDEBUG(LOG_DEBUG, "Event TCP_CLIENT_CONNECTED");
        connection->outgoing = false;
        connection->curr_transport_state = TRANSPORT_STATE_SERVER_WAIT_INITIAL;
        break;
    case TCP_RELAY_SESSION_CONNECTED:
        /* If this event happens, it means that the we (as a relay
         * client) have managed to open a session to the relay server
         * for the purpose of accepting an incoming connection that is waiting 
         * at the relay server */
        WISHDEBUG(LOG_DEBUG, "Event TCP_RELAY_SESSION_CONNECTED");
        connection->curr_transport_state
                    = TRANSPORT_STATE_RELAY_CLIENT_SEND_SESSION_ID;
        wish_core_process_data(core, connection);

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
static void build_client_and_server_hashes(wish_connection_t *connection, 
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
    mbedtls_sha256_finish(&sha256_ctx, connection->client_hash);
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
    mbedtls_sha256_finish(&sha256_ctx, connection->server_hash);
    mbedtls_sha256_free(&sha256_ctx);

}


void wish_core_handle_payload(wish_core_t* core, wish_connection_t* connection, uint8_t* payload, int len) {
    switch (connection->curr_protocol_state) {
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
                wish_close_connection(core, connection);
                break;
            }
            ret = mbedtls_mpi_read_string(&dhm_ctx.G, 16, MBEDTLS_DHM_RFC3526_MODP_3072_G);
            if (ret) {
                WISHDEBUG(LOG_CRITICAL, "Error setting up DHM G");
                wish_close_connection(core, connection);
                break;
            }

            dhm_ctx.len = mbedtls_mpi_size( &dhm_ctx.P );
            WISHDEBUG(LOG_TRIVIAL, "ctx len %d ", dhm_ctx.len);
            /* Read peer's public value */
            ret = mbedtls_dhm_read_public(&dhm_ctx, payload, len);
            if (ret) {
                WISHDEBUG(LOG_CRITICAL, "Error reading DHM peer public ");
                wish_close_connection(core, connection);
                break;
            }

            const size_t dhm_public_len = 384;
            uint8_t dhm_public[dhm_public_len];
            
            ret = mbedtls_dhm_make_public(&dhm_ctx, 2,
                dhm_public, dhm_public_len, wish_platform_fill_random, NULL);
            if (ret) {
                WISHDEBUG(LOG_CRITICAL, "Error writing DHM own public %hhx", ret);
                wish_close_connection(core, connection);
                break;
            }
            /* Send our public value to the peer */
            char frame_len_data[2] = { 0 };
            memcpy(frame_len_data, &dhm_public_len, 2);
            /* byte order conversion here is not portable */
            uint8_t tmp = frame_len_data[0];
            frame_len_data[0] = frame_len_data[1];
            frame_len_data[1] = tmp;
            WISHDEBUG(LOG_TRIVIAL, "0: %hhx", frame_len_data[0]);
            WISHDEBUG(LOG_TRIVIAL, "1: %hhx", frame_len_data[1]);
            unsigned char out_buffer[2+384];
            memcpy(out_buffer, frame_len_data, 2);
            memcpy(out_buffer+2, dhm_public, 384);
            /* Send the frame length and the key in one go */
            connection->send(connection->send_arg, out_buffer, 2+384);

            /* Calculate shared secret */
            ret = mbedtls_dhm_calc_secret(&dhm_ctx, 
                dhm_public, 384, (size_t *)&dhm_public_len, NULL, NULL);
            if (ret) {
                WISHDEBUG(LOG_CRITICAL, "Error deriving shared secret %x", ret);
                wish_close_connection(core, connection);
                break;
            }
            else {
                /* Shared secret was calculated */
                WISHDEBUG(LOG_TRIVIAL, "shared secret, len %d: ", dhm_public_len);
                int i = 0;
                for (i = 0; i < dhm_public_len; i++) {
                    WISHDEBUG2(LOG_INFO, "0x%x ", dhm_public[i]);
                }
            }
            mbedtls_dhm_free(&dhm_ctx);

            /* Copy AES key and IV vectors for in the outgoing (they are
             * the same at first, but then their nonce parts are
             * separately incremented at every transmission and receive*/
            memcpy(connection->aes_gcm_key_in, dhm_public+32, 16);
            memcpy(connection->aes_gcm_key_out, dhm_public, 16);
            memcpy(connection->aes_gcm_iv_in, dhm_public+32+16, 12);
            memcpy(connection->aes_gcm_iv_out, dhm_public+16, 12);

            int i = 0;
            /* Print out key */
            WISHDEBUG(LOG_INFO, "IN key: ");
            for (i = 0; i < 16; i++) {
                WISHDEBUG2(LOG_INFO, "0x%x ", connection->aes_gcm_key_in[i]);
            }

            /* Build the client and server hashes now, because we have
             * the secret at hand. The hashes are stored
             * in the wish context struct */
            build_client_and_server_hashes(connection, dhm_public);

            connection->curr_protocol_state = PROTO_STATE_ID_VERIFY_SEND_CLIENT_HASH;
        }

        break;
    case PROTO_STATE_ID_VERIFY_SEND_CLIENT_HASH:
        /* We have agreed upon a shared key, now lets use it to perform
         * a identity verification by sending the client hash */
        {
            uint8_t signature[ED25519_SIGNATURE_LEN];
            uint8_t local_privkey[WISH_PRIVKEY_LEN];
            if (wish_load_privkey(connection->luid, local_privkey)) {
                WISHDEBUG(LOG_CRITICAL, "Could not load privkey");
                wish_close_connection(core, connection);
                break;
            }
            else {
                ed25519_sign(signature, connection->client_hash, SHA256_HASH_LEN,
                    local_privkey);
            }

            wish_debug_print_array(LOG_DEBUG, "Signature:", signature, ED25519_SIGNATURE_LEN);
            wish_core_send_message(core, connection, signature, ED25519_SIGNATURE_LEN);

            /* Then, check that we can read a frame whose length
             * corresponds to the server hash */

            const int server_signature_len = ED25519_SIGNATURE_LEN;
            unsigned char server_signature[server_signature_len];
            /* Length of part of incoming payload containing cipher text */
            int ciphertxt_len = len-AES_GCM_AUTH_TAG_LEN;
            WISHDEBUG(LOG_DEBUG, "ciphertxt len is %d", ciphertxt_len);

            /* Pointer to the beginning of the auth_tag */
            uint8_t* auth_tag = payload + ciphertxt_len;

            if (wish_core_decrypt(core, connection, payload, ciphertxt_len, 
                    auth_tag, AES_GCM_AUTH_TAG_LEN, 
                        server_signature, server_signature_len)) {
                WISHDEBUG(LOG_CRITICAL, "Decryption fails in server hash check");
                wish_close_connection(core, connection);
                break;
            }
            
            if (connection->friend_req_connection == false ) {
                /* Normal connection */
                uint8_t remote_pubkey[WISH_PUBKEY_LEN] = { 0 };
                if (wish_load_pubkey(connection->ruid, remote_pubkey)) {
                    WISHDEBUG(LOG_CRITICAL, "Could not load remote pubkey");
                    wish_close_connection(core, connection);
                    break;
                }

                if (ed25519_verify(server_signature, connection->server_hash,
                        SHA256_HASH_LEN, remote_pubkey) == 0) {
                    WISHDEBUG(LOG_CRITICAL, "Server hash signature check fail");
                    wish_close_connection(core, connection);
                    break;
                }
                else {
                    WISHDEBUG(LOG_DEBUG, "Server hash signature check OK");
                }

                connection->curr_protocol_state = PROTO_STATE_WISH_HANDSHAKE;
            } else {
                /* Friend request connection */
                //WISHDEBUG(LOG_CRITICAL, "Outgoing friend req: Skipping server signature check");
                connection->curr_protocol_state = PROTO_STATE_WISH_HANDSHAKE;
            }
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

            if (wish_core_decrypt(core, connection, payload, ciphertxt_len, auth_tag,
                AES_GCM_AUTH_TAG_LEN, plaintxt, plaintxt_len)) {

                WISHDEBUG(LOG_CRITICAL, "Decrypt fails in Wish handshake");
                wish_close_connection(core, connection);
                break;

            }

            /* Submit the decrypted message upwards in the stack */
            wish_debug_print_array(LOG_TRIVIAL, "Performing local handshake steps", plaintxt, len-AES_GCM_AUTH_TAG_LEN);
            wish_core_process_handshake(core, connection, plaintxt);
            connection->curr_protocol_state = PROTO_STATE_WISH_RUNNING;

            if (connection->friend_req_connection) {
                //WISHDEBUG(LOG_CRITICAL, "Sending friend request RPC");
                /* FIXME: this should just call a "connection established" handler instead, which would in turn call the RPC client for sending the friend req */
                wish_core_send_friend_req(core, connection);
                connection->context_state = WISH_CONTEXT_CONNECTED;
            }
            else {
                /* if we discover that we are banned, don't announce the connection, but instead just close it. */
                bson_iterator it;
                if (bson_find_from_buffer(&it, plaintxt, "banned") == BSON_BOOL) {
                    if (bson_iterator_bool(&it)) {
                        WISHDEBUG(LOG_CRITICAL, "Note: We are banned from the remote host (outgoing connection)");
                        wish_identity_add_meta_connect(core, connection->ruid, false);
                        wish_close_connection(core, connection);
                        break;
                    }
                }
                
                struct wish_event evt = { .event_type =
                    WISH_EVENT_NEW_CORE_CONNECTION, .context = connection };
                wish_message_processor_notify(&evt);
                
            }

       }
        break;
    case PROTO_STATE_WISH_RUNNING:
        {
            WISHDEBUG(LOG_WIRE, "processing message of length %d", len);

            /* Length of part of incoming payload containing cipher text */
            int ciphertxt_len = len - AES_GCM_AUTH_TAG_LEN;
            int plaintxt_len = ciphertxt_len;
            /* Pointer to the beginning of the auth_tag */
            uint8_t* auth_tag = payload + ciphertxt_len;

            wish_debug_print_array(LOG_TRIVIAL, "Auth tag", auth_tag, AES_GCM_AUTH_TAG_LEN);

            uint8_t* plaintxt = (uint8_t*) wish_platform_malloc(plaintxt_len);
            if (plaintxt == NULL) {
                WISHDEBUG(LOG_CRITICAL, "Could not allocate memory");
                wish_close_connection(core, connection);
                break;
            }

            int ret = wish_core_decrypt(core, connection, payload, ciphertxt_len, 
                auth_tag, AES_GCM_AUTH_TAG_LEN, plaintxt, plaintxt_len);

            if (ret) {
                WISHDEBUG(LOG_CRITICAL, 
                    "There was an error while decrypting Wish message");
                wish_platform_free(plaintxt);
                wish_close_connection(core, connection);
                break;
            }
            wish_debug_print_array(LOG_TRIVIAL, "Plaintext", plaintxt, len);
            wish_core_process_message(core, connection, plaintxt);
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

            mbedtls_dhm_context* server_dhm_ctx = connection->server_dhm_ctx;
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
                wish_close_connection(core, connection);
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
            memcpy(connection->aes_gcm_key_out, output+32, 16);
            memcpy(connection->aes_gcm_key_in, output, 16);
            memcpy(connection->aes_gcm_iv_out, output+32+16, 12);
            memcpy(connection->aes_gcm_iv_in, output+16, 12);

            wish_platform_free(server_dhm_ctx);

            /* Save the client and server hashes, because we have the
             * secret at hand */
            build_client_and_server_hashes(connection, output);

            /* We can now communicate securely, proceed to identity check.
             * First, send the server hash signature to client */
            uint8_t signature[ED25519_SIGNATURE_LEN];
            uint8_t local_privkey[WISH_PRIVKEY_LEN];
            if (wish_load_privkey(connection->luid, local_privkey)) {
                WISHDEBUG(LOG_CRITICAL, "Could not load privkey");
                wish_close_connection(core, connection);
                break;
            }
            ed25519_sign(signature, connection->server_hash, SHA256_HASH_LEN,
                local_privkey);

            wish_core_send_message(core, connection, signature, ED25519_SIGNATURE_LEN);

            connection->curr_protocol_state 
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

            if (wish_core_decrypt(core, connection, payload, ciphertxt_len, 
                    auth_tag, AES_GCM_AUTH_TAG_LEN, 
                        client_signature, client_signature_len)) {
                WISHDEBUG(LOG_CRITICAL, "Decryption fails in client hash check");
                wish_close_connection(core, connection);
                break;
            }
            
            if (connection->friend_req_connection == false) {
                /* Incoming normal connection */
                uint8_t remote_pubkey[WISH_PUBKEY_LEN] = { 0 };
                if (wish_load_pubkey(connection->ruid, remote_pubkey)) {
                    WISHDEBUG(LOG_CRITICAL, "Could not load remote pubkey");
                    wish_close_connection(core, connection);
                    break;
                }

                if (ed25519_verify(client_signature, connection->client_hash,
                        SHA256_HASH_LEN, remote_pubkey) == 0) {
                    WISHDEBUG(LOG_CRITICAL, "Client hash signature check fail");
                    wish_close_connection(core, connection);
                    break;
                }
                else {
                    WISHDEBUG(LOG_DEBUG, "Client hash signature check OK");

                }

                /* Identities have now been successfully verified */
                connection->curr_protocol_state 
                    = PROTO_SERVER_STATE_WISH_SEND_HANDSHAKE;
            } else {
                /* Incoming friend request connection */
                //WISHDEBUG(LOG_CRITICAL, "Incoming friend req connection, skipping client hash check");
                connection->curr_protocol_state = PROTO_SERVER_STATE_WISH_SEND_HANDSHAKE;
            }
        }
        /* WARNING: FALLTHROUGH */
    case PROTO_SERVER_STATE_WISH_SEND_HANDSHAKE:
        {
             /* Send Wish handshake */
            WISHDEBUG(LOG_DEBUG, "Sending handshake");
            const int max_handshake_len = 500;
            uint8_t handshake_msg[max_handshake_len];

            wish_core_create_handshake_msg(core, connection, handshake_msg, max_handshake_len);

            bson bs;
            bson_init_with_data(&bs, handshake_msg);
            
            WISHDEBUG(LOG_DEBUG, "We have generated BSON message of len %d", bson_size(&bs));

            if (wish_core_send_message(core, connection, handshake_msg, bson_size(&bs))) {
                /* Send error. Skip sending this time */
                WISHDEBUG(LOG_CRITICAL, "Send fails in server state wish send handshake");
                break;
            }
            /* Sending OK */
            connection->curr_protocol_state 
                = PROTO_SERVER_STATE_WISH_HANDSHAKE_READ_REPLY;
        }
        break;
    case PROTO_SERVER_STATE_WISH_HANDSHAKE_READ_REPLY:
        WISHDEBUG(LOG_DEBUG, "In server handshake read reply phase");
        {
            uint8_t* plaintxt = (uint8_t*) wish_platform_malloc(len);
            if (plaintxt == NULL) {
                WISHDEBUG(LOG_CRITICAL, "Out of memory in server handshake read reply phase");
                wish_close_connection(core, connection);
                break;
            }
            int ciphertxt_len = len-AES_GCM_AUTH_TAG_LEN;
             /* Pointer to the beginning of the auth_tag */
            uint8_t* auth_tag = payload + ciphertxt_len;


            int ret = wish_core_decrypt(core, connection, payload, ciphertxt_len, 
                auth_tag, AES_GCM_AUTH_TAG_LEN, plaintxt, len);

            if (ret) {
                WISHDEBUG(LOG_CRITICAL, "There was an error while decrypting Wish message");
                wish_platform_free(plaintxt);
                wish_close_connection(core, connection);
                break;
            }

            wish_debug_print_array(LOG_TRIVIAL, "Got handshake reply OK", plaintxt, len);

            bson_iterator it;
            
            /* Recover the Host id of the client */
            if (bson_find_from_buffer(&it, plaintxt, "host") != BSON_BINDATA) {
                WISHDEBUG(LOG_CRITICAL, "We could not get the host field from client handshake");
                bson_visit("We could not get the host field from client handshake", plaintxt);
                wish_platform_free(plaintxt);
                return;
            }
            
            if (bson_iterator_bin_len(&it) != WISH_WHID_LEN) {
                WISHDEBUG(LOG_CRITICAL, "We could not get the host field from client handshake, invalid len");
                bson_visit("We could not get the host field from client handshake, invalid len", plaintxt);
                wish_platform_free(plaintxt);
                return;
            }

            const uint8_t* host_id = bson_iterator_bin_data(&it);
            int32_t host_id_len = bson_iterator_bin_len(&it);

            if (host_id_len == WISH_WHID_LEN) {
                memcpy(connection->rhid, host_id, WISH_WHID_LEN);
            } else {
                WISHDEBUG(LOG_CRITICAL, "Bad hostid length in client handshake");
                wish_platform_free(plaintxt);
                return;
            }
            
            /* Update transports if we have a normal connection */
            if (connection->friend_req_connection == false) {
                wish_identity_t id;
                if ( wish_identity_load(connection->ruid, &id) == RET_SUCCESS ) {
                    bool found_transports = false;
                    /* Clear existing transports, and replace them with transports provided by remote party */
                    /* FIXME append to transport list - instead of overwriting - the old transports should be deprecated later when we discover that they are no longer valid */
                    memset(id.transports, 0, WISH_MAX_TRANSPORTS*WISH_MAX_TRANSPORT_LEN);
                    for (int i = 0; i < WISH_MAX_TRANSPORTS; i++) {
                        const size_t path_max_len = 16;
                        char path[path_max_len];
                        wish_platform_snprintf(path, path_max_len, "transports.%d", i);
                        bson_iterator_from_buffer(&it, plaintxt);
                        if (bson_find_fieldpath_value(path, &it) == BSON_STRING) {
                            strncpy(&id.transports[i][0], bson_iterator_string(&it), WISH_MAX_TRANSPORT_LEN);
                            found_transports = true;
                        }
                    }

                    if (!found_transports) {
                        WISHDEBUG(LOG_CRITICAL, "No transports were reported by remote!");
                    }
                    else {
                        /* Save the remote identity updated with transports */
                        wish_identity_update(core, &id);
                    }
                }
                else {
                    WISHDEBUG(LOG_CRITICAL, "Error loading identity when about to update transports!");
                }
                wish_identity_destroy(&id);
            }
            
            if (bson_find_from_buffer(&it, plaintxt, "banned") == BSON_BOOL) {
                WISHDEBUG(LOG_CRITICAL, "Note: We are banned from the remote host (incoming connection)");
                /* update the contact meta with { connect: false } and close the connection. 
                 * Note that this should not normally happen, because the remote host that has us banned should not contact us in the first place! */
                wish_identity_add_meta_connect(core, connection->ruid, false);        
                wish_close_connection(core, connection);
            }
            else {
                connection->curr_protocol_state = PROTO_STATE_WISH_RUNNING;
                if (connection->friend_req_connection == false) {
                    struct wish_event evt = { 
                        .event_type = WISH_EVENT_NEW_CORE_CONNECTION,
                        .context = connection };
                    wish_message_processor_notify(&evt);
                    /* Remove "connect: false" from meta if it exists, we have now been again contacted by the remote! */
                    wish_identity_remove_meta_connect(core, connection->ruid); 
                }
            }
            /* Finished processing the handshake */
            wish_platform_free(plaintxt);         
        }
        break;
    case PROTO_STATE_INITIAL:
        WISHDEBUG(LOG_CRITICAL, "PROTO_STATE_INITIAL: id %d", connection->connection_id);
    default:
        WISHDEBUG(LOG_CRITICAL, "illegal protocol state reached, connection id %d", connection->connection_id);
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
int wish_core_send_message(wish_core_t* core, wish_connection_t* connection, const uint8_t* payload_clrtxt, int payload_len) {
    mbedtls_gcm_context aes_gcm_ctx;
    mbedtls_gcm_init(&aes_gcm_ctx);
    WISHDEBUG(LOG_DEBUG, "send payload len %d", payload_len);
    int ret = mbedtls_gcm_setkey(&aes_gcm_ctx, MBEDTLS_CIPHER_ID_AES, 
                connection->aes_gcm_key_out, AES_GCM_KEY_LEN*8);
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
        connection->aes_gcm_iv_out, AES_GCM_IV_LEN, NULL, 0,
        payload_clrtxt, frame+2,
        AES_GCM_AUTH_TAG_LEN, frame+2+payload_len);
    mbedtls_gcm_free(&aes_gcm_ctx);
    if (ret) {
        WISHDEBUG(LOG_CRITICAL, "Encryption fail");

        return 1;
    }

    /* Sinxa LE->BE */
    uint16_t frame_len_be = uint16_native2be(payload_len+AES_GCM_AUTH_TAG_LEN);
    memcpy(frame, &frame_len_be, 2);
    /* Send the frame length and the key in one go */
    WISHDEBUG(LOG_DEBUG, "About to send %d", frame_len);
    ret = connection->send(connection->send_arg, frame, frame_len);
    if (ret == 0) {
        /* Sending not failed */
        WISHDEBUG(LOG_DEBUG, "Sent %d", frame_len);
        update_nonce(connection->aes_gcm_iv_out+4);
    }
    else {
        WISHDEBUG(LOG_CRITICAL, "Porting layer send function reported failure");
    }
    wish_platform_free(frame);
    WISHDEBUG(LOG_DEBUG, "Exiting");
    return ret;
}


int wish_core_decrypt(wish_core_t* core, wish_connection_t* ctx, uint8_t* ciphertxt, size_t 
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
wish_connection_t* wish_identify_context(wish_core_t* core, uint8_t rmt_ip[4], 
    uint16_t rmt_port, uint8_t local_ip[4], uint16_t local_port) {

    bool found = false;

    int i = 0; 
    for (i = 0; i < WISH_CONTEXT_POOL_SZ; i++) {
        if (core->connection_pool[i].local_port != local_port) {
            continue;
        }
        if (core->connection_pool[i].remote_port != rmt_port) {
            continue;
        }
        int j = 0;
        for (j = 0; j < 4; j++) {
            if (core->connection_pool[i].remote_ip_addr[j] != rmt_ip[j]) {
                continue;
            }
            if (core->connection_pool[i].local_ip_addr[j] != local_ip[j]) {
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
    return &(core->connection_pool[i]);
}

/* 
 * This function will perform misc initting of various parts of the
 * system, mainly initting of RPC servers in the core 
 */
void wish_core_init(wish_core_t* core) {
    wish_core_config_load(core);
    
    core->ldiscover_allowed = true;
    
    char id[32];
    
    wish_core_get_host_id(core, id);
    
    core->time_db = NULL;
    
    core->wish_server_port = core->wish_server_port == 0 ? 37009 : core->wish_server_port;
    
    wish_connections_init(core);

    core_service_ipc_init(core);
    
    wish_core_init_rpc(core);
    wish_core_app_rpc_init(core);

    core->core_rpc_client = wish_platform_malloc(sizeof(rpc_client));
    memset(core->core_rpc_client, 0, sizeof(rpc_client));
    core->core_rpc_client->next_id = 1;
    core->core_rpc_client->context = core;


    //struct wish_service_entry service_registry[WISH_MAX_SERVICES];

    int service_registry_size = sizeof(struct wish_service_entry) * WISH_MAX_SERVICES;

    core->service_registry = wish_platform_malloc(service_registry_size);
    memset(core->service_registry, 0, service_registry_size);
    
    wish_core_relay_client_init(core);
    
    wish_ldiscover_init(core);
    
    wish_acl_init(core);
}


int wish_core_get_rx_buffer_free(wish_core_t* core, wish_connection_t* connection) {
    return ring_buffer_space(&(connection->rx_ringbuf));
}


void wish_close_all_connections(wish_core_t* core) {
    int i = 0;
    for (i = 0; i < WISH_CONTEXT_POOL_SZ; i++) {
        switch (core->connection_pool[i].context_state) {
        case WISH_CONTEXT_FREE:
            continue;
            break;
        case WISH_CONTEXT_IN_MAKING:
            /* FALLTHROUGH */
        case WISH_CONTEXT_CONNECTED:
            wish_close_connection(core, &(core->connection_pool[i]));
            break;
        case WISH_CONTEXT_CLOSING:
            WISHDEBUG(LOG_CRITICAL, "Not closing connection which is already closing");
            break;
        }
    }
}