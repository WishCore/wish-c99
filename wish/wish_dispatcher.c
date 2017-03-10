#include <stdint.h>
#include <stdbool.h>
#include "mbedtls/gcm.h"
#include "wish_config.h"
#include "wish_io.h"
#include "wish_debug.h"
#include "cbson.h"
#include <string.h>
#include "wish_dispatcher.h"
#include "wish_platform.h"
#include "wish_event.h"
#include "wish_core_rpc_func.h"
#include "wish_identity.h"
#include "bson_visitor.h"
#include "wish_service_registry.h"
#include "wish_core_app_rpc_func.h"
#include "core_service_ipc.h"
#include "wish_fs.h"

#include "mbedtls/sha256.h"
#include "ed25519.h"

/* Embedded Wish */

void wish_core_send_pong(wish_core_t* core, wish_connection_t* ctx) {
    WISHDEBUG(LOG_DEBUG, "Ping, sending pong!");
    /* Enqueue a pong message as answer to ping */
    int32_t pong_msg_max_len = 50;
    uint8_t pong_msg[pong_msg_max_len];
    bson_init_doc(pong_msg, pong_msg_max_len);
    /* Send: { pong: true } */
    bson_write_boolean(pong_msg, pong_msg_max_len, 
        "pong", true);
    wish_core_send_message(core, ctx, pong_msg, bson_get_doc_len(pong_msg));

}


static return_t zeroes(void* src, int bytes) {
    int i;
    for (i=0; i< bytes; i++) {
        char* b = (char*) src;
        if (b[i] & 0xff) {
            return ret_fail;
        }
    }
    return ret_success;
}

size_t wish_core_get_host_id(wish_core_t* core, uint8_t *hostid_ptr) {
    if ( zeroes(core->id, WISH_WHID_LEN) == ret_success ) {
        WISHDEBUG(LOG_CRITICAL, "Creating new host id");
        /* Create new host id file */        
        char sys_id_input_str[WISH_WHID_LEN];
        wish_platform_fill_random(NULL, sys_id_input_str, WISH_WHID_LEN);
        wish_core_create_hostid(core, (char*)hostid_ptr, sys_id_input_str, WISH_WHID_LEN);

        memcpy(core->id, hostid_ptr, WISH_WHID_LEN);
        wish_core_config_save(core);
    }

    memcpy(hostid_ptr, core->id, WISH_WHID_LEN);
    
    return WISH_WHID_LEN;
}

/** Create a Wish host identity based on seed bytes. Host identity
 * generation is a deterministic process, yielding the same pubkey and
 * privkey for a given sys_id_str
 */
size_t wish_core_create_hostid(wish_core_t* core, char* hostid, char* sys_id_str, 
    size_t sys_id_str_len) {
    /* Just generate a hostid by first hashing the hosts's MAC address
     * (or other system-specific data) to form 32 seed bytes, 
     * which is used as seed to ed25519 create keypair - note
     * that under this scheme the hostid will always be the same for any 
     * given sys_id string. */
    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0); 
    mbedtls_sha256_update(&sha256_ctx, (const unsigned char *)sys_id_str, 
        sys_id_str_len); 
    uint8_t seed[WISH_ED25519_SEED_LEN];
    mbedtls_sha256_finish(&sha256_ctx, seed);
    mbedtls_sha256_free(&sha256_ctx);

    uint8_t host_pubkey[WISH_PUBKEY_LEN];
    uint8_t host_privkey[WISH_PRIVKEY_LEN];
    ed25519_create_keypair(host_pubkey, host_privkey, seed);
    memcpy(hostid, host_pubkey, WISH_WHID_LEN);
    return WISH_WHID_LEN;
}

void wish_core_create_handshake_msg(wish_core_t* core, uint8_t *buffer, size_t buffer_len) {
    uint8_t host_id[WISH_WHID_LEN] = { 0 };
    uint8_t *handshake_msg = buffer;
    size_t max_handshake_len = buffer_len;
    wish_core_get_host_id(core, host_id);
    bson_init_doc(handshake_msg, max_handshake_len);

    bson_write_binary(handshake_msg, max_handshake_len, "host", 
        host_id, WISH_WHID_LEN);
    /* FIXME Create a list of transports - but this is not currently in
     * use */
#if 0   /* if 0, creation of transports array is disabled */
    const int transports_array_max_len = 240;
    uint8_t transports_array[transports_array_max_len];
    bson_init_doc(transports_array, transports_array_max_len);
    char wish_url[200];
    wish_platform_sprintf(wish_url, "wish://%d.%d.%d.%d:%d", 0, 0, 0, 0,37008);
    bson_write_string(transports_array, transports_array_max_len,
        "0", wish_url);
    bson_write_embedded_doc_or_array(handshake_msg, max_handshake_len,
        "transports", transports_array, BSON_KEY_ARRAY);
#endif
}

/* Submit a BSON handshake message (extracted from the wire) to the Wish core.
 *
 * Note that if you wish (heh-heh) to retain any part of the bson_doc for later
 * processing, you MUST explicitly make a copy of the data, as the parameter
 * bson_doc is allocated from stack! */
void wish_core_process_handshake(wish_core_t* core, wish_connection_t* ctx, uint8_t* bson_doc) {
    uint32_t doc_len = bson_get_doc_len(bson_doc);
    WISHDEBUG(LOG_DEBUG, "In process handshake");
    WISHDEBUG(LOG_DEBUG, "We obtained BSON document with len=%d", doc_len);
    /* We are primarly interested about the host identity, not much else
     * */
    uint8_t* host_id = NULL;
    int32_t host_id_len = 0;
    if (bson_get_binary(bson_doc, "host", &host_id, &host_id_len)
                == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "We could not get the host field");
        return;
    }
    if (host_id_len == WISH_WHID_LEN) {
        memcpy(ctx->rhid, host_id, WISH_WHID_LEN);
    }
    else {
        WISHDEBUG(LOG_CRITICAL, "Bad hostid length");
        return;
    }

    /* Now create our own "wish handshake message" */
    const int max_handshake_len = 500;
    uint8_t handshake_msg[max_handshake_len];
    
    wish_core_create_handshake_msg(core, handshake_msg, max_handshake_len);
    WISHDEBUG(LOG_DEBUG, "We have generated BSON message of len %d", 
        bson_get_doc_len(handshake_msg));

    uint8_t* recovered_ptr;
    int32_t recovered_len;
    uint8_t recovered_type;
    bson_get_elem_by_name(handshake_msg, "host", &recovered_type, 
        &recovered_ptr, &recovered_len);
    if (recovered_len != WISH_WHID_LEN) {
        WISHDEBUG(LOG_CRITICAL, "Recover hostid of incorrect length");
    }

    wish_core_send_message(core, ctx, handshake_msg, bson_get_doc_len(handshake_msg));
 
}

/* Generate an id for service messages */
int32_t generate_service_msg_id(void) {
    /* The latest message "id" we have sent away is stored here */
    static int my_last_id = 0;

    return my_last_id++;
}


void wish_core_process_message(wish_core_t* core, wish_connection_t* ctx, uint8_t* bson_doc) {
    uint32_t doc_len = bson_get_doc_len(bson_doc);
    WISHDEBUG(LOG_DEBUG, "We obtained BSON document with len=%d\n\r", doc_len);

    /* If you want to print out the on-wire message, now would be the
     * time */
    bool wire_debug = false;
    if (wire_debug) {
        bson_visit("Incoming message", bson_doc);
    }

    /* Read the top-level and 'req'(uest), 'res'(ponse)
     * If 'req', then feed to an instance of wish-rpc server
     * if 'res', then feed to the corresponding instance of wish-client
     */

    uint8_t *core_lvl_pl = NULL;
    int32_t core_lvl_pl_len = 0;
    if (bson_get_document(bson_doc, "req", &core_lvl_pl,
            &core_lvl_pl_len) == BSON_SUCCESS) {
        /* Request. Feed to core RPC server */
        WISHDEBUG(LOG_DEBUG, "Core RPC req found!");
        wish_core_feed_to_rpc_server(core, ctx, core_lvl_pl, core_lvl_pl_len);

    }
    else if (bson_get_document(bson_doc, "res", &core_lvl_pl,
            &core_lvl_pl_len) == BSON_SUCCESS) {
        /* Response. Feed to core RPC client */
        WISHDEBUG(LOG_DEBUG, "Core RPC res found!");
        wish_core_feed_to_rpc_client(core, ctx, core_lvl_pl, core_lvl_pl_len);

    }
    else {
        bool ping_val = false;
        if (bson_get_boolean(bson_doc, "ping", &ping_val) 
                == BSON_SUCCESS) {
            wish_core_send_pong(core, ctx);
       }
        else if (bson_get_boolean(bson_doc, "pong", &ping_val) 
                == BSON_SUCCESS) {
            WISHDEBUG(LOG_DEBUG, "Got pong");
        }
        else {
            WISHDEBUG(LOG_CRITICAL, "Neither req or res found!");
        }
    }
}

/* Route an incoming message (from app) */
void wish_core_handle_app_to_core(wish_core_t* core, uint8_t src_wsid[WISH_ID_LEN], uint8_t *data, size_t len) {
    //WISHDEBUG(LOG_CRITICAL, "Incoming message from app to core len %d", len);
    //bson_visit("Incoming message from app to core", data);

    /* Determine if it is login or what */
    uint8_t *recovered_wsid = NULL;
    int32_t recovered_wsid_len = 0;
    
    /* If the incoming message is a 'ready' from the service, the state is saved here */
    bool app_ready = false;
    
    if (bson_get_binary(data, "wsid", &recovered_wsid, &recovered_wsid_len) == BSON_SUCCESS) {
        /* Most likely a login message */
        WISHDEBUG(LOG_DEBUG, "Service-to-core login detected");
        if (recovered_wsid_len != WISH_WSID_LEN) {
            WISHDEBUG(LOG_CRITICAL, "WSID format fail");
            return;
        }
        if (memcmp(src_wsid, recovered_wsid, WISH_WSID_LEN) != 0) {
            WISHDEBUG(LOG_CRITICAL, "WSID mismatch");
            return;
        }

        char *name = 0;
        int32_t name_len = 0;
        if (bson_get_string(data, "name", &name, &name_len) == BSON_FAIL) {
            WISHDEBUG(LOG_CRITICAL, "Cannot get service name");
            return;
        }
        uint8_t *protocols_array = 0;
        int32_t protocols_array_len = 0;
        if (bson_get_array(data, "protocols", &protocols_array,
                &protocols_array_len) == BSON_FAIL) {
            WISHDEBUG(LOG_CRITICAL, "No protocols get protocols array");
        }
        uint8_t *permissions_array = 0;
        int32_t permissions_array_len = 0;
        if (bson_get_array(data, "permissions", &permissions_array,
                &permissions_array_len) == BSON_FAIL) {
            WISHDEBUG(LOG_CRITICAL, "Cannot get permissions array");
            return;
        }

        wish_service_register_add(core, src_wsid, name, protocols_array, permissions_array);

        /* Send 'signal: "ready" to App */
        const size_t ready_signal_max_len = 100;
        uint8_t ready_signal[ready_signal_max_len];
        bson_init_doc(ready_signal, ready_signal_max_len);
        bson_write_string(ready_signal, ready_signal_max_len, "type", "signal");
        bson_write_string(ready_signal, ready_signal_max_len, "signal", "ready");
        send_core_to_app(core, src_wsid, ready_signal, bson_get_doc_len(ready_signal));
    }
    else if (bson_get_boolean(data, "ready", &app_ready) == BSON_SUCCESS) {
        /* Detected a 'ready' signal from the service. App sends 'ready: true' when it is ready to start accepting frames from other peers. */
        if (!app_ready) {
            WISHDEBUG(LOG_CRITICAL, "'ready: false' from service, what does that mean?!");
        }
        else {
            WISHDEBUG(LOG_DEBUG, "App ready");
            /* Send peer "online" updates to connected cores */
            struct wish_service_entry *service_entry = wish_service_get_entry(core, src_wsid);
            if (service_entry != NULL) {
                wish_send_peer_update(core, service_entry, true);
            }
            /* Send peer online to app, regarding existing services which reside on remote cores.
             * Iterate through the list of Wish connections, and 
             * send online signal for each service on each active core connection */
            int i = 0;
            wish_connection_t *wish_context_pool = wish_core_get_connection_pool(core);
            for (i = 0; i < WISH_CONTEXT_POOL_SZ; i++) {
                wish_connection_t *ctx = &(wish_context_pool[i]);
                if (ctx->context_state == WISH_CONTEXT_CONNECTED) {
                    wish_send_online_offline_signal_to_apps(core, ctx, true);
                }
            }    
            /* Send online messages regarding other local services on this core */
            
            struct wish_service_entry *service_registry = wish_service_get_registry(core);
            /* This is the service entry corresponding the the new service which became ready */
            struct wish_service_entry *service_entry_ready = wish_service_get_entry(core, src_wsid);
            
            if (service_entry_ready == NULL) {
                WISHDEBUG(LOG_CRITICAL, "Error getting service entry");
                return;
            }
         
            for (i = 0; i < WISH_MAX_SERVICES; i++) {
                if (wish_service_entry_is_valid(core, &(service_registry[i]))) {
                    /* FIXME support for multiple protocols */
                    if (strncmp(service_registry[i].protocols[0].name, service_entry_ready->protocols[0].name, WISH_PROTOCOL_NAME_MAX_LEN) != 0) {
                        /* Protocols do not match */
                        continue;
                    }
                    /* Inform the service which became ready with information about other services on the local core */
                    wish_send_peer_update_locals(core, src_wsid, &(service_registry[i]), true);
                    /* Inform the other services on this core about the new service which became ready */
                    wish_send_peer_update_locals(core, service_registry[i].wsid, service_entry_ready, true);
                }
            }
        }
    }
    else {
        /* The message is not a login message -
         * Determine where the message is going - to a local service, or
         * a remote service */
        wish_core_app_rpc_handle_req(core, src_wsid, data);
    }
}


