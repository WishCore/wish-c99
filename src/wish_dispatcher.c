/**
 * Copyright (C) 2018, ControlThings Oy Ab
 * Copyright (C) 2018, André Kaustell
 * Copyright (C) 2018, Jan Nyman
 * Copyright (C) 2018, Jepser Lökfors
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * @license Apache-2.0
 */
#include <stdint.h>
#include <stdbool.h>
#include "utlist.h"
#include "mbedtls/gcm.h"
#include "wish_config.h"
#include "wish_connection.h"
#include "wish_debug.h"
#include "bson.h"
#include <string.h>
#include "wish_dispatcher.h"
#include "wish_connection_mgr.h"
#include "wish_platform.h"
#include "wish_event.h"
#include "wish_core_rpc.h"
#include "wish_identity.h"
#include "bson_visit.h"
#include "wish_service_registry.h"
#include "wish_core_app_rpc.h"
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
    
    bson bs;
    bson_init_buffer(&bs, pong_msg, pong_msg_max_len);
    
    /* Send: { pong: true } */
    bson_append_bool(&bs, "pong", true);
    bson_finish(&bs);
    
    wish_core_send_message(core, ctx, bson_data(&bs), bson_size(&bs));
}


static return_t zeroes(void* src, int bytes) {
    int i;
    for (i=0; i< bytes; i++) {
        char* b = (char*) src;
        if (b[i] & 0xff) {
            return RET_FAIL;
        }
    }
    return RET_SUCCESS;
}

size_t wish_core_get_host_id(wish_core_t* core, uint8_t *hostid_ptr) {
    if ( zeroes(core->id, WISH_WHID_LEN) == RET_SUCCESS ) {
        WISHDEBUG(LOG_CRITICAL, "Creating new host id");
        /* Create new host id file */        
        char sys_id_input_str[WISH_WHID_LEN];
        wish_platform_fill_random(NULL, sys_id_input_str, WISH_WHID_LEN);
        wish_core_create_hostid(core, (char*)hostid_ptr, sys_id_input_str, WISH_WHID_LEN);

        memcpy(core->id, hostid_ptr, WISH_WHID_LEN);
        wish_core_config_save(core);
        WISHDEBUG(LOG_CRITICAL, "New host id: %02x %02x %02x", hostid_ptr[0], hostid_ptr[1], hostid_ptr[2]);
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

void wish_core_update_transports_from_handshake(wish_core_t *core, wish_connection_t *connection, uint8_t *handshake_msg) {
    /* Update transports if we have a normal connection */
    
    wish_identity_t id;
    bson_iterator it;
    
    if ( wish_identity_load(connection->ruid, &id) == RET_SUCCESS ) {
        bool found_transports = false;
        /* Clear existing transports, and replace them with transports provided by remote party */
        /* FIXME append to transport list - instead of overwriting - the old transports should be deprecated later when we discover that they are no longer valid */
        memset(id.transports, 0, WISH_MAX_TRANSPORTS*WISH_MAX_TRANSPORT_LEN);
        for (int i = 0; i < WISH_MAX_TRANSPORTS; i++) {
            const size_t path_max_len = 16;
            char path[path_max_len];
            wish_platform_snprintf(path, path_max_len, "transports.%d", i);
            bson_iterator_from_buffer(&it, handshake_msg);
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

void wish_core_create_handshake_msg(wish_core_t* core, wish_connection_t* conn, uint8_t *buffer, size_t buffer_len) {
    
    uint8_t host_id[WISH_WHID_LEN] = { 0 };
    char host_part[WISH_MAX_TRANSPORT_LEN];
    char transport_url[WISH_MAX_TRANSPORT_LEN];
    
    wish_core_get_host_id(core, host_id);

    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_binary(&bs, "host", host_id, WISH_WHID_LEN);
    bson_append_start_array(&bs, "transports");
    
    
    int i = 0;
    
#if 0 //Putting local IP addr in handshake is disabled.
    if (wish_get_host_ip_str(core, host_part, WISH_MAX_TRANSPORT_LEN)) {
        WISHDEBUG(LOG_CRITICAL, "Could not get local IP addr."); 
    }
    else {
        /* IP addr of the local interface */
        wish_platform_sprintf(transport_url, "wish://%s:%d", host_part, wish_get_host_port(core));
        bson_append_string(&bs, "0", transport_url);
        i++;
    }
#endif
    
    wish_relay_client_t* relay = NULL;
    
    LL_FOREACH(core->relay_db, relay) {
        char index[21];
        BSON_NUMSTR(index, i++);
        
        char host[29];
        
        wish_platform_snprintf(host, 29, "wish://%d.%d.%d.%d:%d", relay->ip.addr[0], relay->ip.addr[1], relay->ip.addr[2], relay->ip.addr[3], relay->port);
        host[28] = '\0';
        
        bson_append_string(&bs, index, host);
    }
      
    bson_append_finish_array(&bs);
    
    if (conn->friend_req_connection == false) {
        /* Check if conn->ruid has permissions: { banned:true } */
        wish_identity_t id;

        if (wish_identity_load(conn->ruid, &id) != RET_SUCCESS) {
            WISHDEBUG(LOG_CRITICAL, "While checking permissions: Could not load ruid identity");       
        }
        else {
           
            bool banned = wish_identity_is_banned(&id);
            //WISHDEBUG(LOG_CRITICAL, "Adding: banned %i", banned);
            
            if (banned) {
                bson_append_bool(&bs, "banned", banned);
            }
        }
        wish_identity_destroy(&id);
    }
    
    bson_finish(&bs);
}

/**
 * Submit a BSON handshake message (extracted from the wire) to the Wish core.
 *
 * Note that if you wish (heh-heh) to retain any part of the bson_doc for later
 * processing, you MUST explicitly make a copy of the data, as the parameter
 * bson_doc is allocated from stack! 
 */
void wish_core_process_handshake(wish_core_t* core, wish_connection_t* ctx, uint8_t* handshake) {
    /* We are primarly interested about the host identity, not much else
     * */
    
    bson_iterator it;
    
    bson_iterator_from_buffer(&it, handshake);
    
    if (bson_find_fieldpath_value("host", &it) != BSON_BINDATA) {
        WISHDEBUG(LOG_CRITICAL, "We could not get the host field");
        return;
    }
    
    const uint8_t* host_id = bson_iterator_bin_data(&it);
    int32_t host_id_len = bson_iterator_bin_len(&it);
    
    if (host_id_len != WISH_WHID_LEN) {
        WISHDEBUG(LOG_CRITICAL, "Bad hostid length");
        return;
    }
    
    memcpy(ctx->rhid, host_id, WISH_WHID_LEN);
    
    if (ctx->friend_req_connection == false) {
        wish_core_update_transports_from_handshake(core, ctx, handshake);
    }
        
    /* Now create our own "wish handshake message" */
    const int max_handshake_len = 500;
    uint8_t handshake_msg[max_handshake_len];
    
    wish_core_create_handshake_msg(core, ctx, handshake_msg, max_handshake_len);
    
    bson bs;
    bson_init_with_data(&bs, handshake_msg);

    wish_core_send_message(core, ctx, bson_data(&bs), bson_size(&bs));
}

/* Generate an id for service messages */
int32_t generate_service_msg_id(void) {
    /* The latest message "id" we have sent away is stored here */
    static int my_last_id = 0;

    return my_last_id++;
}


void wish_core_process_message(wish_core_t* core, wish_connection_t* ctx, uint8_t* msg) {
    /* If you want to print out the on-wire message, now would be the
     * time */
    bool wire_debug = false;
    if (wire_debug) {
        bson_visit("Incoming message", msg);
    }

    /* Read the top-level and 'req'(uest), 'res'(ponse)
     * If 'req', then feed to an instance of wish-rpc server
     * if 'res', then feed to the corresponding instance of wish-client
     */
    
    bson_iterator it;
    
    if (bson_find_from_buffer(&it, msg, "req") == BSON_OBJECT) {
        WISHDEBUG(LOG_DEBUG, "Core RPC req found!");
        // FIXME: We send 0 as length, works only because it is not used
        wish_core_feed_to_rpc_server(core, ctx, bson_iterator_value(&it), 0);
    } else if (bson_find_from_buffer(&it, msg, "res") == BSON_OBJECT) {
        WISHDEBUG(LOG_DEBUG, "Core RPC res found!");
        // FIXME: We send 0 as length, works only because it is not used
        wish_core_feed_to_rpc_client(core, ctx, bson_iterator_value(&it), 0);
    } else if (bson_find_from_buffer(&it, msg, "ping") == BSON_BOOL) {
        wish_core_send_pong(core, ctx);
    } else if (bson_find_from_buffer(&it, msg, "pong") == BSON_BOOL) {
        // received a pong, but won't do much with it here.
    } else {
        WISHDEBUG(LOG_CRITICAL, "Unknown message on wire!");
    }
}

/* Route an incoming message (from app) */
void wish_core_handle_app_to_core(wish_core_t* core, const uint8_t src_wsid[WISH_ID_LEN], const uint8_t* data, size_t len) {
#if 0
    // This is used for debugging
    wish_app_entry_t* app = wish_service_get_entry(core, src_wsid);
    if (app) { WISHDEBUG(LOG_CRITICAL, "Incoming message from app %s to core len %d", app->name, len); }
    
    WISHDEBUG(LOG_CRITICAL, "Incoming message from app to core len %d", len);
    bson_visit("Incoming message from app to core", data);
#endif    
    

    /* Determine if it is login or what */
    const uint8_t *recovered_wsid = NULL;
    int32_t recovered_wsid_len = 0;
    
    /* If the incoming message is a 'ready' from the service, the state is saved here */
    bool app_ready = false;
    
    bson_iterator it;
    if (bson_find_from_buffer(&it, data, "wsid") == BSON_BINDATA) {
        recovered_wsid = bson_iterator_bin_data(&it);
        recovered_wsid_len = bson_iterator_bin_len(&it);
        
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

        if (bson_find_from_buffer(&it, data, "name") != BSON_STRING) {
            WISHDEBUG(LOG_CRITICAL, "Cannot get service name");
            return;
        }
        
        const char *name = bson_iterator_string(&it);
        int32_t name_len = bson_iterator_string_len(&it);
        
        if (name_len > 32) {
            WISHDEBUG(LOG_CRITICAL, "Service name too long");
            return;
        }

        if (bson_find_from_buffer(&it, data, "protocols") != BSON_ARRAY) {
            WISHDEBUG(LOG_CRITICAL, "Cannot get protocols array");
            return;
        }
        
        const uint8_t *protocols = bson_iterator_value(&it);
        
        if (bson_find_from_buffer(&it, data, "permissions") != BSON_ARRAY) {
            WISHDEBUG(LOG_CRITICAL, "Cannot get permissions array");
            return;
        }

        const uint8_t *permissions = bson_iterator_value(&it);

        wish_service_register_add(core, src_wsid, name, protocols, permissions);

        /* Send 'signal: "ready" to App */
        const size_t ready_signal_max_len = 100;
        uint8_t ready_signal[ready_signal_max_len];
        
        bson bs;
        bson_init_buffer(&bs, ready_signal, ready_signal_max_len);
        bson_append_string(&bs, "type", "signal");
        bson_append_string(&bs, "signal", "ready");
        bson_finish(&bs);
        
        send_core_to_app(core, src_wsid, bson_data(&bs), bson_size(&bs));
    }
    else if (bson_find_from_buffer(&it, data, "ready") == BSON_BOOL) {
        app_ready = bson_iterator_bool(&it);
        
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


