#ifndef WISH_CORE_RPC_FUNC_H
#define WISH_CORE_RPC_FUNC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "wish_io.h"
#include "wish_service_registry.h"

void wish_core_init_rpc(void);

void wish_core_feed_to_rpc_server(wish_context_t *ctx, 
    uint8_t *data, size_t len);

void wish_core_feed_to_rpc_client(wish_context_t *ctx, 
    uint8_t *data, size_t len);

/* Helper function for simply sending a 'peers' request e.g. when new
 * core connection is established */
void wish_core_send_peers_rpc_req(wish_context_t *ctx);


void wish_send_online_offline_signal_to_apps(wish_context_t *ctx, bool online);

void wish_send_peer_update(struct wish_service_entry *registry_entry, bool online);

/* 
 This function is used to clean up the core RPC server from old requests when a connection to a remote core is severed 
 @param ctx the core connection context of the severed link
 */
void wish_cleanup_core_rpc_server(wish_context_t *ctx);

#endif //WISH_CORE_RPC_FUNC_H
