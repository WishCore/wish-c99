#ifndef WISH_CORE_APP_RPC_FUNC_H
#define WISH_CORE_APP_RPC_FUNC_H

#include "wish_service_registry.h"
#include "wish_identity.h"

void wish_core_app_rpc_init(void);

void wish_core_app_rpc_handle_req(uint8_t src_wsid[WISH_ID_LEN], uint8_t *data);

void wish_core_app_rpc_cleanup_requests(uint8_t *wsid);

void wish_send_peer_update_locals(uint8_t *dst_wsid, struct wish_service_entry *service_entry, bool online);

void wish_report_identity_to_local_services(wish_identity_t* identity, bool online);

#endif 
