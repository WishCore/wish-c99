#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "stdint.h"
#include "uthash.h"
#include "wish_identity.h"

#include "wish_core.h"
    
    /* Identity API */
    
    void wish_api_identity_export(rpc_server_req* req, const uint8_t* args);

    void wish_api_identity_import(rpc_server_req* req, const uint8_t* args);

    void wish_api_identity_list(rpc_server_req* req, const uint8_t* args);

    void wish_api_identity_get(rpc_server_req* req, const uint8_t* args);

    void wish_api_identity_create(rpc_server_req* req, const uint8_t* args);

    void wish_api_identity_update(rpc_server_req* req, const uint8_t* args);

    void wish_api_identity_remove(rpc_server_req* req, const uint8_t* args);

    void wish_api_identity_sign(rpc_server_req* req, const uint8_t* args);

    void wish_api_identity_verify(rpc_server_req* req, const uint8_t* args);

    void wish_api_identity_friend_request(rpc_server_req* req, const uint8_t* args);

    void wish_api_identity_friend_request_list(rpc_server_req* req, const uint8_t* args);

    void wish_api_identity_friend_request_accept(rpc_server_req* req, const uint8_t* args);

    void wish_api_identity_friend_request_decline(rpc_server_req* req, const uint8_t* args);    
    
    /* Identity internals */

    void wish_report_identity_to_local_services(wish_core_t* core, wish_identity_t* identity, bool online);
    
#ifdef __cplusplus
}
#endif
