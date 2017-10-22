#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "stdint.h"
    
#include "wish_core.h"
    
    /* Connections API */
    
    void wish_api_connections_list(rpc_server_req* req, const uint8_t* args);
    
    void wish_api_connections_request(rpc_server_req* req, const uint8_t* args);
    
    void wish_api_connections_disconnect(rpc_server_req* req, const uint8_t* args);
    
    void wish_api_connections_check_connections(rpc_server_req* req, const uint8_t* args);

    void wish_api_connections_apps(rpc_server_req* req, const uint8_t* args);
    
    /* Connections internals */
    
#ifdef __cplusplus
}
#endif
