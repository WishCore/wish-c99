#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "stdint.h"
#include "uthash.h"

#include "wish_core.h"
    
    /* Relay API */
    
    void wish_api_relay_list(rpc_server_req* req, const uint8_t* args);
    
    void wish_api_relay_add(rpc_server_req* req, const uint8_t* args);
    
    void wish_api_relay_remove(rpc_server_req* req, const uint8_t* args);

    /* Relay internals */
    
#ifdef __cplusplus
}
#endif
