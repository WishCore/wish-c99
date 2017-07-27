#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "stdint.h"
#include "uthash.h"
    
#include "wish_core.h"
    
    /* Acl API */
    
    void wish_api_wld_list(rpc_server_req* req, const uint8_t* args);
    
    void wish_api_wld_announce(rpc_server_req* req, const uint8_t* args);

    void wish_api_wld_clear(rpc_server_req* req, const uint8_t* args);

    void wish_api_wld_friend_request(rpc_server_req* req, const uint8_t* args);
    
    /* Acl internals */
    
#ifdef __cplusplus
}
#endif
