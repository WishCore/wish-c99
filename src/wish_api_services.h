#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "stdint.h"
#include "uthash.h"
    
#include "wish_core.h"
    
    /* Services API */
    
    void wish_api_services_send(rpc_server_req* req, const uint8_t* args);
    
    void wish_api_services_list(rpc_server_req* req, const uint8_t* args);

    /* Services internals */
    
#ifdef __cplusplus
}
#endif
