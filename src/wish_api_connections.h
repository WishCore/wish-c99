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

    void wish_api_connections_disconnect_all(rpc_server_req* req, const uint8_t* args);
    
    void wish_api_connections_check_connections(rpc_server_req* req, const uint8_t* args);

    void wish_api_connections_apps(rpc_server_req* req, const uint8_t* args);
    
    /* Connections internals */
    
#ifdef __cplusplus
}
#endif
