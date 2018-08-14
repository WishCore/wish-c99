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
#include "uthash.h"
    
#include "wish_core.h"
    
    /* Services API */
    
    void wish_api_services_send(rpc_server_req* req, const uint8_t* args);
    
    void wish_api_services_list(rpc_server_req* req, const uint8_t* args);

    /* Services internals */
    
#ifdef __cplusplus
}
#endif
