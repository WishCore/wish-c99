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

#include "wish_core.h"
    
void wish_core_signals(rpc_server_req* req, const uint8_t* args);

void wish_core_signals_emit(wish_core_t* core, bson* signal);

/* Convenience function for emitting bson signal { data: [string] } */
void wish_core_signals_emit_string(wish_core_t* core, char* string);
