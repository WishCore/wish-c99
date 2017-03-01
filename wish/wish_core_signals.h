#pragma once

#include "wish_core.h"
    
void wish_core_signals(rpc_server_req* req, uint8_t* args);

void wish_core_signals_emit(wish_core_t* core, bson* signal);
