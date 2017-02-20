#pragma once

#include "wish_core.h"
    
void wish_core_signals(wish_rpc_ctx* req, uint8_t* args);

void wish_core_signal_emit(wish_core_t* core, bson* signal);
