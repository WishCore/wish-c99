#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define WISH_CORE_CONFIG_DB_NAME "wish.conf"
    
#include "wish_core.h"
    
int wish_core_config_load(wish_core_t* core);

int wish_core_config_save(wish_core_t* core);

#ifdef __cplusplus
}
#endif
