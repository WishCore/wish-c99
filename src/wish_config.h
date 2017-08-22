#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define WISH_CORE_CONFIG_DB_NAME "wish.conf"
    
#include "wish_core.h"
    
int wish_core_config_load(wish_core_t* core);

int wish_core_config_save(wish_core_t* core);

int wish_core_config_store(wish_core_t* core, const char* key, int len, bson* document);

bson* wish_core_config_find(wish_core_t* core, bson* query);

#ifdef __cplusplus
}
#endif
