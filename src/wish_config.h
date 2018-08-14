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

#define WISH_CORE_CONFIG_DB_NAME "wish.conf"
    
#include "wish_core.h"
    
int wish_core_config_load(wish_core_t* core);

int wish_core_config_save(wish_core_t* core);

int wish_core_config_store(wish_core_t* core, const char* key, int len, bson* document);

bson* wish_core_config_find(wish_core_t* core, bson* query);

#ifdef __cplusplus
}
#endif
