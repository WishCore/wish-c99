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

void wish_service_register_add(wish_core_t* core, const uint8_t* src_wsid, const char* name, const uint8_t* protocols, const uint8_t* permissions);

void wish_service_register_remove(wish_core_t* core, const uint8_t *wsid);

wish_app_entry_t* wish_service_get_registry(wish_core_t* core);

bool wish_service_entry_is_valid(wish_core_t* core, wish_app_entry_t *entry);

wish_app_entry_t* wish_service_get_entry(wish_core_t* core, const uint8_t *wsid);

/**
 * Returns pointer to the app if it exists or NULL
 * 
 * @param core
 * @param app
 * @return 
 */
wish_app_entry_t* wish_service_exists(wish_core_t* core, const wish_app_entry_t* app);



