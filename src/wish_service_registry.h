#pragma once

#include "wish_app.h"
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



