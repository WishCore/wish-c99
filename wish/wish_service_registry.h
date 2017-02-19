#pragma once

#include "wish_app.h"
#include "wish_core.h"

void wish_service_register_add(wish_core_t* core, uint8_t *src_wsid, char *name, 
    uint8_t *protocols_array, uint8_t *permissions_array);

void wish_service_register_remove(wish_core_t* core, uint8_t *wsid);

struct wish_service_entry * wish_service_get_registry(wish_core_t* core);
bool wish_service_entry_is_valid(wish_core_t* core, struct wish_service_entry *entry);

struct wish_service_entry *wish_service_get_entry(wish_core_t* core, uint8_t *wsid);

