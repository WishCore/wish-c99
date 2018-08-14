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

#include "wish_service_registry.h"
#include "wish_identity.h"

void wish_core_app_rpc_init(wish_core_t* core);

void wish_core_app_rpc_handle_req(wish_core_t* core, const uint8_t src_wsid[WISH_ID_LEN], const uint8_t *data);

void wish_core_app_rpc_cleanup_requests(wish_core_t* core, struct wish_service_entry *service_entry_offline);

void wish_send_peer_update_locals(wish_core_t* core, const uint8_t *dst_wsid, struct wish_service_entry *service_entry, bool online);
