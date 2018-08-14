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

/*
 * Service IPC, core interface.
 *
 * This is the interface that is used by the Service IPC layer to
 * transfer data in and out of the Wish core 
 */

#include "wish_core.h"

/* 
 * wsid: the id of the app talking to core 
 */
void receive_app_to_core(wish_core_t* core, const uint8_t wsid[WISH_ID_LEN], const uint8_t *data, size_t len);

/* wsid: the id the app which should receive the data */
void send_core_to_app(wish_core_t* core, const uint8_t wsid[WISH_ID_LEN], const uint8_t *data, size_t len);

void core_service_ipc_init(wish_core_t* core);

