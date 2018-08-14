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

#define NUM_APP_CONNECTIONS 20

#define APP_RX_RB_SZ 64*1024-1

#include "wish_core.h"

void setup_app_server(wish_core_t* core, uint16_t port);

/* This defines the possible states of an App connection */
enum app_state { APP_CONNECTION_INITIAL, APP_CONNECTION_CONNECTED };

enum app_transport_state {
    APP_TRANSPORT_INITIAL,
    APP_TRANSPORT_WAIT_FRAME_LEN,
    APP_TRANSPORT_WAIT_PAYLOAD,
    APP_TRANSPORT_CLOSING
};

void app_connection_feed(wish_core_t* core, int i, uint8_t *buffer, size_t buffer_len);

void app_connection_cleanup(wish_core_t* core, int i);

void send_core_to_app_via_tcp(wish_core_t* core, const uint8_t wsid[WISH_ID_LEN], const uint8_t *data, size_t len);

bool is_app_via_tcp(wish_core_t* core, const uint8_t wsid[WISH_WSID_LEN]);
