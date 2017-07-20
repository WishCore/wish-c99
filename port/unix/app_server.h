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
