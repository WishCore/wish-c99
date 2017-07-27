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

