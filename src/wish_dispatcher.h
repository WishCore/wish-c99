#pragma once

#include "wish_core.h"
#include "wish_connection.h"

/* Embedded Wish */

/* Submit a handshake message (extracted from the wire) to the Wish core */
void wish_core_process_handshake(wish_core_t* core, wish_connection_t* ctx, uint8_t* bson_doc);

void wish_core_create_handshake_msg(wish_core_t* core, uint8_t *buffer, size_t buffer_len);

/* Submit an actual Wish service message */
void wish_core_process_message(wish_core_t* core, wish_connection_t* ctx, uint8_t* bson_doc);

void wish_core_process_service_meta(wish_core_t* core, wish_connection_t* ctx,
uint8_t* service_reply_doc);

void user_notify_service_subscribe_sent(wish_core_t* core);

/* Generate a unique message id for service messages */
int32_t generate_service_msg_id(void);


/* Route an incoming message (from app) */
void wish_core_handle_app_to_core(wish_core_t* core, const uint8_t src_wsid[WISH_ID_LEN], const uint8_t *data, size_t len);

/** Create a Wish host identity based on seed bytes. Host identity
 * generation is a deterministic process, yeilding the same pubkey and
 * privkey for a given sys_id_str
 */
size_t wish_core_create_hostid(wish_core_t* core, char* hostid, char* sys_id_str, size_t sys_id_str_len);


size_t wish_core_get_host_id(wish_core_t* core, uint8_t *hostid_ptr);

