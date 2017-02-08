#ifndef WISH_DISPATCHER_H
#define WISH_DISPATCHER_H
#include "wish_io.h"

/* Embedded Wish */

/* Submit a handshake message (extracted from the wire) to the Wish core */
void wish_core_process_handshake(wish_context_t* ctx, uint8_t* bson_doc);

void wish_core_create_handshake_msg(uint8_t *buffer, size_t buffer_len);

/* Submit an actual Wish service message */
void wish_core_process_message(wish_context_t* ctx, uint8_t* bson_doc);

void wish_core_process_service_meta(wish_context_t* ctx,
uint8_t* service_reply_doc);

void user_notify_service_subscribe_sent(void);

/* Generate a unique message id for service messages */
int32_t generate_service_msg_id(void);


/* Route an incoming message (from app) */
void wish_core_handle_app_to_core(uint8_t src_wsid[WISH_ID_LEN], uint8_t *data, size_t len);

/** Create a Wish host identity based on seed bytes. Host identity
 * generation is a deterministic process, yeilding the same pubkey and
 * privkey for a given sys_id_str
 */
size_t wish_core_create_hostid(char* hostid, char* sys_id_str, 
    size_t sys_id_str_len);


size_t wish_core_get_local_hostid(uint8_t *hostid_ptr);

#endif  //WISH_DISPATCHER_H
