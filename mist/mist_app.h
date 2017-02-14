#ifndef MIST_APP_H
#define MIST_APP_H

#ifdef __cplusplus
extern "C" {
#endif

#include "cbson.h"
#include "wish_debug.h"
#include "wish_rpc.h"
#include "wish_app.h"
#include "wish_protocol.h"
#include "mist_model.h"

/* This defines the size of the buffer were the RPC reply will be
 * built */
#define MIST_RPC_REPLY_BUF_LEN 1460

#define MIST_APP_NAME_MAX_LEN 16

/** Maximum number of Mist apps you can have. Note that this cannot be
 * smaller than NUM_WISH_APPS */
#define NUM_MIST_APPS 5

#if NUM_MIST_APPS != NUM_WISH_APPS
#error Max number of mist apps cannot be larger than number of wish apps
#endif
    


typedef struct mist_app_t {
    char name[MIST_APP_NAME_MAX_LEN];
    bool occupied;
    wish_app_t *app;
    wish_protocol_handler_t ucp_handler;
    struct mist_model model;
    wish_rpc_server_t device_rpc_server;
    void (*online)(void* app, wish_protocol_peer_t* peer);
    void (*offline)(void* app, wish_protocol_peer_t* peer);
} mist_app_t;

typedef struct {
    wish_app_t* app;
    wish_protocol_peer_t* peer;
} app_peer_t;

mist_app_t *mist_app_get_new_context(void);

mist_app_t *start_mist_app(void);

void mist_set_name(mist_app_t *ctx, char* name);

wish_rpc_id_t receive_device_southbound(mist_app_t *mist_app, uint8_t *reply_doc, size_t reply_doc_actual_len, wish_protocol_peer_t* peer, rpc_client_callback cb);

wish_rpc_id_t mist_app_request(mist_app_t *mist_app, wish_protocol_peer_t* peer, uint8_t *request, size_t request_len, rpc_client_callback cb);

void handle_mist_message(mist_app_t *mist_app, uint8_t* data, int data_len, wish_protocol_peer_t* peer);

mist_app_t *mist_app_lookup_by_wsid(uint8_t *wsid);

#ifdef __cplusplus
}
#endif

#endif /* MIST_APP_H */
