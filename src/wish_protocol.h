#ifndef WISH_PROTOCOL_H
#define WISH_PROTOCOL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include "wish_rpc.h"

#define WISH_APP_PROTOCOL_PEERS_MAX 10

#define WISH_PROTOCOL_NAME_MAX_LEN 10

#define WISH_UID_LEN 32

typedef struct {
    bool occupied;
    uint8_t luid[WISH_UID_LEN];
    uint8_t ruid[WISH_UID_LEN];
    uint8_t rhid[WISH_UID_LEN];
    uint8_t rsid[WISH_UID_LEN];
    char protocol[WISH_UID_LEN];
    bool online;
} wish_protocol_peer_t;

typedef struct {
    /* A facility for sending RPC messages, and define callbacks which
     * will be executed when the call is acked */
    rpc_client rpc_client;
    
    /* wish_rpc_server_t *rpc_server,
     * This will include a facility for dynamically define callbacks for
     * messages with different 'op's */
    //enum wish_protocol protocol;
    char protocol_name[WISH_PROTOCOL_NAME_MAX_LEN];
    /* Callback to be invoked when frame is received.
     * The argument data is the frame's payload, the elem named "data" of the frame*/
    int (*on_frame)(void *app_ctx, uint8_t *data, size_t data_len, wish_protocol_peer_t* peer);
    /* Callback to be invoked when peer comes online */
    int (*on_online)(void *app_ctx, wish_protocol_peer_t* peer);
    /* Callback to be invoked when peer goes offline */
    int (*on_offline)(void *app_ctx, wish_protocol_peer_t* peer);
    /** This is the application context that will be supplied to every
     * invocation of the protocol handler callback functions. 
     * It must be initialised when saving the function contexts. */
    void *app_ctx;
    /* Cache size for peers for this protocol */
    int peer_pool_size;
    wish_protocol_peer_t* peer_pool;
    wish_protocol_peer_t peer_pool_data[WISH_APP_PROTOCOL_PEERS_MAX];
} wish_protocol_handler_t;


#ifdef __cplusplus
}
#endif

#endif /* WISH_PROTOCOL_H */
