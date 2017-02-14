#ifndef MIST_HANDLER_H
#define MIST_HANDLER_H

#ifdef __cplusplus
extern "C" {
#endif

    #include <stdint.h>
    #include "wish_rpc.h"
    #include "mist_app.h"


    #if 0
    /* Function for feeding Mist messages up to the Mist RPC client */
    void receive_mist_northbound(mist_app_t *mist_app, uint8_t *bson_doc, uint8_t *peer_doc);
    #endif

    /* Functio for feeding Mist message to the Device API RPC server */
    void receive_device_northbound(mist_app_t *mist_app, uint8_t *data, int data_len, wish_protocol_peer_t* peer);


    /* Generate model of the device and send it, acking request_id */
    void handle_mist_control_model(uint8_t *bson_doc, wish_protocol_peer_t* peer);

    void mist_invoke_response(wish_rpc_server_t* s, int id, uint8_t* data);

    void mist_device_setup_rpc(wish_rpc_server_t *device_rpc_server);

    void mist_device_setup_rpc_handlers(wish_rpc_server_t *device_rpc_server);

#ifdef __cplusplus
}
#endif

#endif //MIST_HANDLER_H
