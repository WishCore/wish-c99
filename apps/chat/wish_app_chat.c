#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "bson.h"
#include "wish_io.h"
#include "wish_debug.h"
#include "wish_app.h"

wish_app_t *app;

static int chat_online(void *app_ctx, wish_protocol_peer_t* peer) {
    return 0;
}

static int chat_offline(void *app_ctx, wish_protocol_peer_t* peer) {
    return 0;
}

static int chat_frame_received(void *app_ctx, uint8_t *data, size_t data_len, wish_protocol_peer_t *peer) {
    // danger, danger setting character outside buffer to 0!
    data[data_len] = 0;
    WISHDEBUG(LOG_CRITICAL, "in chat_frame_received %s\n", data);


    wish_app_send(app, peer, "The most cool response ever!", 28, NULL);
    
    

    return 0;
}

wish_protocol_handler_t chat_handler = {
    .protocol_name = "chat",
    .on_online = chat_online,
    .on_offline = chat_offline,
    .on_frame = chat_frame_received,
};

void wish_app_chat_init() {

    app = wish_app_create("Chat");
    if (app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Failed creating wish app");
        return;
    }
    wish_app_add_protocol(app, &chat_handler);
    wish_app_login(app);
}


