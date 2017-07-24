/*
 * A dummy, or "faux" Service IPC layer implementation, 
 * which exists only to tie services togheter with the core in the
 * situation where they are running in the same process */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "wish_core.h"
#include "wish_app.h"
//#include "app_service_ipc.h"
#include "core_service_ipc.h"
#include "bson_visit.h"
#include "wish_debug.h"
#include "wish_dispatcher.h"
#include "wish_port_config.h"

#ifdef WITH_APP_TCP_SERVER
#include "app_server.h"     /* in directory port/unix */
#endif

uint8_t wsid[WISH_WSID_LEN];
bool login = false;


void core_service_ipc_init(wish_core_t* wish_core) {
    //core = wish_core;
}

void send_app_to_core(uint8_t *wsid, uint8_t *data, size_t len) {
    /* Handle the following situations:
     *      -login message 
     *      -normal situation */

    /* Snatch the "wsid" field from login */
    if (login == false) {
        bson_iterator it;

        if (bson_find_from_buffer(&it, data, "wsid") == BSON_BINDATA 
                && bson_iterator_bin_len(&it) == WISH_WSID_LEN) 
        {
            memcpy(wsid, bson_iterator_bin_data(&it), WISH_WSID_LEN);
            login = true;
        } else {
            bson_visit("Bad login message!", data);
        }
    }

    wish_core_t* core = NULL;
    
    /* Feed the message to core */
    receive_app_to_core(core, wsid, data, len);
}


void receive_app_to_core(wish_core_t* core, const uint8_t wsid[WISH_ID_LEN], const uint8_t* data, size_t len) {
    wish_core_handle_app_to_core(core, wsid, data, len);
}

#if 0
void receive_core_to_app(wish_app_t *app, uint8_t *data, size_t len) {
    /* Parse the message:
     * -peer
     * -frame
     * -ready signal
     *
     * Then feed it to the proper wish_app_* callback depending on type
     */
    wish_app_determine_handler(app, data, len);
}
#endif

void send_core_to_app(wish_core_t* core, const uint8_t wsid[WISH_ID_LEN], const uint8_t *data, size_t len) {
#ifdef WITH_APP_TCP_SERVER
    /* First test if we have an application which has contacted via the
     * TCP app port - if it is, send te data via the App TCP connection
     * and return */
    if (is_app_via_tcp(core, wsid)) {
        send_core_to_app_via_tcp(core, wsid, data, len);
        return;
    }
    /* If we get this far, it means that the app is not via the app TCP
     * server, and should be handled locally */

#endif
#ifdef WITH_APP_INTERNAL    
    /* Find from the list of wish apps the one with the said wsid */
    wish_app_t *dst_app = wish_app_find_by_wsid(wsid);
    if (dst_app == NULL) {
        //bson_visit("send_app_to_core: Could not find the destination service", data);
    }
    else {
        receive_core_to_app(wish_core_t* core, dst_app, data, len);
    }
#endif
}


void send_wish_api(uint8_t *buffer, size_t buffer_len) {
        WISHDEBUG(LOG_CRITICAL, "WISHAPI UNIMPLEMENTED");

}
