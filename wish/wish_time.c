#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "wish_time.h"
#include "wish_io.h"
#include "wish_debug.h"
#include "wish_connection_mgr.h"
#include "wish_relay_client.h"
#include "cbson.h"


/* FIXME getter function? */
extern wish_context_t wish_context_pool[WISH_CONTEXT_POOL_SZ];

#define PING_INTERVAL 10    /* seconds */
#define PING_TIMEOUT (PING_INTERVAL + 30) /* seconds, must be larger than PING_INTERVAL */

#define CONNECTION_TIMEOUT 30 /* seconds */

/* This function will check the connections and send a 'ping' if they
 * have not received anything lately */
static void check_connection_liveliness(wish_core_t* core) {
    int i = 0;
    for (i = 0; i < WISH_CONTEXT_POOL_SZ; i++) {
        wish_context_t* w = &(wish_context_pool[i]);
        switch (w->context_state) {
        case WISH_CONTEXT_CONNECTED:
            /* We have found a connected context we must examine */
            if ((core->core_time > (w->latest_input_timestamp + PING_INTERVAL))
                && (w->ping_sent_timestamp <= w->latest_input_timestamp)) {
                WISHDEBUG(LOG_DEBUG, "Pinging connection %d", i);
 
                /* Enqueue a ping message */
                int32_t ping_msg_max_len = 50;
                uint8_t ping_msg[ping_msg_max_len];
                bson_init_doc(ping_msg, ping_msg_max_len);
                /* Send: { ping: true } */
                bson_write_boolean(ping_msg, ping_msg_max_len, 
                    "ping", true);
                wish_core_send_message(core, w, ping_msg, bson_get_doc_len(ping_msg));
                w->ping_sent_timestamp = core->core_time;
            }

            if (core->core_time > (w->latest_input_timestamp + PING_TIMEOUT) &&
                (w->ping_sent_timestamp > w->latest_input_timestamp)) {
                WISHDEBUG(LOG_CRITICAL, "Connection ping: Killing connection because of \
inactivity");
                wish_close_connection(core, w);
            }
            break;
        case WISH_CONTEXT_IN_MAKING:
            if (core->core_time > (w->latest_input_timestamp + PING_TIMEOUT)) {
                WISHDEBUG(LOG_CRITICAL, "Connection ping: Killing connection because it has been in handshake phase for too long");
                wish_close_connection(core, w);
            }
            break;
        case WISH_CONTEXT_CLOSING:
            WISHDEBUG(LOG_CRITICAL, "Connection ping: Found context in closing state! Forcibly closing it.");
            wish_close_connection(core, w);
            break;
        case WISH_CONTEXT_FREE:
            /* Obviously we don't ping unused contexts! */
            break;
        }
    }
}

/* Report to Wish core that one second has been passed.
 * This function must be called periodically by the porting layer 
 * one second intervals */
void wish_time_report_periodic(wish_core_t* core) {
    core->core_time++;

    check_connection_liveliness(core);
    wish_relay_check_timeout(core);

    static wish_time_t check_connections_timestamp;
    if (core->core_time > (check_connections_timestamp + 60)) {
        check_connections_timestamp = core->core_time;
        wish_connections_check(core);
    }
}

/* Report the number of seconds elapsed since core startup */
wish_time_t wish_time_get_relative(wish_core_t* core) {
    return core->core_time;
}


