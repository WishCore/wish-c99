#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "wish_time.h"
#include "wish_io.h"
#include "wish_debug.h"
#include "wish_connection_mgr.h"
#include "wish_relay_client.h"
#include "cbson.h"

#include "utlist.h"


/* Report to Wish core that one second has been passed.
 * This function must be called periodically by the porting layer 
 * one second intervals */
void wish_time_report_periodic(wish_core_t* core) {
    core->core_time++;

    wish_relay_check_timeout(core);

    static wish_time_t check_connections_timestamp;
    if (core->core_time > (check_connections_timestamp + 60)) {
        check_connections_timestamp = core->core_time;
        wish_connections_check(core);
    }

    wish_timer_db_t* timer = NULL;
    wish_timer_db_t* tmp = NULL;
    
    LL_FOREACH_SAFE(core->time_db, timer, tmp) {
        //WISHDEBUG(LOG_CRITICAL, "timer check %i > %i, int: %i?", core->core_time, timer->time, timer->interval);
        if (core->core_time >= timer->time) {
            timer->cb(core, timer->cb_ctx);
            if (timer->singleShot) {
                LL_DELETE(core->time_db, timer);
                wish_platform_free(timer);
            } else {
                timer->time = core->core_time + timer->interval;
            }
        }
    }
}

wish_timer_db_t* wish_core_time_set_interval(wish_core_t* core, timer_cb cb, void* cb_ctx, int interval ) {
    wish_timer_db_t* timer = wish_platform_malloc(sizeof(wish_timer_db_t));
    timer->time = core->core_time + interval;
    timer->interval = interval;
    timer->cb = cb;
    timer->cb_ctx = cb_ctx;
    timer->singleShot = false;
    LL_APPEND(core->time_db, timer);
    
    return timer;
}

wish_timer_db_t* wish_core_time_set_timeout(wish_core_t* core, timer_cb cb, void* cb_ctx, int interval ) {
    wish_timer_db_t* timer = wish_platform_malloc(sizeof(wish_timer_db_t));
    timer->time = core->core_time + interval;
    timer->interval = interval;
    timer->cb = cb;
    timer->cb_ctx = cb_ctx;
    timer->singleShot = true;
    LL_APPEND(core->time_db, timer);
    
    return timer;
}

/* Report the number of seconds elapsed since core startup */
wish_time_t wish_time_get_relative(wish_core_t* core) {
    return core->core_time;
}


