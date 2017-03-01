#pragma once

/* Time-related functions for Wish.
 *
 * The Wish core needs a time base for tracking time in one second
 * resultion.
 *
 * The time is needed for example for connection pinging, for detecting
 * dead connections. 
 */

#include "wish_core.h"

/* Report to Wish core that one second has been passed.
 * This function must be called periodically by the porting layer 
 * one second intervals */
void wish_time_report_periodic(wish_core_t* core);

typedef void (*timer_cb)(wish_core_t* core, void* cb_ctx);

wish_timer_db_t* wish_core_time_set_interval(wish_core_t* core, timer_cb cb, void* cb_ctx, int interval);

wish_timer_db_t* wish_core_time_set_timeout(wish_core_t* core, timer_cb cb, void* cb_ctx, int interval);

/* Report the number of seconds elapsed since core startup */
wish_time_t wish_time_get_relative(wish_core_t* core);
