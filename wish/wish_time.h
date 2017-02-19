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

/* Report the number of seconds elapsed since core startup */
wish_time_t wish_time_get_relative(wish_core_t* core);
