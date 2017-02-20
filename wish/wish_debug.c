#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include "wish_debug.h"
#include "wish_platform.h"
#include "wish_port_config.h"

/* 15 octets can be printed per line, assuming canonical 80 charter wide
 * terminal */
const int octets_per_line = 16;

#define WISH_DEBUG_STREAM_INDEX_MAX 10

char debug_stream_names[WISH_DEBUG_STREAM_INDEX_MAX][15] = {
    "wire",
    "critical",
    "debug",
    "info",
};

bool debug_stream_enabled[WISH_DEBUG_STREAM_INDEX_MAX] = {
    false,
    false,
    false,
    false,
};

void wish_debug_set_stream(unsigned int stream, bool enable) {
    if(stream >= WISH_DEBUG_STREAM_INDEX_MAX) { return; }
    
    WISHDEBUG(LOG_CRITICAL, "%s debug output for %s", enable == true ? "Enabling" : "Disabling", debug_stream_names[stream]);
    
    debug_stream_enabled[stream] = enable;
}

void wish_debug_printf(int stream, const char* format, ...) {
    
    if(stream >= WISH_DEBUG_STREAM_INDEX_MAX) { return; }
    
    if (debug_stream_enabled[stream] == true) {
        va_list arg;
        va_start(arg, format);
        wish_platform_printf(format, arg);
        va_end(arg);        
    }
}

/* Print out an array on the terminal */
void wish_debug_print_array(int log_lvl, char* title, uint8_t* array, uint8_t len) {
    int i = 0;
    WISHDEBUG(log_lvl, "%s: print_array len: %d:", title, len);
    WISHDEBUG2(log_lvl, "  ");
    for (i = 0; i < len; i++) {
        WISHDEBUG2(log_lvl, "0x%02x ", array[i]);
        if (i % (octets_per_line-1) == 0 && i > 0) {
            WISHDEBUG(log_lvl, "");
            WISHDEBUG2(log_lvl, "  ");
        }
    }
    WISHDEBUG(log_lvl,"");
}

/* Platform-dependent function to immediately cease all processing and
 * just wait performing only the minimum amount of activity, such as
 * watchdog feed etc. 
 * This is useful to debug problems which would othervise lead to
 * watchdog resets. */
void wish_debug_die() {
    while (1) {
//        system_soft_wdt_feed();
    }

}
