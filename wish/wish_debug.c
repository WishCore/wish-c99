#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include "wish_debug.h"
#include "wish_platform.h"
#include "wish_port_config.h"

#ifdef WISH_CONSOLE_COLORS

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_WHITE   "\x1b[37m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define AC_WHITE_STRING    ANSI_COLOR_WHITE "%s" ANSI_COLOR_RESET

#else   //WISH_CONSOLE_COLORS

#define ANSI_COLOR_RED     
#define ANSI_COLOR_GREEN   
#define ANSI_COLOR_YELLOW  
#define ANSI_COLOR_BLUE    
#define ANSI_COLOR_MAGENTA 
#define ANSI_COLOR_CYAN    
#define ANSI_COLOR_WHITE   
#define ANSI_COLOR_RESET   

#define AC_WHITE_STRING   "%s"
#endif  //WISH_CONSOLE_COLORS



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

/* This is a generic BSON element visitor function which can be used
 * with bson_visit function. It just prints out the name of elements */
void elem_visitor(char *elem_name, uint8_t elem_type, uint8_t *elem, uint8_t depth) {

    depth += 1;
    char indent[32];
    memset(indent, ' ', 32);
    indent[depth*4] = 0;
    
    switch (elem_type) {
    case BSON_KEY_ARRAY:
        WISHDEBUG(LOG_CRITICAL, "%s" AC_WHITE_STRING ": [", indent, elem_name);
        break;
    case BSON_KEY_DOCUMENT:
        WISHDEBUG(LOG_CRITICAL, "%s" AC_WHITE_STRING ": {", indent, elem_name);
        break;
    case BSON_KEY_BINARY:
        WISHDEBUG(LOG_CRITICAL, "%s" AC_WHITE_STRING ": Buffer(" ANSI_COLOR_CYAN "0x%02x %02x %02x %02x" ANSI_COLOR_RESET " ...)", indent, elem_name, elem[0], elem[1], elem[2], elem[3]);
        break;
    case BSON_KEY_STRING:
        WISHDEBUG(LOG_CRITICAL, "%s" AC_WHITE_STRING ": " ANSI_COLOR_YELLOW "'%s'" ANSI_COLOR_RESET, indent, elem_name, elem);
        break;
    case BSON_KEY_INT32:
        WISHDEBUG(LOG_CRITICAL, "%s" AC_WHITE_STRING ": " ANSI_COLOR_GREEN "%d" ANSI_COLOR_RESET, indent, elem_name, int32_le2native(elem));
        break;
    case BSON_KEY_BOOLEAN:
        WISHDEBUG(LOG_CRITICAL, "%s" AC_WHITE_STRING ": " ANSI_COLOR_BLUE "%s" ANSI_COLOR_RESET, indent, elem_name, ((uint8_t)*elem) == 0 ? "false" : "true" );
        break;
    default:
        WISHDEBUG(LOG_CRITICAL, "%s" AC_WHITE_STRING ": ", indent, elem_name);
    }

}



