/**
 * Copyright (C) 2018, ControlThings Oy Ab
 * Copyright (C) 2018, André Kaustell
 * Copyright (C) 2018, Jan Nyman
 * Copyright (C) 2018, Jepser Lökfors
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * @license Apache-2.0
 */
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include "wish_debug.h"
#include "wish_platform.h"
#include "wish_port_config.h"

/* 15 octets can be printed per line, assuming canonical 80 charter wide
 * terminal */
const int octets_per_line = 32;

#ifndef COMPILING_FOR_ESP8266

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

#endif //COMPILING_FOR_ESP8266

/* Print out an array on the terminal */
void wish_debug_print_array(int log_lvl, char* title, uint8_t* array, uint8_t len) {
    int i = 0;
    WISHDEBUG(log_lvl, "%s: print_array len: %d:", title, len);
    WISHDEBUG2(log_lvl, "  ");
    for (i = 0; i < len; i++) {
        WISHDEBUG2(log_lvl, "%02x ", array[i]);
        if (i % (octets_per_line-1) == 0 && i > 0) {
            WISHDEBUG(log_lvl, "");
            WISHDEBUG2(log_lvl, "  ");
        }
    }
    WISHDEBUG(log_lvl,"");
}
