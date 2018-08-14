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
#include "rb.h"

void ring_buffer_init(ring_buffer_t* buf, uint8_t* data, uint16_t len) {
    buf->read = 0;
    buf->data_len = 0;
    buf->data = data;
    buf->max_len = len;
    buf->state = RINGBUFFER_STATE_WAIT;
}


uint8_t ring_buffer_is_full(ring_buffer_t* buf) {
    if ( buf->data_len == buf->max_len ) {
        return 1;
    } else {
        return 0;
    }
}

uint8_t ring_buffer_is_empty(ring_buffer_t* buf) {
    if ( buf->data_len == 0 ) {
        return 1;
    } else {
        return 0;
    }
}

uint16_t ring_buffer_length(ring_buffer_t* buf) {
    return buf->data_len;
}

uint16_t ring_buffer_space(ring_buffer_t* buf) {
    return buf->max_len - buf->data_len;
}

uint16_t ring_buffer_write(ring_buffer_t* buf, const uint8_t* data, uint16_t len) {
    uint16_t wrote = 0;
    uint16_t cursor = (buf->read+buf->data_len)%buf->max_len;
    while (wrote<len) {
        if ( ring_buffer_is_full(buf) ) {
            return wrote;
        } else {
            buf->data[cursor] = data[wrote];
            wrote++;
            buf->data_len++;
            cursor = (buf->read+buf->data_len)%buf->max_len;
        }
    }
    return wrote;
}

uint16_t ring_buffer_read(ring_buffer_t* buf, uint8_t* data, uint16_t len) {
    uint16_t read = 0;
    uint16_t cursor = buf->read;
    while (read<len) {
        if ( ring_buffer_is_empty(buf) ) {
            return read;
        } else {
            data[read] = buf->data[cursor];
            read++;
            buf->data_len--;
            ++buf->read;
            buf->read %= buf->max_len;
            cursor = buf->read;
        }
    }
    return read;
}

uint16_t ring_buffer_skip(ring_buffer_t* buf, uint16_t len) {
    uint16_t read = 0;
    while (read<len) {
        if ( ring_buffer_is_empty(buf) ) {
            return read;
        } else {
            read++;
            buf->data_len--;
            ++buf->read;
            buf->read %= buf->max_len;
        }
    }
    return read;
}

uint16_t ring_buffer_peek(ring_buffer_t* buf, uint8_t* data, uint16_t len) {
    uint16_t read = 0;
    uint16_t cursor = buf->read;
    // Peek a maximum of data_len bytes
    if ( buf->data_len < len ) {
        len = buf->data_len;
    }
    while (read<len) {
        data[read] = buf->data[cursor];
        read++;
        cursor++;
        cursor %= buf->max_len;
    }
    return read;
}



