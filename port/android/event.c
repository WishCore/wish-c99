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
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "wish_event.h"
#include <stdlib.h>
#include <stdio.h>
#include "wish_platform.h"

int event_read = 0;
int event_write = 0;
int num_curr_events = 0;
#define EVENT_QUEUE_LEN 40
struct wish_event events[EVENT_QUEUE_LEN];

void wish_message_processor_notify(struct wish_event *ev) {
    memcpy(&(events[event_write]), ev, sizeof (struct wish_event));
    event_write = (event_write + 1) % EVENT_QUEUE_LEN;
    num_curr_events++;
    if (num_curr_events > EVENT_QUEUE_LEN) {
        wish_platform_printf("Event queue overflow.\n");
        //exit(0);
    }
}

struct wish_event * wish_get_next_event() {
    struct wish_event *ev = NULL;
    if (num_curr_events) {
        ev = &(events[event_read]);
        event_read = (event_read + 1) % EVENT_QUEUE_LEN;
        num_curr_events--;
    }
    return ev;
}

