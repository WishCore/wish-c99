#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "wish_app.h"
#include "uv.h"
#include "rb.h"

typedef struct wish_core_client {
    wish_app_t* app;
    ring_buffer_t* rb;
    uv_loop_t* loop;
    uv_connect_t* connect_req;
    uv_stream_t* tcp_stream;
    uv_tcp_t* tcp;
    uv_timer_t* timeout;
    struct wish_core_client* next;
    struct wish_core_client* prev;
} wish_core_client_t;

void wish_core_client_init(wish_app_t *app);

void wish_core_client_close(wish_app_t* app);

#ifdef __cplusplus
}
#endif