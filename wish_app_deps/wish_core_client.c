#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <uv.h> 
#include "bson.h"
#include "cbson.h"
#include "bson_visitor.h"
#include "wish_core_client.h"
#include "wish_fs.h"
#include "fs_port.h"
#include "rb.h"
#include "utlist.h"

#include <time.h>
#include "wish_platform.h"

char app_login_header[100] = {'W', '.', '\x19'};

void on_write_end(uv_write_t *req, int status);

void elem_visitor(char *elem_name, uint8_t elem_type, uint8_t *elem, uint8_t depth);

void send_wish_api(uint8_t *buffer, size_t buffer_len) {
    //printf("Dummy send_wish_api function called... doing nothing!\n");
}

bool login = false;

static wish_core_client_t* wish_core_clients = NULL;

typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;

void free_write_req(uv_write_t *req, int status) {
    write_req_t *wr = (write_req_t*) req;
    free(wr->buf.base);
    free(wr);
}

void send_app_to_core(uint8_t *wsid, uint8_t *data, size_t len) {
    
    /* Handle the following situations:
     *      -login message 
     *      -normal situation */

    /* Snatch the "wsid" field from login */
    if (login == false) {
        int login_wsid_len = 0;
        uint8_t *login_wsid = 0;
        if (bson_get_binary(data, "wsid", &login_wsid, &login_wsid_len)
                == BSON_SUCCESS) {
            if (login_wsid_len == WISH_WSID_LEN) {
                memcpy(wsid, login_wsid, WISH_WSID_LEN);
            }
            else {
                printf("wsid len mismatch");
            }
            login = true;
        }
        else {
            printf("Could not snatch wsid from login");
            return;
        }
    }

    // Write the frame (header+message) to the socket
    char hdr[2];
    hdr[0] = len >> 8;
    hdr[1] = len & 0xff;
    
    int buf_len = 2+len;
    char* buf = malloc(buf_len);
    
    memcpy(buf, &hdr, 2);
    memcpy(buf+2, data, len);
    
    write_req_t* write_req = malloc(sizeof(write_req_t));

    write_req->buf = uv_buf_init( buf, buf_len);

    
    wish_core_client_t* elt;
    uv_stream_t* tcp_stream = NULL;
    int c = 0;
    
    DL_FOREACH(wish_core_clients, elt) {
        c++;
        if (memcmp(wsid, elt->app->wsid, WISH_WSID_LEN) == 0) {
            tcp_stream = elt->tcp_stream;
            break;
        }
    }
    
    if (tcp_stream != NULL) {
        printf("%s to core... len: %i sid: %02x %02x %02x %02x\n", elt->app->name, (int)len, wsid[0], wsid[1], wsid[2], wsid[3]);
        bson_visit(data, elem_visitor);
        //printf("send_app_to_core: Found the correct stream %p and app %p\n", tcp_stream, elt->app);
        uv_write((uv_write_t*)write_req, tcp_stream, &write_req->buf, 1, free_write_req);
    } else {
        printf("send_app_to_core: could not find the stream! checked: %i\n", c);
    }
}


#define log(x) printf("%s\n", x);

void on_connect(uv_connect_t *req, int status);
void on_write_end(uv_write_t *req, int status);
void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
void echo_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);

int state = 0;
int expect = 0;

static void parse(wish_core_client_t* client) {
    int available;
    
again:

    available = ring_buffer_length(client->rb);
    //printf("parsing available %i\n", available);
    
    switch(state) {
        case 0:
            if(available < 2) { /*printf("waiting for header\n");*/ return; }
            // got the frame header
            
            uint8_t hdr_s[2];
            uint8_t* hdr = hdr_s;
            
            ring_buffer_read(client->rb, hdr, 2);
            
            expect = (((uint16_t)hdr[1]) & 0xff) + (hdr[0] << 8);
            //printf("expect frame length: %d (%02x %02x)\n", expect, hdr[0], hdr[1]);
            //ring_buffer_skip(rb, 2);
            state = 1;
            goto again;
            break;
        case 1:
            if(available < expect) { /*printf("waiting for more data\n");*/ return; }
            
            uint8_t data_s[65535];
            uint8_t* data = data_s;
            ring_buffer_read(client->rb, data, expect);
            
            printf("core_client::parse have a message for app %s\n", client->app->name);
            bson_visit(data, elem_visitor);
            
            wish_app_determine_handler(client->app, data, expect);
            //ring_buffer_skip(rb, expect);
            expect = 2;
            state = 0;
            goto again;
            break;
        default:
            //printf("We expect a frame body with length: %i, but got %i data \n", expect, (int)available);
            break;
    }
}

void echo_read(uv_stream_t *server, ssize_t nread, const uv_buf_t *buf) {
    if (nread < 0) {
        //fprintf(stderr, "error echo_read %i \n", (int)nread);
        uv_read_stop(server);
        return;
    }
    
    wish_core_client_t* elt;
    uv_stream_t* tcp_stream = NULL;
    
    DL_FOREACH(wish_core_clients, elt) {
        if (server == elt->tcp_stream) {
            tcp_stream = elt->tcp_stream;
            break;
        }
    }
    
    if (tcp_stream == NULL) {
        printf("echo_read: could not find the stream!\n");
        return;
    }

    //printf("echo_read: Found the correct stream %p and app %p\n", tcp_stream, elt->app);
    
    int wrote = ring_buffer_write(elt->rb, buf->base, nread);
    
    if (wrote == nread) {
        // all ok, we wrote the whole thing
    } else {
        printf("Failed to write everything to buffer got %i wrote %i\n", (int)nread, (int)wrote);
    }
    
    //memcpy(wcursor, buf->base, nread);
    //wcursor += nread;
    
    if(buf->base != NULL) {
        free(buf->base);
    }
    
    parse(elt);
}

void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
  buf->base = malloc(suggested_size);
  buf->len = suggested_size;
}

void on_write_end(uv_write_t *req, int status) {
    if (status == -1) {
        //fprintf(stderr, "error on_write_end");
        return;
    }
    free(req);
}

void on_connect(uv_connect_t *req, int status) {
    if (status == -1) {
        //fprintf(stderr, "error on_write_end");
        return;
    }
    
    wish_core_client_t* elt;
    uv_connect_t* tcp_req = NULL;
    
    DL_FOREACH(wish_core_clients, elt) {
        if (req == elt->connect_req) {
            tcp_req = elt->connect_req;
            break;
        }
    }
    
    if (tcp_req == NULL) {
        printf("echo_read: could not find the tcp_req!\n");
        return;
    }
    
    //printf("echo_read: Found the correct tcp_req %p and app %p\n", tcp_req, elt->app);
    
    
    // register the handler
    elt->tcp_stream = req->handle;
    
    //printf("Connected to code. rq set to %p\n", rq);
    
    uv_buf_t buf = uv_buf_init(app_login_header, sizeof (app_login_header));
    buf.len = 3;
    
    uv_write_t* write_req = malloc(sizeof(uv_write_t));

    int buf_count = 1;
    uv_write(write_req, elt->tcp_stream, &buf, buf_count, on_write_end);
    uv_read_start(elt->tcp_stream, alloc_buffer, echo_read);
    
    free(req);
    /* Note: call to wish_app_login is hidden inside wish_app_connected() */
    wish_app_connected(elt->app, true);
}

static void identity_list_cb(rpc_client_req* req, void *ctx, uint8_t *payload, size_t payload_len) {
    printf("response to identity_list request: wish_app_core %i", (int)payload_len);
    bson_visit(payload, elem_visitor);
}
/*
static void identity_list() {
    int len = 300;
    uint8_t buf[len];
    bson bs; 
    bson_init_buffer(&bs, buf, len);
    bson_append_start_array(&bs, "args");
    bson_append_bool(&bs, "0", true);
    bson_append_string(&bs, "1", "complex");
    bson_append_int(&bs, "2", 2);
    bson_append_start_object(&bs, "3");
    bson_append_string(&bs, "complex", "trem");
    bson_append_finish_object(&bs);
    bson_append_finish_array(&bs);
    bson_finish(&bs);
    
    wish_app_core(app, "identity.list", (char*)bson_data(&bs), bson_size(&bs), identity_list_cb);
}
*/

static void periodic(uv_timer_t* handle) {
    
    wish_core_client_t* elt;
    uv_timer_t* timeout = NULL;
    
    DL_FOREACH(wish_core_clients, elt) {
        if (handle == elt->timeout) {
            timeout = elt->timeout;
            break;
        }
    }
    
    if (timeout != NULL) {
        //printf("echo_read: Found the correct tcp_req %p and app %p\n", timeout, elt->app);
        wish_app_periodic(elt->app);
    } else {
        printf("echo_read: could not find the tcp_req!\n");
        return;
    }
    
    //printf("Try consuming data from above.\n");

    
    //identity_list();
    /*
    bson bs;
    bson_init(&bs);
    bson_append_bool(&bs, "ready", true);
    bson_finish(&bs);
    
    send_app_to_core("asd", bs.data, bson_size(&bs));
    */
    
    //identity_list();
    //mist_follow_task();
}

void wish_core_client_init(wish_app_t *wish_app) {
    // Initialize wish_platform functions
    wish_platform_set_malloc(malloc);
    wish_platform_set_realloc(realloc);
    wish_platform_set_free(free);
    srandom(time(NULL));
    wish_platform_set_rng(random);
    wish_platform_set_vprintf(vprintf);
    wish_platform_set_vsprintf(vsprintf);    
    
    /* File system functions are needed for Mist mappings! */
    wish_fs_set_open(my_fs_open);
    wish_fs_set_read(my_fs_read);
    wish_fs_set_write(my_fs_write);
    wish_fs_set_lseek(my_fs_lseek);
    wish_fs_set_close(my_fs_close);
    wish_fs_set_rename(my_fs_rename);
    wish_fs_set_remove(my_fs_remove);
    
    wish_core_client_t* client = wish_platform_malloc(sizeof(wish_core_client_t));
    
    printf("Appeding wish_core_client.\n");
    DL_APPEND(wish_core_clients, client);
    
    client->app = wish_app;
    
    int len = 60*1024;
    char* inbuf = wish_platform_malloc(len);
    client->rb = wish_platform_malloc(sizeof(ring_buffer_t));
    ring_buffer_init(client->rb, inbuf, len);

    // Initialize libuv loop
    client->loop = wish_platform_malloc(sizeof(uv_loop_t));
    uv_loop_init(client->loop);

    // Initialize the core tcp connection
    client->tcp = wish_platform_malloc(sizeof(uv_tcp_t));
    uv_tcp_init(client->loop, client->tcp);

    struct sockaddr_in req_addr;
    if (client->app->port != 0) {
        printf("got a port %d\n", client->app->port);
        uv_ip4_addr("127.0.0.1", client->app->port, &req_addr);
    } else {
        //printf("using default port\n");
        uv_ip4_addr("127.0.0.1", 9094, &req_addr);
    }

    client->connect_req = wish_platform_malloc(sizeof(uv_connect_t));
    memset(client->connect_req, 0, sizeof(uv_connect_t));

    uv_tcp_connect(client->connect_req, client->tcp, (const struct sockaddr*) &req_addr, on_connect);

    client->timeout = wish_platform_malloc(sizeof(uv_timer_t));
    
    // setup periodic for mist_follow_task()
    uv_timer_init(client->loop, client->timeout);

    uv_timer_start(client->timeout, periodic, 100, 50);
    
    uv_run(client->loop, UV_RUN_DEFAULT);
    printf("This loop is now terminated. App: %p\n", client->app);
    wish_platform_free(client);
}

void wish_core_client_close(wish_core_client_t* client) {
    if (client->loop != NULL) {
        //printf("Stopping loop.\n");
        //uv_loop_close(loop);
        uv_stop(client->loop);
    } else {
        //printf("NOT stopping loop.\n");
    }
}
