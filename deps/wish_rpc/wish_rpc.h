#ifndef WISH_APP_RPC_H
#define WISH_APP_RPC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "bson.h"

/* A generic RPC client and server implementation */

typedef int32_t wish_rpc_id_t;

struct wish_rpc_server;

#define MAX_RPC_OP_LEN 32
#define MAX_RPC_SERVER_NAME_LEN 16
/* This defines the maximum length of an RPC error message */
#define WISH_RPC_ERR_MSG_MAX_LEN 256

typedef struct wish_rpc_context {
    struct wish_rpc_server* server;
    char op_str[MAX_RPC_OP_LEN];
    /* Request ID */
    int id;
    /** This field is for saving local service id, used in following situatons:
     *      -when handling a "core app" rpc to determine which service called 
     *      the RPC
     *      -in mist device app, the local service which is the destination of an incoming Mist RPC command is saved here so that the RPC handler can use it for determining which mist device is  the recipient of the RPC 
     */
    uint8_t *local_wsid;
    /* The originating wish context of the message, used in core rpc
     * server, send_op_handler(). */
    void *ctx;
    void *context; /* Pointer to the wanted context structure  */
    void (*send)(void*, uint8_t* data, int len);
    void* send_context;
    void (*end)(struct wish_rpc_context *rpc_ctx); /* if non-null this callback is called when a request is terminated */
} wish_rpc_ctx;

struct wish_rpc_entry;

typedef void (*rpc_client_callback)(struct wish_rpc_entry* req, void *ctx, uint8_t *payload, size_t payload_len);

struct wish_rpc_context_list_elem {
    wish_rpc_ctx request_ctx;
    struct wish_rpc_context_list_elem *next;
};

typedef void (*rpc_op_handler)(struct wish_rpc_context *rpc_ctx, uint8_t *args_array);

typedef struct wish_rpc_entry {
    wish_rpc_id_t id;
    rpc_client_callback cb;
    void* cb_context;
    rpc_client_callback passthru_cb;
    int passthru_id;
    void* passthru_ctx; // used for storing peer pointer in passthrough. This field should probably should be removed when introducing separate rpc_clients for each peer
    void* passthru_ctx2; // used for storing Mist pointer in nodejs addon
    struct wish_rpc_entry *next;
    bool err;
} rpc_client_req;

typedef struct wish_rpc_request {
    wish_rpc_id_t id;
    
    // context used for sending replies, is a: 
    //   - peer            in wish_app_protocol_rpc
    //   - remote host     in wish-core intercore RPC
    //   - wsid            in wish-core service RPC
    void* response_context;
    
    struct wish_rpc_entry *next;
} wish_rpc_req;

typedef struct {
    wish_rpc_id_t next_id;  // This is the ID that will be used in next req
    struct wish_rpc_entry *list_head;
    void (*send)(void* ctx, uint8_t* buffer, int buffer_len);
    void* send_ctx;
} wish_rpc_client_t;




/* This struct encapsulates a Wish RPC server op handler */
struct wish_rpc_server_handler {
    /* the operation that this handler handles */
    char op_str[MAX_RPC_OP_LEN];
    rpc_op_handler handler;
    struct wish_rpc_server_handler *next;
};

/* If WISH_RPC_SERVER_STATIC_REQUEST_POOL is defined, you must supply the RPC server with a statically allocated buffer for storing wish_rpc_ctx structures.
 You must also initialise wish_rpc_server_t.rpc_ctx_pool_num_slots accordingly. */
#define WISH_RPC_SERVER_STATIC_REQUEST_POOL

typedef struct wish_rpc_server {
    char server_name[MAX_RPC_SERVER_NAME_LEN];
    struct wish_rpc_server_handler *list_head;
    void * context;
    /* A list representing the requests that have arrived to the RPC server. Used in for example to emit 'sig' responses */
    struct wish_rpc_context_list_elem *request_list_head;
#ifdef WISH_RPC_SERVER_STATIC_REQUEST_POOL
    /* RPC contexts of incoming requests are stored to this pool */
    struct wish_rpc_context_list_elem *rpc_ctx_pool;
    /* The number of slots in the rpc_ctx_pool */
    int rpc_ctx_pool_num_slots;
#endif
} wish_rpc_server_t;

/** Server: Add a RPC handler */
void wish_rpc_server_add_handler(wish_rpc_server_t *s, 
        char *op_str, rpc_op_handler handler_fn);

void wish_rpc_server_register(wish_rpc_server_t *s, struct wish_rpc_server_handler* handler);

/* Handle an RPC request to an RPC server
 * Returns 0, if the request was valid, and 1 if there was no handler to
 * this "op" */
int wish_rpc_server_handle(wish_rpc_server_t *s, struct wish_rpc_context *wish_rcp_ctx, uint8_t *args_array);

void wish_rpc_server_end(wish_rpc_server_t *s, int end);

void wish_rpc_server_end_by_ctx(wish_rpc_server_t *s, void* ctx);

rpc_client_req* find_request_entry(wish_rpc_client_t *c, wish_rpc_id_t id);

rpc_client_req* find_passthrough_request_entry(wish_rpc_client_t *c, wish_rpc_id_t id);

wish_rpc_id_t wish_rpc_client(wish_rpc_client_t *c, char *op, uint8_t *args, size_t args_len, rpc_client_callback cb, uint8_t *buffer, size_t buffer_len);

wish_rpc_id_t wish_rpc_client_bson(wish_rpc_client_t *c, char *op, uint8_t *args, size_t args_len, rpc_client_callback cb, uint8_t *buffer, size_t buffer_len);

void wish_rpc_client_end_by_ctx(wish_rpc_client_t *c, void* ctx);

void wish_rpc_client_end_by_id(wish_rpc_client_t *c, int id);

void wish_rpc_client_set_cb_context(wish_rpc_client_t *c, int id, void* ctx);

int wish_rpc_passthru_context(wish_rpc_client_t* client, bson* bs, rpc_client_callback cb, void* ctx);

int wish_rpc_passthru(wish_rpc_client_t* client, bson* bs, rpc_client_callback cb);

int wish_rpc_passthru_req(wish_rpc_ctx* server_rpc_ctx, wish_rpc_client_t* client, bson* bs, rpc_client_callback cb);

int wish_rpc_server_send(struct wish_rpc_context *ctx, const uint8_t *response, size_t response_len);

int wish_rpc_server_emit(struct wish_rpc_context *ctx, const uint8_t *response, size_t response_len);

int wish_rpc_server_error(struct wish_rpc_context *ctx, int code, const uint8_t *msg);

wish_rpc_ctx* wish_rpc_server_req_by_id(wish_rpc_server_t* s, int id);

void wish_rpc_server_emit_broadcast(wish_rpc_server_t* s, char* op, const uint8_t *response, size_t response_len);

void wish_rpc_server_delete_rpc_ctx(struct wish_rpc_context *rpc_ctx);

int wish_rpc_client_handle_res(wish_rpc_client_t *c, void *ctx, uint8_t *data, size_t len);

struct wish_rpc_context_list_elem *wish_rpc_server_get_free_rpc_ctx_elem(wish_rpc_server_t *s);

void wish_rpc_server_print(wish_rpc_server_t *s);

#ifdef __cplusplus
}
#endif

#endif  /* WISH_APP_RPC_H */
