#ifndef MIST_API_H
#define MIST_API_H

#ifdef __cplusplus
extern "C" {
#endif

#include "wish_app.h"
#include "mist_app.h"
#include "wish_rpc.h"
#include "bson.h"
#include "sandbox.h"

#define MIST_API_REQUEST_POOL_SIZE 40
    
    struct mist_api_context;
    
    typedef void (*mist_api_periodic_cb)(void* ctx);

    typedef struct mist_api_context {
        wish_app_t* wish_app;
        mist_app_t* mist_app;
        mist_api_periodic_cb periodic;
        void* periodic_ctx;
        // sandbox for 3-rd party access to api
        sandbox_t* sandbox_db;

        wish_rpc_client_t client;
        wish_rpc_server_t server;
        struct wish_rpc_context_list_elem request_pool[MIST_API_REQUEST_POOL_SIZE];
        struct mist_api_context* next;
        struct mist_api_context* prev;
    } mist_api_t;
    
    mist_api_t* mist_api_init(mist_app_t* mist_app);
    
    int wish_api_request_context(mist_api_t* mist_api, bson* bs, rpc_client_callback cb, void* ctx);

    int wish_api_request(mist_api_t* mist_api, bson* bs, rpc_client_callback cb);

    void wish_api_request_cancel(mist_api_t* mist_api, int id);

    int mist_api_request_context(mist_api_t* mist_api, bson* bs, rpc_client_callback cb, void* cb_ctx);
    
    int mist_api_request(mist_api_t* mist_api, bson* bs, rpc_client_callback cb);
    
    void mist_api_request_cancel(mist_api_t* mist_api, int id);
    
    int sandboxed_api_request_context(mist_api_t* mist_api, const char* sandbox_id, bson* req, rpc_client_callback cb, void* cb_ctx);

    void sandboxed_api_request_cancel(mist_api_t* mist_api, const char* sandbox_id, int id);

#ifdef __cplusplus
}
#endif

#endif /* MIST_API_H */

