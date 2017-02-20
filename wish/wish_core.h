#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define WISH_CONTEXT_POOL_SZ (WISH_PORT_CONTEXT_POOL_SZ)

#define WISH_MAX_SERVICES 5 /* contrast with NUM_WISH_APPS due to be removed in wish_app.h */

#include "wish_port_config.h"
#include "wish_rpc.h"
#include "wish_app.h"

struct wish_service_entry {
    uint8_t wsid[WISH_WSID_LEN];
    char service_name[WISH_APP_NAME_MAX_LEN];
    uint8_t protocols[WISH_PROTOCOL_NAME_MAX_LEN][WISH_APP_MAX_PROTOCOLS]; 
    //uint8_t permissions[WISH_PERMISSION_NAME_MAX_LEN][WISH_APP_MAX_PERMISSIONS];
};

typedef struct {
    uint8_t uid[WISH_ID_LEN];
} wish_uid_list_elem_t;

typedef uint32_t wish_time_t;

typedef int wish_connection_id_t;

struct wish_context;

typedef struct wish_core {
    uint16_t wish_server_port;
    
    int num_ids;
    int loaded_num_ids;
    wish_uid_list_elem_t uid_list[WISH_PORT_MAX_UIDS];
    
    #ifdef WISH_RPC_SERVER_STATIC_REQUEST_POOL
    #define REQUEST_POOL_SIZE (3*WISH_CONTEXT_POOL_SZ)
    struct wish_rpc_context_list_elem request_pool[REQUEST_POOL_SIZE];
    #endif

    wish_rpc_server_t* core_rpc_server;
    wish_rpc_server_t* core_app_rpc_server;
    
    // moved from wish_service_registry.c
    struct wish_service_entry service_registry[WISH_MAX_SERVICES];
    
    wish_rpc_client_t* core_rpc_client;
    
    /* The number of seconds since core startup is stored here */
    wish_time_t core_time;

    /* Statically allocate some resources */
    struct wish_context* wish_context_pool;
    wish_connection_id_t next_conn_id;
    
} wish_core_t;

int wish_core_update_identities(wish_core_t* core);

#ifdef __cplusplus
}
#endif
