#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define WISH_CONTEXT_POOL_SZ (WISH_PORT_CONTEXT_POOL_SZ)

#define WISH_MAX_SERVICES 5 /* contrast with NUM_WISH_APPS due to be removed in wish_app.h */

#include "wish_return.h"
#include "stdint.h"
#include "stdbool.h"
    
#include "wish_port_config.h"
#include "wish_rpc.h"
#include "wish_app.h"
#include "bson.h"

typedef struct {
    uint8_t name[WISH_PROTOCOL_NAME_MAX_LEN];
} wish_protocol_t;
    
typedef struct wish_service_entry {
    uint8_t wsid[WISH_WSID_LEN];
    char name[WISH_APP_NAME_MAX_LEN];
    wish_protocol_t protocols[WISH_APP_MAX_PROTOCOLS]; 
    //uint8_t permissions[WISH_PERMISSION_NAME_MAX_LEN][WISH_APP_MAX_PERMISSIONS];
} wish_app_entry_t;

typedef struct {
    uint8_t uid[WISH_ID_LEN];
} wish_uid_list_elem_t;

struct wish_core;

typedef uint32_t wish_time_t;
typedef struct wish_timer_db {
    void (*cb)(struct wish_core* core, void* ctx);
    void *cb_ctx;
    wish_time_t time;
    wish_time_t interval;
    bool singleShot;
    struct wish_timer_db* next;
} wish_timer_db_t;

typedef int wish_connection_id_t;

typedef enum wish_discovery_type {
    LocalDiscovery, RemoteFriendRequest, FriendRecommendation
} wish_discovery_type_t;

/*
typedef struct {
    wish_identity_t id;
    wish_discovery_type_t discovery_type;
    bson* meta;
} wish_relationship_t;

typedef struct wish_claim_t {
    uint8_t* signature;
    bson* document;
} wish_claim_t;
*/

struct wish_context;
struct wish_ldiscover_t;
struct wish_relationship_t;
struct wish_relay_client_ctx;

typedef struct wish_core {
    /* Configurations */
    bool config_skip_connection_acl;
    bool config_skip_service_acl;
    
    uint8_t id[WISH_WHID_LEN];
    
    /* TCP Server */
    uint16_t wish_server_port;
    
    /* Identities */
    int num_ids;
    int loaded_num_ids;
    wish_uid_list_elem_t uid_list[WISH_PORT_MAX_UIDS];
    
    /* RPC Servers */
    #ifdef WISH_RPC_SERVER_STATIC_REQUEST_POOL
    #define REQUEST_POOL_SIZE (3*WISH_CONTEXT_POOL_SZ)
    struct wish_rpc_context_list_elem request_pool[REQUEST_POOL_SIZE];
    #endif

    wish_rpc_server_t* core_rpc_server;
    wish_rpc_server_t* core_app_rpc_server;
    
    /* Services */
    struct wish_service_entry* service_registry;
    
    wish_rpc_client_t* core_rpc_client;
    
    /* The number of seconds since core startup is stored here */
    wish_time_t core_time;
    wish_timer_db_t* time_db;

    /* Connections */
    struct wish_context* wish_context_pool;
    wish_connection_id_t next_conn_id;
    
    /* Instantiate Relay client to a server with specied IP addr and port */
    struct wish_relay_client_ctx* relay_db;

    /* Local discovery */
    bool ldiscover_allowed;
    struct wish_ldiscover_t* ldiscovery_db;
    
    /* Relationship management */
    struct wish_relationship_req_t* relationship_req_db;
    struct wish_relationship_t* relationship_db;
    
} wish_core_t;

int wish_core_update_identities(wish_core_t* core);

#ifdef __cplusplus
}
#endif
