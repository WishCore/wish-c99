#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "stdint.h"
#include "uthash.h"
#include "wish_identity.h"

#define ROLE_NAME_LEN (64)
#define USER_NAME_LEN (32)
    
typedef struct wish_acl_role_t {
    char name[ROLE_NAME_LEN];
    char uid[WISH_UID_LEN];
    int id;                    /* key */
    UT_hash_handle hh;         /* makes this structure hashable */
} wish_acl_role_t;
    
typedef struct wish_acl_user_t {
    char name[USER_NAME_LEN];
    struct wish_acl_user_t* next;
} wish_acl_user_t;
    
typedef struct {
    wish_acl_role_t* role;
    uint8_t* permission;
} wish_acl_permission_t;
    
typedef struct wish_acl {
    wish_acl_role_t* role_db;
    wish_acl_user_t* user_db;
    wish_acl_permission_t* permissions_db;
} wish_acl_t;
    
#include "wish_core.h"
    
    /* Acl API */
    
    void wish_api_acl_check(rpc_server_req* req, uint8_t* args);
    
    void wish_api_acl_allow(rpc_server_req* req, uint8_t* args);
    
    void wish_api_acl_remove_allow(rpc_server_req* req, uint8_t* args);
    
    void wish_api_acl_add_user_roles(rpc_server_req* req, uint8_t* args);
    
    void wish_api_acl_remove_user_roles(rpc_server_req* req, uint8_t* args);
    
    void wish_api_acl_user_roles(rpc_server_req* req, uint8_t* args);
    
    void wish_api_acl_what_resources(rpc_server_req* req, uint8_t* args);
    
    void wish_api_acl_allowed_permissions(rpc_server_req* req, uint8_t* args);

    /* Acl internals */
    
    void wish_acl_init(wish_core_t* core);
    
    void wish_acl_user_roles_add(wish_acl_t* acl, const wish_acl_role_t* role);
    
#ifdef __cplusplus
}
#endif
