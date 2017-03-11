#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "stdint.h"
#include "uthash.h"
#include "wish_identity.h"

#define ROLE_NAME_LEN (64)
#define USER_NAME_LEN (32)
    
typedef struct wish_directory_entry {
    char name[ROLE_NAME_LEN];
    char uid[WISH_UID_LEN];
} wish_directory_entry_t;

typedef struct wish_directory {
    char title[4];
} wish_directory_t;
    
#include "wish_core.h"
    
    /* Directory API */
    
    void wish_api_directory_find(rpc_server_req* req, uint8_t* args);
    
    /* Acl internals */
    
    void wish_directory_init(wish_core_t* core);
    
#ifdef __cplusplus
}
#endif
