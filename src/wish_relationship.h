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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "wish_core.h"
#include "wish_identity.h"
#include "wish_rpc.h"

#define WISH_RELATIONSHIP_DB_LEN 10
    
typedef struct wish_relationship_t {
    // quarantined, active, undecided, none
    // quality
    // 
} wish_relationship_t;

typedef struct wish_relationship_req_t {
    uint8_t luid[WISH_UID_LEN];
    wish_identity_t id;
    const char* signed_meta;
    struct wish_relationship_req_t* prev;
    struct wish_relationship_req_t* next;
    /* A a copy of the RPC request structure representing the friend request sent by the remote core */
    rpc_server_req friend_rpc_req;
} wish_relationship_req_t;

void wish_relationship_init(wish_core_t* core);

void wish_relationship_destroy(wish_core_t* core);

void wish_relationship_req_add(wish_core_t* core, wish_relationship_req_t* req);

#ifdef __cplusplus
}
#endif
