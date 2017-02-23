#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "wish_core.h"
#include "wish_identity.h"

#define WISH_RELATIONSHIP_DB_LEN 10
    
typedef struct wish_relationship_t {
    // quarantined, active, undecided, none
    // quality
    // 
} wish_relationship_t;

typedef struct wish_relationship_req {
    uint8_t luid[WISH_UID_LEN];
    wish_identity_t id;
} wish_relationship_req_t;

void wish_relationship_init(wish_core_t* core);

void wish_relationship_destroy(wish_core_t* core);

void wish_relationship_req_add(wish_core_t* core, wish_relationship_req_t* req);

#ifdef __cplusplus
}
#endif
