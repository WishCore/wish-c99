#include "wish_relationship.h"
#include "wish_core.h"
#include "wish_platform.h"
#include "string.h"
#include "wish_debug.h"
#include "utlist.h"

void wish_relationship_init(wish_core_t* core) {
    core->relationship_db = wish_platform_malloc(sizeof(wish_relationship_t) * WISH_RELATIONSHIP_DB_LEN);
}

void wish_relationship_destroy(wish_core_t* core) {
    wish_platform_free(core->relationship_db);
}

void wish_relationship_req_add(wish_core_t* core, wish_relationship_req_t* req) {
    WISHDEBUG(LOG_CRITICAL, "We should add a friend req from %s", req->id.alias);
    
    wish_relationship_req_t* rel = wish_platform_malloc(sizeof(wish_relationship_req_t));
    memcpy(rel, req, sizeof(wish_relationship_req_t));
    
    DL_APPEND(core->relationship_req_db, rel);
}

