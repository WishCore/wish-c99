#include "wish_acl.h"
#include "utlist.h"
#include "wish_platform.h"
#include "string.h"

void wish_acl_init(wish_core_t* core) {
    int size = sizeof(wish_acl_t);
    core->acl = wish_platform_malloc(size);
    memset(core->acl, 0, size);
}

/*
 * args: 'resource, permission, user'
 *   //     alice@host/service?mist#model.battery read bob@host/service
 *   //     alice@host/service?mist#model.battery.status read bob@host/service
 *   //     alice@host/service?mist#model.battery.status read bob@host/service
 *   //     alice@localhost/requestingService
 */
void wish_api_acl_check(rpc_server_req* req, const uint8_t* args) {
    wish_core_t* core = req->server->context;
    wish_app_entry_t* app = req->context;
    
    rpc_server_error_msg(req, 600, "Not implemented.");
}

/* args: 'String(Hex) luid, String role, String resource, Object permission' */
void wish_api_acl_allow(rpc_server_req* req, const uint8_t* args) {
    wish_core_t* core = req->server->context;
    wish_app_entry_t* app = req->context;
    
    rpc_server_error_msg(req, 600, "Not implemented.");
}

/* args: 'String(Hex) luid, String role, String resource, Object permission' */
void wish_api_acl_remove_allow(rpc_server_req* req, const uint8_t* args) {
    wish_core_t* core = req->server->context;
    wish_app_entry_t* app = req->context;
    
    rpc_server_error_msg(req, 600, "Not implemented.");
}

/* args: 'Buffer(32) luid, String role' */
void wish_api_acl_add_user_roles(rpc_server_req* req, const uint8_t* args) {
    wish_core_t* core = req->server->context;
    wish_app_entry_t* app = req->context;
    
    wish_acl_role_t role;

    bson bs;
    bson_iterator it;
    bson_init_with_data(&bs, args);
    
    bson_find(&it, &bs, "0");
    if (bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) != WISH_UID_LEN) {
        rpc_server_error_msg(req, 501, "Expected luid to be Buffer(32).");
        return;
    }
    
    const char* uid = bson_iterator_bin_data(&it);
    
    bson_find(&it, &bs, "1");
    if (bson_iterator_type(&it) != BSON_STRING || bson_iterator_string_len(&it) >= ROLE_NAME_LEN) {
        rpc_server_error_msg(req, 501, "Expected role to be String(<64).");
        return;
    }
    
    const char* name = bson_iterator_string(&it);
    
    memcpy(role.uid, uid, WISH_UID_LEN);
    strncpy(role.name, name, ROLE_NAME_LEN);
    
    wish_acl_user_roles_add(core->acl, &role);
    
    rpc_server_error_msg(req, 600, "Not implemented.");
}

/* args: 'String(Hex) luid, String role, String resource, Object permission' */
void wish_api_acl_remove_user_roles(rpc_server_req* req, const uint8_t* args) {
    wish_core_t* core = req->server->context;
    wish_app_entry_t* app = req->context;
    
    rpc_server_error_msg(req, 600, "Not implemented.");
}

/* args: 'String(Hex) luid, String role, String resource, Object permission' */
void wish_api_acl_user_roles(rpc_server_req* req, const uint8_t* args) {
    wish_core_t* core = req->server->context;
    wish_app_entry_t* app = req->context;

    wish_acl_role_t* role;
    wish_acl_role_t* tmp;

    bson bs;
    bson_init(&bs);
    
    bson_append_start_array(&bs, "data");
    
    int i = 0;
    char index[21];
    
    HASH_ITER(hh, core->acl->role_db, role, tmp) {
        BSON_NUMSTR(index, i++);
        bson_append_start_object(&bs, index);
        bson_append_string(&bs, "role", role->name);
        bson_append_finish_object(&bs);
    }

    bson_append_finish_array(&bs);
    bson_finish(&bs);
    
    rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    bson_destroy(&bs);
}

/* args: 'String(Hex) luid, String role' */
void wish_api_acl_what_resources(rpc_server_req* req, const uint8_t* args) {
    wish_core_t* core = req->server->context;
    wish_app_entry_t* app = req->context;
    
    rpc_server_error_msg(req, 600, "Not implemented.");
}

/* args: 'resource, peer' */
void wish_api_acl_allowed_permissions(rpc_server_req* req, const uint8_t* args) {
    wish_core_t* core = req->server->context;
    wish_app_entry_t* app = req->context;
    
    rpc_server_error_msg(req, 600, "Not implemented.");
}
    

void wish_acl_user_roles_add(wish_acl_t* acl, const wish_acl_role_t* role) {
    if(acl == NULL) { return; }

    wish_acl_role_t* elt;
    
    HASH_FIND_INT(acl->role_db, &role->id, elt);  /* id already in the hash? */
    
    if (elt == NULL) {
        int size = sizeof(wish_acl_role_t);
        wish_acl_role_t* copy = wish_platform_malloc(size);
        memcpy(copy, role, size);
        
        HASH_ADD_INT(acl->role_db, id, copy);  /* id: name of key field */
    }
}
