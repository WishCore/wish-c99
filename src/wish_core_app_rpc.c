#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "wish_rpc.h"
#include "wish_utils.h"
#include "wish_version.h"
#include "wish_identity.h"
#include "wish_event.h"
#include "wish_core_signals.h"
#include "wish_io.h"
#include "wish_core_app_rpc.h"
#include "wish_core.h"

#include "wish_acl.h"
#include "wish_api_identity.h"
#include "wish_api_connections.h"
#include "wish_api_services.h"
#include "wish_directory.h"
#include "wish_api_relay.h"
#include "wish_api_wld.h"

#include "wish_service_registry.h"
#include "core_service_ipc.h"
#include "wish_local_discovery.h"
#include "wish_connection_mgr.h"
#include "wish_dispatcher.h"
#include "ed25519.h"
#include "bson.h"
#include "bson_visit.h"
#include "utlist.h"

#include "mbedtls/sha256.h"

#include "stdlib.h"

#include "wish_debug.h"
#include "wish_port_config.h"
#include "wish_relationship.h"

typedef struct wish_rpc_server_handler handler;

/* 
 * Enumerate available methods in RPC
 */
static void methods(rpc_server_req* req, const uint8_t* args) {
    wish_core_t* core = (wish_core_t*) req->server->context;
    
    handler *h = core->app_api->list_head;
    
    bson bs; 
    bson_init(&bs);
    bson_append_start_object(&bs, "data");
    
    while (h != NULL) {
        bson_append_start_object(&bs, h->op_str);
        if (h->args) { bson_append_string(&bs, "args", h->args); }
        if (h->doc) { bson_append_string(&bs, "doc", h->doc); }
        bson_append_finish_object(&bs);

        h = h->next;
    }
    
    bson_append_finish_object(&bs);
    bson_finish(&bs);
    
    wish_rpc_server_send(req, bs.data, bson_size(&bs));
    bson_destroy(&bs);
}

/*
 * Return core version string  
 * 
 * Example return values:
 * 
 *   v0.6.8-alpha-37-g85643-dirty
 *   v0.6.8-alpha-37-g85643
 *   v0.6.8
 */
static void version(rpc_server_req* req, const uint8_t* args) {
    
    bson bs; 
    bson_init(&bs);
    bson_append_string(&bs, "data", WISH_CORE_VERSION_STRING);
    bson_finish(&bs);
    
    wish_rpc_server_send(req, bs.data, bson_size(&bs));
    bson_destroy(&bs);
}

static void host_config(rpc_server_req* req, const uint8_t* args) {
    int buffer_len = WISH_PORT_RPC_BUFFER_SZ;
    uint8_t buffer[buffer_len];
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_start_object(&bs, "data");
    // FIXME version is shown in the separate version rpc command, consider removing this
    bson_append_string(&bs, "version", WISH_CORE_VERSION_STRING);
    bson_append_finish_object(&bs);
    bson_finish(&bs);

    if (bs.err) {
        wish_rpc_server_error_msg(req, 305, "Failed writing bson.");
        return;
    }
    
    wish_rpc_server_send(req, bson_data(&bs), bson_size(&bs));
}

handler methods_h =                                   { .op_str = "methods",                           .handler = methods, .args = "(void): string" };
handler signals_h =                                   { .op_str = "signals",                           .handler = wish_core_signals, .args = "(filter?: string): Signal" };
handler version_h =                                   { .op_str = "version",                           .handler = version, .args = "(void): string", .doc = "Returns core version." };

handler services_send_h =                             { .op_str = "services.send",                     .handler = wish_api_services_send, .args = "(peer: Peer, payload: Buffer): bool", .doc = "Send payload to peer." };
handler services_list_h =                             { .op_str = "services.list",                     .handler = wish_api_services_list, .args = "(void): Service[]", .doc = "List local services." };

handler identity_list_h =                             { .op_str = "identity.list",                     .handler = wish_api_identity_list, .args="(void): Identity[]" };
handler identity_export_h =                           { .op_str = "identity.export",                   .handler = wish_api_identity_export, .args="(void): Document" };
handler identity_import_h =                           { .op_str = "identity.import",                   .handler = wish_api_identity_import, .args="(identity: Document): Identity" };
handler identity_create_h =                           { .op_str = "identity.create",                   .handler = wish_api_identity_create, .args="(alias: string): Identity" };
handler identity_get_h =                              { .op_str = "identity.get",                      .handler = wish_api_identity_get, .args="(uid: Uid): Identity" };
handler identity_remove_h =                           { .op_str = "identity.remove",                   .handler = wish_api_identity_remove, .args="(uid: Uid): bool" };

handler identity_sign_h =                             { .op_str = "identity.sign",                     .handler = wish_api_identity_sign, .args="(uid: Uid, document: Document, claim: Buffer): Document" };
handler identity_verify_h =                           { .op_str = "identity.verify",                   .handler = wish_api_identity_verify, .args = "(document: Document): Document" };
handler identity_friend_request_h =                   { .op_str = "identity.friendRequest",            .handler = wish_api_identity_friend_request, .args = "(luid: Uid, contact: Contact): bool" };
handler identity_friend_request_list_h =              { .op_str = "identity.friendRequestList",        .handler = wish_api_identity_friend_request_list, .args = "(void): FriendRequest[]" };
handler identity_friend_request_accept_h =            { .op_str = "identity.friendRequestAccept",      .handler = wish_api_identity_friend_request_accept, .args = "(luid: Uid, ruid: Uid): bool" };
handler identity_friend_request_decline_h =           { .op_str = "identity.friendRequestDecline",     .handler = wish_api_identity_friend_request_decline, .args = "(luid: Uid, ruid: Uid): bool" };

handler connections_list_h =                          { .op_str = "connections.list",                  .handler = wish_api_connections_list, .args = "(void): Connection[]" };
handler connections_request_h =                       { .op_str = "connections.request",               .handler = wish_api_connections_request, .args = "(host: Host, op: string, args: array): Response" };
handler connections_disconnect_h =                    { .op_str = "connections.disconnect",            .handler = wish_api_connections_disconnect, .args = "(id: number): bool" };
handler connections_check_connections_h =             { .op_str = "connections.checkConnections",      .handler = wish_api_connections_check_connections, .args = "(id: number): bool" };

handler directory_find_h =                            { .op_str = "directory.find",                    .handler = wish_api_directory_find, .args = "(filter?: string): DirectoryEntry" };

handler api_acl_check_h =                             { .op_str = "acl.check",                         .handler = wish_api_acl_check };
handler api_acl_allow_h =                             { .op_str = "acl.allow",                         .handler = wish_api_acl_allow };
handler api_acl_remove_allow_h =                      { .op_str = "acl.removeAllow",                   .handler = wish_api_acl_remove_allow };
handler api_acl_add_user_roles_h =                    { .op_str = "acl.addUserRoles",                  .handler = wish_api_acl_add_user_roles };
handler api_acl_remove_user_roles_h =                 { .op_str = "acl.removeUserRoles",               .handler = wish_api_acl_remove_user_roles };
handler api_acl_user_roles_h =                        { .op_str = "acl.userRoles",                     .handler = wish_api_acl_user_roles };
handler api_acl_what_resources_h =                    { .op_str = "acl.whatResources",                 .handler = wish_api_acl_what_resources };
handler api_acl_allowed_permissions_h =               { .op_str = "acl.allowedPermissions",            .handler = wish_api_acl_allowed_permissions };
        
handler relay_list_h =                                { .op_str = "relay.list",                        .handler = wish_api_relay_list, .args = "(void): Relay[]" };
handler relay_add_h =                                 { .op_str = "relay.add",                         .handler = wish_api_relay_add, .args = "(relay: string): bool" };
handler relay_remove_h =                              { .op_str = "relay.remove",                      .handler = wish_api_relay_remove, .args = "(relay: string): bool" };

handler wld_list_h =                                  { .op_str = "wld.list",                          .handler = wish_api_wld_list, .args = "(void): Identity[]" };
handler wld_clear_h =                                 { .op_str = "wld.clear",                         .handler = wish_api_wld_clear, .args = "(void): bool" };
handler wld_announce_h =                              { .op_str = "wld.announce",                      .handler = wish_api_wld_announce, .args = "(void): bool" };
handler wld_friend_request_h =                        { .op_str = "wld.friendRequest",                 .handler = wish_api_wld_friend_request, .args = "(luid: Uid, ruid: Uid, rhid: Hid): bool" };

handler host_config_h =                               { .op_str = "host.config",                       .handler = host_config };

static void wish_core_app_rpc_send(rpc_server_req* req, const bson* bs) {
    wish_core_t* core = (wish_core_t*) req->server->context;
    wish_app_entry_t* app = (wish_app_entry_t*) req->context;
    uint8_t* wsid = app->wsid;
    
    //WISHDEBUG(LOG_CRITICAL, "wish_core_app_rpc_send app name: %s", app->name);
    //bson_visit("wish_core_app_rpc_send:", bson_data(bs));
    
    send_core_to_app(core, wsid, bson_data(bs), bson_size(bs));
}

/**
 * Init the Core App RPC
 * 
 * @param core
 */
void wish_core_app_rpc_init(wish_core_t* core) {
    core->app_api = wish_rpc_server_init_size(core, wish_core_app_rpc_send, WISH_PORT_APP_RPC_POOL_SZ);
    wish_rpc_server_set_name(core->app_api, "core-from-app");
    
    wish_rpc_server_register(core->app_api, &methods_h);
    wish_rpc_server_register(core->app_api, &signals_h);
    wish_rpc_server_register(core->app_api, &version_h);
    
    wish_rpc_server_register(core->app_api, &services_send_h);
    wish_rpc_server_register(core->app_api, &services_list_h);
    
    wish_rpc_server_register(core->app_api, &identity_list_h);
    wish_rpc_server_register(core->app_api, &identity_create_h);
    wish_rpc_server_register(core->app_api, &identity_export_h);
    wish_rpc_server_register(core->app_api, &identity_import_h);
    wish_rpc_server_register(core->app_api, &identity_get_h);
    wish_rpc_server_register(core->app_api, &identity_remove_h);
    wish_rpc_server_register(core->app_api, &identity_sign_h);
    wish_rpc_server_register(core->app_api, &identity_verify_h);
    wish_rpc_server_register(core->app_api, &identity_friend_request_h);
    wish_rpc_server_register(core->app_api, &identity_friend_request_list_h);
    wish_rpc_server_register(core->app_api, &identity_friend_request_accept_h);
    wish_rpc_server_register(core->app_api, &identity_friend_request_decline_h);
    wish_rpc_server_register(core->app_api, &directory_find_h);
    
    wish_rpc_server_register(core->app_api, &connections_list_h);
    wish_rpc_server_register(core->app_api, &connections_request_h);
    wish_rpc_server_register(core->app_api, &connections_disconnect_h);
    wish_rpc_server_register(core->app_api, &connections_check_connections_h);

    wish_rpc_server_register(core->app_api, &api_acl_check_h);
    wish_rpc_server_register(core->app_api, &api_acl_allow_h);
    wish_rpc_server_register(core->app_api, &api_acl_remove_allow_h);
    wish_rpc_server_register(core->app_api, &api_acl_add_user_roles_h);
    wish_rpc_server_register(core->app_api, &api_acl_remove_user_roles_h);
    wish_rpc_server_register(core->app_api, &api_acl_user_roles_h);
    wish_rpc_server_register(core->app_api, &api_acl_what_resources_h);
    wish_rpc_server_register(core->app_api, &api_acl_allowed_permissions_h);

    wish_rpc_server_register(core->app_api, &relay_list_h);
    wish_rpc_server_register(core->app_api, &relay_add_h);
    wish_rpc_server_register(core->app_api, &relay_remove_h);
    
    wish_rpc_server_register(core->app_api, &wld_list_h);
    wish_rpc_server_register(core->app_api, &wld_clear_h);
    wish_rpc_server_register(core->app_api, &wld_announce_h);
    wish_rpc_server_register(core->app_api, &wld_friend_request_h);
    
    wish_rpc_server_register(core->app_api, &host_config_h);
}

void wish_core_app_rpc_handle_req(wish_core_t* core, const uint8_t src_wsid[WISH_ID_LEN], const uint8_t *data) {
    wish_app_entry_t* app = wish_service_get_entry(core, src_wsid);

    if (app==NULL) {
        // failed to find app, deny service
        bson_visit("wish_core_app_rpc_handle_req: DENY from unknown service", data);
        return;
    }
    
    bson bs;
    bson_init_with_data(&bs, data);
    
    wish_rpc_server_receive(core->app_api, NULL, app, &bs);
}

// Move implementation to wish-rpc-c99, just call it from here
void wish_core_app_rpc_cleanup_requests(wish_core_t* core, struct wish_service_entry *service_entry_offline) {
    //WISHDEBUG(LOG_CRITICAL, "App rpc server clean up starting");
    struct wish_rpc_context_list_elem *list_elem = NULL;
    struct wish_rpc_context_list_elem *tmp = NULL;
    LL_FOREACH_SAFE(core->app_api->request_list_head, list_elem, tmp) {
        if (list_elem->request_ctx.context == service_entry_offline) {
            //WISHDEBUG(LOG_CRITICAL, "App rpc server clean up: request op %s", list_elem->request_ctx.op_str);
#ifdef WISH_RPC_SERVER_STATIC_REQUEST_POOL
            memset(&(list_elem->request_ctx), 0, sizeof(rpc_server_req));
#else
#error not implemented
            //wish_platform_free....
#endif
            LL_DELETE(core->app_api->request_list_head, list_elem);
        }
    }
}

void wish_send_peer_update_locals(wish_core_t* core, const uint8_t* sid, struct wish_service_entry *service_entry, bool online) {
    //WISHDEBUG(LOG_CRITICAL, "In update locals");
    
    if (memcmp(sid, service_entry->wsid, WISH_ID_LEN) == 0) {
        /* Don't send any peer online/offline messages regarding service itself */
        return;
    }
    
    wish_uid_list_elem_t local_id_list[WISH_NUM_LOCAL_IDS];
    int num_local_ids = wish_get_local_identity_list(local_id_list, WISH_NUM_LOCAL_IDS);
    if (num_local_ids == 0) {
        WISHDEBUG(LOG_CRITICAL, "Unexpected: no local identities");
        return;
    } else {
        WISHDEBUG(LOG_DEBUG, "Local id list: %i", num_local_ids);
    }
    
    uint8_t local_hostid[WISH_WHID_LEN];
    wish_core_get_host_id(core, local_hostid);
            
            
    int i = 0;
    int j = 0;
    for (i = 0; i < num_local_ids; i++) {
        for (j = 0; j < num_local_ids; j++) {
            bson bs;
            int buffer_len = 2 * WISH_ID_LEN + WISH_WSID_LEN + WISH_WHID_LEN + WISH_PROTOCOL_NAME_MAX_LEN + 200;
            uint8_t buffer[buffer_len];
            bson_init_buffer(&bs, buffer, buffer_len);
            
            bson_append_string(&bs, "type", "peer");
            bson_append_start_object(&bs, "peer");
            bson_append_binary(&bs, "luid", (uint8_t*) local_id_list[i].uid, WISH_ID_LEN);
            bson_append_binary(&bs, "ruid", (uint8_t*) local_id_list[j].uid, WISH_ID_LEN);
            bson_append_binary(&bs, "rsid", (uint8_t*) service_entry->wsid, WISH_WSID_LEN);
            bson_append_binary(&bs, "rhid", (uint8_t*) local_hostid, WISH_ID_LEN);
            /* FIXME support more protocols than just one */
            bson_append_string(&bs, "protocol", service_entry->protocols[0].name);   
            bson_append_string(&bs, "type", "N");
            bson_append_bool(&bs, "online", online);
            bson_append_finish_object(&bs);
           
            bson_finish(&bs);
            if (bs.err) {
                WISHDEBUG(LOG_CRITICAL, "BSON error when creating peer message: %i %s len %i", bs.err, bs.errstr, bs.dataSize);
            }
            else {
                //WISHDEBUG(LOG_CRITICAL, "wish_core_app_rpc_func: wish_send_peer_update_locals: online");
                send_core_to_app(core, sid, (uint8_t *) bson_data(&bs), bson_size(&bs));
            }
        }
    }
}
