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
#include "wish_connection.h"
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
    
    handler *h = core->app_api->handlers;
    
    bson bs; 
    bson_init(&bs);
    bson_append_start_object(&bs, "data");
    
    while (h != NULL) {
        bson_append_start_object(&bs, h->op);
        if (h->args) { bson_append_string(&bs, "args", h->args); }
        if (h->doc) { bson_append_string(&bs, "doc", h->doc); }
        bson_append_finish_object(&bs);

        h = h->next;
    }
    
    bson_append_finish_object(&bs);
    bson_finish(&bs);
    
    rpc_server_send(req, bs.data, bson_size(&bs));
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
    
    rpc_server_send(req, bs.data, bson_size(&bs));
    bson_destroy(&bs);
}

static void host_config(rpc_server_req* req, const uint8_t* args) {
    wish_core_t* core = (wish_core_t*) req->server->context;
    
    int buffer_len = WISH_PORT_RPC_BUFFER_SZ;
    uint8_t buffer[buffer_len];
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_start_object(&bs, "data");
    // FIXME version is shown in the separate version rpc command, consider removing this
    bson_append_string(&bs, "version", WISH_CORE_VERSION_STRING);
    bson_append_binary(&bs, "hid", core->id, WISH_WHID_LEN);
    bson_append_finish_object(&bs);
    bson_finish(&bs);

    if (bs.err) {
        rpc_server_error_msg(req, 305, "Failed writing bson.");
        return;
    }
    
    rpc_server_send(req, bson_data(&bs), bson_size(&bs));
}

static void host_skip_connection_acl(rpc_server_req* req, const uint8_t* args) {
    wish_core_t* core = (wish_core_t*) req->server->context;
    
    bson_iterator it;
    bson_iterator_from_buffer(&it, args);
    
    if (bson_find_fieldpath_value("0", &it) != BSON_BOOL) {
        rpc_server_error_msg(req, 306, "Argument must be bool");
        return;
    }
    
    core->config_skip_connection_acl = bson_iterator_bool(&it);
    
    char *msg = NULL;
    if (core->config_skip_connection_acl) {
        msg = "Warning: the core is set to insecure state!";
    }
    else {
        msg = "Note: the core is set to secure state.";
    }
    
    WISHDEBUG(LOG_CRITICAL, "%s", msg);
    
    int buffer_len = 256;
    uint8_t buffer[buffer_len];
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_start_object(&bs, "data");
    // FIXME version is shown in the separate version rpc command, consider removing this
    bson_append_string(&bs, "msg", msg);
    bson_append_finish_object(&bs);
    bson_finish(&bs);

    if (bs.err) {
        rpc_server_error_msg(req, 305, "Failed writing bson.");
        return;
    }
    
    rpc_server_send(req, bson_data(&bs), bson_size(&bs));
}

handler methods_h =                                   { .op = "methods",                           .handler = methods, .args = "(void): string" };
handler signals_h =                                   { .op = "signals",                           .handler = wish_core_signals, .args = "(filter?: string): Signal" };
handler version_h =                                   { .op = "version",                           .handler = version, .args = "(void): string", .doc = "Returns core version." };

handler services_send_h =                             { .op = "services.send",                     .handler = wish_api_services_send, .args = "(peer: Peer, payload: Buffer): bool", .doc = "Send payload to peer." };
handler services_list_h =                             { .op = "services.list",                     .handler = wish_api_services_list, .args = "(void): Service[]", .doc = "List local services." };

handler identity_list_h =                             { .op = "identity.list",                     .handler = wish_api_identity_list, .args="(void): Identity[]" };
handler identity_export_h =                           { .op = "identity.export",                   .handler = wish_api_identity_export, .args="(void): Document" };
handler identity_import_h =                           { .op = "identity.import",                   .handler = wish_api_identity_import, .args="(identity: Document): Identity" };
handler identity_create_h =                           { .op = "identity.create",                   .handler = wish_api_identity_create, .args="(alias: string): Identity" };
handler identity_update_h =                           { .op = "identity.update",                   .handler = wish_api_identity_update, .args="({ alias?: string, [field: string]: string }): Identity" };
handler identity_permissions_h =                      { .op = "identity.permissions",              .handler = wish_api_identity_permissions, .args="({ [field: string]: string }): Identity" };
handler identity_get_h =                              { .op = "identity.get",                      .handler = wish_api_identity_get, .args="(uid: Uid): Identity" };
handler identity_remove_h =                           { .op = "identity.remove",                   .handler = wish_api_identity_remove, .args="(uid: Uid): bool" };

handler identity_sign_h =                             { .op = "identity.sign",                     .handler = wish_api_identity_sign, .args="(uid: Uid, document: Document, claim: Buffer): Document" };
handler identity_verify_h =                           { .op = "identity.verify",                   .handler = wish_api_identity_verify, .args = "(document: Document): Document" };
handler identity_friend_request_h =                   { .op = "identity.friendRequest",            .handler = wish_api_identity_friend_request, .args = "(luid: Uid, contact: Contact): bool" };
handler identity_friend_request_list_h =              { .op = "identity.friendRequestList",        .handler = wish_api_identity_friend_request_list, .args = "(void): FriendRequest[]" };
handler identity_friend_request_accept_h =            { .op = "identity.friendRequestAccept",      .handler = wish_api_identity_friend_request_accept, .args = "(luid: Uid, ruid: Uid): bool" };
handler identity_friend_request_decline_h =           { .op = "identity.friendRequestDecline",     .handler = wish_api_identity_friend_request_decline, .args = "(luid: Uid, ruid: Uid): bool" };

handler connections_list_h =                          { .op = "connections.list",                  .handler = wish_api_connections_list, .args = "(void): Connection[]" };
handler connections_apps_h =                          { .op = "connections.apps",                  .handler = wish_api_connections_apps, .args = "(host: Host): Apps[]" };
handler connections_request_h =                       { .op = "connections.request",               .handler = wish_api_connections_request, .args = "(host: Host, op: string, args: array): Response" };
handler connections_disconnect_h =                    { .op = "connections.disconnect",            .handler = wish_api_connections_disconnect, .args = "(id: number): bool" };
handler connections_disconnect_all_h =                { .op = "connections.disconnectAll",         .handler = wish_api_connections_disconnect_all, .args = "(): bool" };
handler connections_check_connections_h =             { .op = "connections.checkConnections",      .handler = wish_api_connections_check_connections, .args = "(id: number): bool" };

handler directory_find_h =                            { .op = "directory.find",                    .handler = wish_api_directory_find, .args = "(filter?: string): DirectoryEntry" };

handler api_acl_check_h =                             { .op = "acl.check",                         .handler = wish_api_acl_check };
handler api_acl_allow_h =                             { .op = "acl.allow",                         .handler = wish_api_acl_allow };
handler api_acl_remove_allow_h =                      { .op = "acl.removeAllow",                   .handler = wish_api_acl_remove_allow };
handler api_acl_add_user_roles_h =                    { .op = "acl.addUserRoles",                  .handler = wish_api_acl_add_user_roles };
handler api_acl_remove_user_roles_h =                 { .op = "acl.removeUserRoles",               .handler = wish_api_acl_remove_user_roles };
handler api_acl_user_roles_h =                        { .op = "acl.userRoles",                     .handler = wish_api_acl_user_roles };
handler api_acl_what_resources_h =                    { .op = "acl.whatResources",                 .handler = wish_api_acl_what_resources };
handler api_acl_allowed_permissions_h =               { .op = "acl.allowedPermissions",            .handler = wish_api_acl_allowed_permissions };
        
handler relay_list_h =                                { .op = "relay.list",                        .handler = wish_api_relay_list, .args = "(void): Relay[]" };
handler relay_add_h =                                 { .op = "relay.add",                         .handler = wish_api_relay_add, .args = "(relay: string): bool" };
handler relay_remove_h =                              { .op = "relay.remove",                      .handler = wish_api_relay_remove, .args = "(relay: string): bool" };

handler wld_list_h =                                  { .op = "wld.list",                          .handler = wish_api_wld_list, .args = "(void): Identity[]" };
handler wld_clear_h =                                 { .op = "wld.clear",                         .handler = wish_api_wld_clear, .args = "(void): bool" };
handler wld_announce_h =                              { .op = "wld.announce",                      .handler = wish_api_wld_announce, .args = "(void): bool" };
handler wld_friend_request_h =                        { .op = "wld.friendRequest",                 .handler = wish_api_wld_friend_request, .args = "(luid: Uid, ruid: Uid, rhid: Hid): bool" };

handler host_config_h =                               { .op = "host.config",                       .handler = host_config };
handler host_skip_connection_acl_h =                  { .op = "host.skipConnectionAcl",            .handler = host_skip_connection_acl, .args = "(bool): string" };


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
    core->app_api = rpc_server_init_size(core, wish_core_app_rpc_send, WISH_PORT_APP_RPC_POOL_SZ);
    rpc_server_set_name(core->app_api, "core-from-app");
    
    rpc_server_register(core->app_api, &methods_h);
    rpc_server_register(core->app_api, &signals_h);
    rpc_server_register(core->app_api, &version_h);
    
    rpc_server_register(core->app_api, &services_send_h);
    rpc_server_register(core->app_api, &services_list_h);
    
    rpc_server_register(core->app_api, &identity_list_h);
    rpc_server_register(core->app_api, &identity_create_h);
    rpc_server_register(core->app_api, &identity_update_h);
    rpc_server_register(core->app_api, &identity_permissions_h);
    rpc_server_register(core->app_api, &identity_export_h);
    rpc_server_register(core->app_api, &identity_import_h);
    rpc_server_register(core->app_api, &identity_get_h);
    rpc_server_register(core->app_api, &identity_remove_h);
    rpc_server_register(core->app_api, &identity_sign_h);
    rpc_server_register(core->app_api, &identity_verify_h);
    rpc_server_register(core->app_api, &identity_friend_request_h);
    rpc_server_register(core->app_api, &identity_friend_request_list_h);
    rpc_server_register(core->app_api, &identity_friend_request_accept_h);
    rpc_server_register(core->app_api, &identity_friend_request_decline_h);
    rpc_server_register(core->app_api, &directory_find_h);
    
    rpc_server_register(core->app_api, &connections_list_h);
    rpc_server_register(core->app_api, &connections_apps_h);
    rpc_server_register(core->app_api, &connections_request_h);
    rpc_server_register(core->app_api, &connections_disconnect_h);
    rpc_server_register(core->app_api, &connections_disconnect_all_h);
    rpc_server_register(core->app_api, &connections_check_connections_h);

    rpc_server_register(core->app_api, &api_acl_check_h);
    rpc_server_register(core->app_api, &api_acl_allow_h);
    rpc_server_register(core->app_api, &api_acl_remove_allow_h);
    rpc_server_register(core->app_api, &api_acl_add_user_roles_h);
    rpc_server_register(core->app_api, &api_acl_remove_user_roles_h);
    rpc_server_register(core->app_api, &api_acl_user_roles_h);
    rpc_server_register(core->app_api, &api_acl_what_resources_h);
    rpc_server_register(core->app_api, &api_acl_allowed_permissions_h);

    rpc_server_register(core->app_api, &relay_list_h);
    rpc_server_register(core->app_api, &relay_add_h);
    rpc_server_register(core->app_api, &relay_remove_h);
    
    rpc_server_register(core->app_api, &wld_list_h);
    rpc_server_register(core->app_api, &wld_clear_h);
    rpc_server_register(core->app_api, &wld_announce_h);
    rpc_server_register(core->app_api, &wld_friend_request_h);
    
    rpc_server_register(core->app_api, &host_config_h);
    rpc_server_register(core->app_api, &host_skip_connection_acl_h);
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
    
    //WISHDEBUG(LOG_CRITICAL, "wish_core_from_app: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x", data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12], data[13], data[14]);
    //bson_visit("wish_core_from_app:", data);
    
    rpc_server_receive(core->app_api, NULL, app, &bs);
}

// Move implementation to wish-rpc-c99, just call it from here
void wish_core_app_rpc_cleanup_requests(wish_core_t* core, struct wish_service_entry *service_entry_offline) {
    //WISHDEBUG(LOG_CRITICAL, "App rpc server clean up starting");
    rpc_server_req* elm = NULL;
    rpc_server_req* tmp = NULL;
    
    LL_FOREACH_SAFE(core->app_api->requests, elm, tmp) {
        if (elm->context == service_entry_offline) {
            //WISHDEBUG(LOG_CRITICAL, "App rpc server clean up: request op %s", elm->op_str);
            LL_DELETE(core->app_api->requests, elm);
            
#ifdef WISH_RPC_SERVER_STATIC_REQUEST_POOL
            memset(&(elm->request_ctx), 0, sizeof(rpc_server_req));
#else
            wish_platform_free(elm);
#endif
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
            bson_append_string_maxlen(&bs, "name", service_entry->name, WISH_APP_NAME_MAX_LEN);
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
