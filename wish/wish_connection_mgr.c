#include <stdint.h>

#include "wish_port_config.h"
#include "wish_core.h"
#include "wish_utils.h"
#include "wish_identity.h"
#include "wish_debug.h"
#include "wish_io.h"
#include "bson.h"
#include "cbson.h"
#include "bson_visitor.h"
#include "wish_connection_mgr.h"
#include "string.h"

void wish_connections_init(wish_core_t* core) {
    core->wish_context_pool = wish_platform_malloc(sizeof(wish_connection_t)*WISH_CONTEXT_POOL_SZ);
    memset(core->wish_context_pool, 0, sizeof(wish_connection_t)*WISH_CONTEXT_POOL_SZ);
    core->next_conn_id = 1;
    
    wish_core_time_set_interval(core, &check_connection_liveliness, NULL, 1);
}

void wish_connections_check(wish_core_t* core) {
    int num_uids_in_db = wish_get_num_uid_entries();
    wish_uid_list_elem_t uid_list[num_uids_in_db];
    int num_uids = wish_load_uid_list(uid_list, num_uids_in_db);

    int i = 0;

    int j;
    for (j = 0; j < num_uids; j++) {
        if (i == j) { continue; }
        if( wish_core_is_connected_luid_ruid(core, uid_list[0].uid, uid_list[j].uid) ) { continue; }

        size_t id_bson_doc_max_len = sizeof (wish_identity_t) + 100;
        uint8_t id_bson_doc[id_bson_doc_max_len];
        int ret = wish_load_identity_bson(uid_list[j].uid, id_bson_doc, id_bson_doc_max_len);
        if (ret != 1) {
            WISHDEBUG(LOG_CRITICAL, "Failed loading identity");
            return;
        }
        
        //bson_visit("wish_connections_check -- id_bson_doc", id_bson_doc);

        bson_iterator it;
        bson_type bt;

        bson_iterator_from_buffer(&it, id_bson_doc);
        bt = bson_find_fieldpath_value("transports.0", &it);        
        
        //WISHDEBUG(LOG_CRITICAL, "transports type: %d", bson_iterator_type(&it));
        
        if (bson_iterator_type(&it) != BSON_STRING) {
            continue;
        }        

        do {
            int url_len = bson_iterator_string_len(&it);
            char* url = (char *) bson_iterator_string(&it);
            //WISHDEBUG(LOG_CRITICAL, "  Should connect %02x %02x > %02x %02x to %s", uid_list[0].uid[0], uid_list[0].uid[1], uid_list[j].uid[0], uid_list[j].uid[1], url);
            
            wish_ip_addr_t ip;
            uint16_t port;
            ret = wish_parse_transport_port(url, url_len, &port);
            if (ret) {
                WISHDEBUG(LOG_CRITICAL, "Could not parse transport port");
            }
            else {
                ret = wish_parse_transport_ip(url, url_len, &ip);
                if (ret) {
                    WISHDEBUG(LOG_CRITICAL, "Could not parse transport ip");
                }
                else {
                    /* Parsing of IP and port OK: go ahead with connecting */
                    wish_connections_connect_tcp(core, uid_list[0].uid, uid_list[j].uid, &ip, port);
                }
            }
        } while ((bt = bson_iterator_next(&it)) != BSON_EOO);
    }
}

/* This function will check the connections and send a 'ping' if they
 * have not received anything lately */
void check_connection_liveliness(wish_core_t* core, void* ctx) {
    //WISHDEBUG(LOG_CRITICAL, "check_connection_liveliness");
    int i = 0;
    for (i = 0; i < WISH_CONTEXT_POOL_SZ; i++) {
        wish_connection_t* connection = &(core->wish_context_pool[i]);
        switch (connection->context_state) {
        case WISH_CONTEXT_CONNECTED:
            /* We have found a connected context we must examine */
            if ((core->core_time > (connection->latest_input_timestamp + PING_INTERVAL))
                && (connection->ping_sent_timestamp <= connection->latest_input_timestamp)) 
            {
                WISHDEBUG(LOG_DEBUG, "Pinging connection %d", i);
 
                /* Enqueue a ping message */
                int32_t ping_msg_max_len = 50;
                uint8_t ping_msg[ping_msg_max_len];
                bson_init_doc(ping_msg, ping_msg_max_len);
                /* Send: { ping: true } */
                bson_write_boolean(ping_msg, ping_msg_max_len, "ping", true);
                wish_core_send_message(core, connection, ping_msg, bson_get_doc_len(ping_msg));
                connection->ping_sent_timestamp = core->core_time;
            }

            if (core->core_time > (connection->latest_input_timestamp + PING_TIMEOUT) &&
                (connection->ping_sent_timestamp > connection->latest_input_timestamp)) {
                WISHDEBUG(LOG_CRITICAL, "Connection ping: Killing connection because of inactivity");
                wish_close_connection(core, connection);
            }
            break;
        case WISH_CONTEXT_IN_MAKING:
            if (core->core_time > (connection->latest_input_timestamp + PING_TIMEOUT)) {
                WISHDEBUG(LOG_CRITICAL, "Connection ping: Killing connection because it has been in handshake phase for too long");
                wish_close_connection(core, connection);
            }
            break;
        case WISH_CONTEXT_CLOSING:
            WISHDEBUG(LOG_CRITICAL, "Connection ping: Found context in closing state! Forcibly closing it.");
            wish_close_connection(core, connection);
            break;
        case WISH_CONTEXT_FREE:
            /* Obviously we don't ping unused contexts! */
            break;
        }
    }
}

return_t wish_connections_connect_tcp(wish_core_t* core, uint8_t *luid, uint8_t *ruid, wish_ip_addr_t *ip, uint16_t port) {
    
    wish_identity_t lu;
    wish_identity_t ru;
    
    if ( ret_success == wish_load_identity(luid, &lu) 
            && ret_success == wish_load_identity(ruid, &ru) )
    {
        WISHDEBUG(LOG_CRITICAL, "open connection: %s > %s ", lu.alias, ru.alias);
    } else {
        return ret_fail;
    }
    
    wish_connection_t *new_ctx = wish_connection_init(core, luid, ruid);
    if (new_ctx != NULL) {
        WISHDEBUG(LOG_CRITICAL, "Wish core tcp connect: %u.%u.%u.%u:%hu", ip->addr[0], ip->addr[1], ip->addr[2], ip->addr[3], port);
        wish_open_connection(core, new_ctx, ip, port, false);
    }
    
    return ret_success;
}
