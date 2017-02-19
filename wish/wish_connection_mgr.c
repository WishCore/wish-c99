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
        
        bson_visit(id_bson_doc, elem_visitor);

        bson_iterator it;
        bson_type bt;

        bson_iterator_from_buffer(&it, id_bson_doc);
        bt = bson_find_fieldpath_value("transports.0", &it);        
        
        WISHDEBUG(LOG_CRITICAL, "transports type: %d", bson_iterator_type(&it));
        
        if (bson_iterator_type(&it) != BSON_STRING) {
            continue;
        }        

        do {
            int url_len = bson_iterator_string_len(&it);
            char* url = (char *) bson_iterator_string(&it);
            WISHDEBUG(LOG_CRITICAL, "  Should connect %02x %02x > %02x %02x to %s", uid_list[0].uid[0], uid_list[0].uid[1], uid_list[j].uid[0], uid_list[j].uid[1], url);
            
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

void wish_connections_connect_tcp(wish_core_t* core, uint8_t *luid, uint8_t *ruid, wish_ip_addr_t *ip, uint16_t port) {
    int num_uids_in_db = wish_get_num_uid_entries();
    wish_uid_list_elem_t uid_list[num_uids_in_db];
    int num_uids = wish_load_uid_list(uid_list, num_uids_in_db);

    if (num_uids < 0) {
        WISHDEBUG(LOG_CRITICAL, "Error loading uid list");
        return;
    }

    /* FIXME currently always using first uid of list */
    uint8_t *my_uid = uid_list[0].uid;
    wish_context_t *new_ctx = wish_core_start(core, my_uid, ruid);
    if (new_ctx != NULL) {
        /* FIXME the ipshould be read from * 'transports' */
        WISHDEBUG(LOG_CRITICAL, "wld: Will start connection to: %u.%u.%u.%u:%hu\n", 
            ip->addr[0], ip->addr[1], ip->addr[2], ip->addr[3], port);

        /* Request opening of a new wish connection, and associate the
         * new wish context with it */

        /* FIXME the port here is hardcoded! It should be read from 
         * 'transports' */
        wish_open_connection(core, new_ctx, ip, port, false);
    }
    
}
