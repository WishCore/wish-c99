#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#ifdef __APPLE__
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <stdio.h>
#endif

#include "wish_utils.h"
#include "wish_local_discovery.h"
#include "wish_debug.h"
#include "bson.h"
#include "bson_visit.h"
#include "wish_connection_mgr.h"
#include "wish_identity.h"
#include "wish_dispatcher.h"
#include "wish_core_signals.h"
#include "wish_time.h"
#include "wish_connection.h"

static void wish_ldiscover_periodic(wish_core_t* core, void* ctx) {
    //WISHDEBUG(LOG_CRITICAL, "Do some discovering...", ctx);
    
    //if (advertize_own_uid && core->loaded_num_ids > 0) {
    if (core->ldiscover_allowed) {
        wish_ldiscover_announce_all(core);
    }
}

void wish_ldiscover_init(wish_core_t* core) {
    int size = sizeof(wish_ldiscover_t)*WISH_LOCAL_DISCOVERY_MAX;
    core->ldiscovery_db = wish_platform_malloc(size);
    memset(core->ldiscovery_db, 0, size);
    wish_core_time_set_interval(core, &wish_ldiscover_periodic, NULL, 5);
}

void wish_ldiscover_announce_all(wish_core_t* core) {
    if (core->loaded_num_ids > 0) {
        int c;
        for (c=0; c<core->loaded_num_ids; c++) {
            wish_ldiscover_advertize(core, core->uid_list[c].uid);
        }
    }
}

/* Start local discovery */
void wish_ldiscover_start(wish_core_t* core) {
    core->ldiscover_allowed = true;
}


/* Feed local discovery message data into Wish core for processing.
 * ip[4], the originating IPv4 address
 * port, the originating UDP port (in host byte order)
 */
void wish_ldiscover_feed(wish_core_t* core, wish_ip_addr_t *ip, uint16_t port, uint8_t *buffer, 
size_t buffer_len) {
    /* First, try to detect the magic bytes 'W' and '.' in the beginning
     * of the message */

    if (buffer_len < 3) {
        WISHDEBUG(LOG_DEBUG, "Malformed ldiscover message (too short)");
        return;
    }

    if (buffer[0] != 'W' && buffer[1] != '.') {
        WISHDEBUG(LOG_DEBUG, "Malformed ldiscover message (bad magic)");
        return;
    }

    /* Pointer to the beginning of the actual autoconfiguration data */
    uint8_t *msg = buffer + 2;

    /* For Auto configuration, we expect a BSON message with following
     * fields:
     * uid: a buffer containing 32 bytes
     * whid: a buffer which should contain 32 bytes
     * pubkey: 32 bytes containing the pubkey (optional, only when the
     * peer wishes to be claimed)
     */

    bson_iterator it;
    
    if (bson_find_from_buffer(&it, msg, "wuid") != BSON_BINDATA) {
        WISHDEBUG(LOG_CRITICAL, "Malformed ldiscover message (no uid)");
        return;
    }

    const uint8_t* ruid = bson_iterator_bin_data(&it);

    if (bson_iterator_bin_len(&it) != WISH_ID_LEN) {
        WISHDEBUG(LOG_CRITICAL, "Malformed ldiscover message (uid len mismatch)");
        return;
    }

    /* Test if we already have a connection the said identity (using my identity) and host */

    if (bson_find_from_buffer(&it, msg, "whid") != BSON_BINDATA) {
        WISHDEBUG(LOG_CRITICAL, "Malformed ldiscover message (no whid)");
        return;
    }

    if (bson_iterator_bin_len(&it) != WISH_ID_LEN) {
        WISHDEBUG(LOG_CRITICAL, "Malformed ldiscover message (whid len mismatch)");
        return;
    }
    
    const uint8_t* rhid = bson_iterator_bin_data(&it);  /* The candidate remote host identity */

    if (bson_find_from_buffer(&it, msg, "pubkey") != BSON_BINDATA) {
        WISHDEBUG(LOG_CRITICAL, "Malformed ldiscover message (no pubkey)");
        return;
    }

    if (bson_iterator_bin_len(&it) != WISH_PUBKEY_LEN) {
        WISHDEBUG(LOG_CRITICAL, "Malformed ldiscover message (pubkey len mismatch)");
        return;
    }
    
    const uint8_t *pubkey_ptr = bson_iterator_bin_data(&it);


    if (bson_find_from_buffer(&it, msg, "alias") != BSON_STRING) {
        WISHDEBUG(LOG_CRITICAL, "Malformed ldiscover message (no pubkey)");
        return;
    }
    
    const char* alias = bson_iterator_string(&it);

    bool claim = false;
    
    if (bson_find_from_buffer(&it, msg, "claim") == BSON_BOOL) {
        claim = bson_iterator_bool(&it);
    }
    
    bson_iterator_from_buffer(&it, msg);
    
    const char* meta_product = NULL;
    
    if (bson_find_fieldpath_value("meta.product", &it) == BSON_STRING) {
        meta_product = bson_iterator_string(&it);
    }
    
    /** The port number of the remote wish core will be saved here */
    uint16_t tcp_port = 0;

    bson_iterator_from_buffer(&it, msg);

    // FIXME: Only first transport is read
    
    if (bson_find_fieldpath_value("transports.0", &it) == BSON_STRING) {
        const char* url = bson_iterator_string(&it);
        int url_len = bson_iterator_string_len(&it);
        
        if (wish_parse_transport_port(url, url_len, &tcp_port)) {
            WISHDEBUG(LOG_CRITICAL, "wld: Error while parsing port");
            return;
        }
    } else {
        WISHDEBUG(LOG_CRITICAL, "No transport in local discovery message");
        return;
    }
    
    //WISHDEBUG(LOG_CRITICAL, "LocalDiscovery checking cache. ruid: %02x %02x %02x %02x", ruid[0], ruid[1], ruid[2], ruid[3]);
    
    uint32_t current_time = wish_time_get_relative(core);
    bool found = false;
    int free = -1;

    int i;
    for(i=0; i<WISH_LOCAL_DISCOVERY_MAX; i++) {
        if (core->ldiscovery_db[i].occupied && core->ldiscovery_db[i].type == DISCOVER_TYPE_LOCAL && current_time - core->ldiscovery_db[i].timestamp > 30) {
            core->ldiscovery_db[i].occupied = false;
            //WISHDEBUG(LOG_CRITICAL, "LocalDiscovery dropped timed out entry.");
            
            wish_core_signals_emit_string(core, "localDiscovery");
            continue;
        }
        
        if (core->ldiscovery_db[i].occupied) {
            if( memcmp(&core->ldiscovery_db[i].ruid,  ruid, WISH_ID_LEN) == 0 && 
                    memcmp(&core->ldiscovery_db[i].rhid, rhid, WISH_ID_LEN) == 0 ) 
            {
                //WISHDEBUG(LOG_CRITICAL, "Found entry. Updating timestamp");
                found = true;
                core->ldiscovery_db[i].timestamp = current_time;
                
                bool changed = false;
                
                if (strncmp(core->ldiscovery_db[i].alias, alias, WISH_ALIAS_LEN) != 0) {
                    strncpy((char*) &core->ldiscovery_db[i].alias, alias, WISH_ALIAS_LEN);
                    changed = true;
                }
                
                if (core->ldiscovery_db[i].claim != claim) {
                    // claim state changed
                    changed = true;
                }
                
                if (changed) {
                    wish_core_signals_emit_string(core, "localDiscovery");
                }
                
                break;
            }
        } else {
            free = i;
        }
    }
    if(!found && free != -1) {
        core->ldiscovery_db[free].type = DISCOVER_TYPE_LOCAL;
        core->ldiscovery_db[free].occupied = true;
        core->ldiscovery_db[free].timestamp = current_time;
        memcpy(&core->ldiscovery_db[free].ruid, ruid, WISH_ID_LEN);
        memcpy(&core->ldiscovery_db[free].rhid, rhid, WISH_ID_LEN);
        memcpy(&core->ldiscovery_db[free].pubkey, pubkey_ptr, WISH_PUBKEY_LEN);
        strncpy((char*) &core->ldiscovery_db[free].alias, alias, WISH_ALIAS_LEN);
        core->ldiscovery_db[free].class = (meta_product != NULL ? strdup(meta_product) : NULL);
        core->ldiscovery_db[free].claim = claim;
        /* FIXME ip address length here is hardcoded and assumed to be
         * IPv4 */
        /* FIXME the ip address is read from where the broadcast is
         * received from - and not from transports! */
        memcpy(&core->ldiscovery_db[free].transport_ip, ip, sizeof (wish_ip_addr_t));
        /* FIXME the port is hardcoded, should be read from transports */
        core->ldiscovery_db[free].transport_port = tcp_port;
        WISHDEBUG(LOG_DEBUG, "Inserted Local Discovered peer at index %d", free);
        
        wish_core_signals_emit_string(core, "localDiscovery");
    }
    
    /* Save the pubkey to contact database, along with metadata.
     * But first, check if we already know this uid */
    wish_identity_t discovered_id;
    return_t ret = wish_identity_load(ruid, &discovered_id);
    wish_identity_destroy(&discovered_id);
    
    if (ret != RET_SUCCESS) {
        // Not trying to connect to unknown uid
        return;
    }

    /* Start a connection to the new peer */

    /* Determine what uid we will be using as local uid when
     * connecting */
    
    /* FIXME now we use only the first identity in the database which is advertized to everybody */
    wish_uid_list_elem_t uid_list[1];
    int num_uids = wish_load_uid_list(uid_list, 1);

    if(num_uids == 0) {
        // we do not have any identities, and cannot therefore connect
        return;
    }

    wish_connection_t *existing_conn_ctx = wish_core_lookup_ctx_by_luid_ruid_rhid(core, uid_list[0].uid, ruid, rhid);
    if (existing_conn_ctx != NULL) {
        if (existing_conn_ctx->context_state == WISH_CONTEXT_CONNECTED) {
            /* Found that we already have a wish connection where one of
             * our own identities is local identity */
            WISHDEBUG(LOG_DEBUG, "Not opening a new connection because we already have a connection to the remote core");
            return;
        }
        else if (existing_conn_ctx->context_state == WISH_CONTEXT_IN_MAKING) {
            WISHDEBUG(LOG_CRITICAL, "wld: we are already opening a connection.");
            return;
        }
        else {
            WISHDEBUG(LOG_CRITICAL, "wld: Unexpected context state");
            return;
        }
    }
    
    /* Obtain local hostid and compare with the rhid of the broadcast */
    uint8_t local_hostid[WISH_WHID_LEN];
    if (wish_core_get_host_id(core, local_hostid) == WISH_WHID_LEN) {
        if (memcmp(rhid, local_hostid, WISH_WHID_LEN) == 0) {
            /* The wld broadcast has originated from this host itself! */
            return;
        }
    } else  {
        WISHDEBUG(LOG_CRITICAL, "wld: error obtaining local host id");
    }
    
    /* Create new wish context with the ids */

    /* FIXME currently always using first uid of list */
    uint8_t *my_uid = uid_list[0].uid;
    wish_connection_t *connection = wish_connection_init(core, my_uid, ruid);
    if (connection != NULL) {
        /* FIXME the ipshould be read from * 'transports' */
        
        //WISHDEBUG(LOG_CRITICAL, "LocalDiscovery: Will start connection to: %u.%u.%u.%u:%hu\n", ip->addr[0], ip->addr[1], ip->addr[2], ip->addr[3], tcp_port);

        /* Request opening of a new wish connection, and associate the
         * new wish context with it */

        wish_open_connection(core, connection, ip, tcp_port, false);
    }

}

/* This function will create a 'transports' document in the memory
 * pointed to by the supplied pointer. 
 * @param transports_array   The pointer to memory where the document is to be
 * stored
 * @param transports_array_max_len The maxmimum allowed length of the document
 * @return Value 0, if no error
 */
static int append_transports_array(wish_core_t* core, bson* bs) {
    
    bson_append_start_array(bs, "transports");
    
    char transport_url[WISH_MAX_TRANSPORT_LEN];
    char host_part[WISH_MAX_TRANSPORT_LEN];
    
#ifdef __APPLE__
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    char *addr;
    
    getifaddrs (&ifap);
    int c = 0;
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family==AF_INET) {
            if(c==0) { c++; continue; }
            sa = (struct sockaddr_in *) ifa->ifa_addr;
            addr = inet_ntoa(sa->sin_addr);
            //printf("Interface: %s\tAddress: %s\n", ifa->ifa_name, addr);
            wish_platform_sprintf(transport_url, "wish://%s:%d", addr, wish_get_host_port(core));
            
            bson_append_string(bs, "0", transport_url);
            
            freeifaddrs(ifap);
            return 0;
            break;
        }
    }
#else
    if (wish_get_host_ip_str(core, host_part, WISH_MAX_TRANSPORT_LEN)) {
        WISHDEBUG(LOG_CRITICAL, "Could not get Host IP addr");
        return 1;
    }
    wish_platform_sprintf(transport_url, "wish://%s:%d", host_part, wish_get_host_port(core));

    bson_append_string(bs, "0", transport_url);
    
#endif
    bson_append_finish_array(bs);
    
    return 0;
}

/* Send out one "advertizement" message for wish identity my_uid */
void wish_ldiscover_advertize(wish_core_t* core, uint8_t* uid) {
    /* Advert message length:
     * uid len + hostid len + pubkey len + room for metadata */

    wish_identity_t id;
    return_t ret = wish_identity_load(uid, &id);
    
    // Local discovery will not advertise if we cant load identity
    if (ret != RET_SUCCESS) { 
        wish_identity_destroy(&id);
        return; 
    }

    // Local discovery will not advertise if we don't have a private key
    if (!id.has_privkey) { return; }

    const size_t msg_len = 2 + 2*(20 + WISH_ID_LEN) + 20 + WISH_PUBKEY_LEN + 10 + WISH_MAX_TRANSPORT_LEN + WISH_ALIAS_LEN;
    uint8_t msg[msg_len];

    msg[0] = 'W';
    msg[1] = '.';

    bson bs;
    bson_init_buffer(&bs, msg+2, msg_len-2);
    
    bson_append_string(&bs, "alias", id.alias);
#ifdef WLD_META_PRODUCT
    bson_append_start_object(&bs, "meta");
    bson_append_string(&bs, "product", WLD_META_PRODUCT);
    bson_append_finish_object(&bs);
#endif
    bson_append_binary(&bs, "wuid", uid, WISH_ID_LEN);

    uint8_t host_id[WISH_WHID_LEN];
    wish_core_get_host_id(core, host_id);
    bson_append_binary(&bs, "whid", host_id, WISH_ID_LEN);

    uint8_t pubkey[WISH_PUBKEY_LEN] = { 0 };

    if (wish_load_pubkey(uid, pubkey)) {
        bson_visit("failed to load pubkey for uid", bson_data(&bs));
        return;
    }

    bson_append_binary(&bs, "pubkey", pubkey, WISH_PUBKEY_LEN);
    append_transports_array(core, &bs);
    
    if (core->config_skip_connection_acl) {
        bson_append_bool(&bs, "claim", true);
    }

    bson_finish(&bs);

    //bson_visit("Advertisement message going out from core:", bson_data(&bs));
    
    wish_send_advertizement(core, msg, 2 + bson_size(&bs));
    wish_identity_destroy(&id);
}

void wish_ldiscover_add(wish_core_t* core, wish_ldiscover_t* entry) {
    int i;
    int free = -1;
    
    for(i=0; i<WISH_LOCAL_DISCOVERY_MAX; i++) {
        if (!core->ldiscovery_db[i].occupied) {
            free = i;
            break;
        }
    }
    
    if (free == -1) {
        WISHDEBUG(LOG_CRITICAL, "Dropped a discovery entry due to memory being full.");
        return;
    }

    wish_ldiscover_t* elt = &core->ldiscovery_db[free];
    
    memcpy(elt, entry, sizeof(wish_ldiscover_t));
    elt->occupied = true;
    //WISHDEBUG(LOG_CRITICAL, "wish_ldiscover_add completed successfully.");
}

void wish_ldiscover_clear(wish_core_t* core) {
    int i;
    for(i=0; i<WISH_LOCAL_DISCOVERY_MAX; i++) {
        if (core->ldiscovery_db[i].meta) { wish_platform_free(core->ldiscovery_db[i].meta); }
        
        core->ldiscovery_db[i].occupied = false;
    }
}

wish_ldiscover_t *wish_ldiscover_get(wish_core_t* core) {
    return core->ldiscovery_db;
}



