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
#include "cbson.h"
#include "bson.h"
#include "bson_visitor.h"
#include "wish_connection_mgr.h"
#include "wish_identity.h"
#include "wish_dispatcher.h"
#include "wish_time.h"
#include "wish_io.h"

static void wish_ldiscover_periodic(wish_core_t* core, void* ctx) {
    WISHDEBUG(LOG_CRITICAL, "Do some discovering...", ctx);
    
    //if (advertize_own_uid && core->loaded_num_ids > 0) {
    if (core->loaded_num_ids > 0) {
        int c;
        for (c=0; c<core->loaded_num_ids; c++) {
            wish_ldiscover_advertize(core, core->uid_list[c].uid);
        }
    }
}

void wish_ldiscover_init(wish_core_t* core) {
    core->ldiscovery_db = wish_platform_malloc(sizeof(wish_ldiscover_t)*WISH_LOCAL_DISCOVERY_MAX);
    wish_core_time_set_interval(core, &wish_ldiscover_periodic, NULL, 5);
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

    uint8_t *ruid = 0;
    int32_t uid_len = 0;
    if (bson_get_binary(msg, "wuid", &ruid, &uid_len) == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Malformed ldiscover message (no uid)");
        return;
    }

    if (uid_len != WISH_ID_LEN) {
        WISHDEBUG(LOG_CRITICAL, "Malformed ldiscover message (uid len mismatch)");
        return;
    }

    /* Test if we already have a connection the said identity (using my identity) and host */

    uint8_t *rhid = 0;  /* The candidate remote host identity */
    int32_t rhid_len = 0;
    if (bson_get_binary(msg, "whid", &rhid, &rhid_len) == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Malformed ldiscover message (no whid)");
        return;
    }

    uint8_t *pubkey_ptr = 0;
    int32_t pubkey_len = 0;
    if (bson_get_binary(msg, "pubkey", &pubkey_ptr, &pubkey_len) == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Malformed ldiscover message (no pubkey)");
        return;
    }

    char *alias = 0;
    int32_t alias_len = 0;
    if (bson_get_string(msg, "alias", &alias, &alias_len) == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Malformed ldiscover message (no alias)");
        return;
    }

    /** The port number of the remote wish core will be saved here */
    uint16_t tcp_port = 0;

    uint8_t *transports = 0;
    int32_t transports_len = 0;
    if (bson_get_array(msg, "transports", &transports, &transports_len)
            == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Malformed ldiscover message (no transports)");
        return;
    }
    else {
        char *url = 0;
        int32_t url_len = 0;
        if (bson_get_string(transports, "0", &url, &url_len) == BSON_FAIL) {
            WISHDEBUG(LOG_CRITICAL, "Malformed ldiscover message (transports yes, but no contents)");
            return;
        }
        else {
            WISHDEBUG(LOG_DEBUG, "wld: Extracted from transports url: %s", url);
            if (wish_parse_transport_port(url, url_len, &tcp_port)) {
                WISHDEBUG(LOG_CRITICAL, "wld: Error while parsing port");
                return;
            }
        }
    }

    //WISHDEBUG(LOG_CRITICAL, "LocalDiscovery checking cache. ruid: %02x %02x %02x %02x", ruid[0], ruid[1], ruid[2], ruid[3]);
    
    uint32_t current_time = wish_time_get_relative(core);
    bool found = false;
    int free = -1;

    int i;
    for(i=0; i<WISH_LOCAL_DISCOVERY_MAX; i++) {
        if (core->ldiscovery_db[i].occupied && current_time - core->ldiscovery_db[i].timestamp > 30) {
            core->ldiscovery_db[i].occupied = false;
            WISHDEBUG(LOG_CRITICAL, "LocalDiscovery dropped timed out entry.");
        }
        
        if (core->ldiscovery_db[i].occupied) {
            if( memcmp(&core->ldiscovery_db[i].ruid,  ruid, WISH_ID_LEN) == 0 && 
                    memcmp(&core->ldiscovery_db[i].rhid, rhid, WISH_ID_LEN) == 0 ) 
            {
                //WISHDEBUG(LOG_CRITICAL, "Found entry. Updating timestamp");
                found = true;
                core->ldiscovery_db[i].timestamp = current_time;
                break;
            }
        } else {
            free = i;
        }
    }
    if(!found && free != -1) {
        core->ldiscovery_db[free].occupied = true;
        core->ldiscovery_db[free].timestamp = current_time;
        memcpy(&core->ldiscovery_db[free].ruid, ruid, WISH_ID_LEN);
        memcpy(&core->ldiscovery_db[free].rhid, rhid, WISH_ID_LEN);
        memcpy(&core->ldiscovery_db[free].pubkey, pubkey_ptr, WISH_PUBKEY_LEN);
        strncpy((char*) &core->ldiscovery_db[free].alias, alias, WISH_MAX_ALIAS_LEN);
        /* FIXME ip address length here is hardcoded and assumed to be
         * IPv4 */
        /* FIXME the ip address is read from where the broadcast is
         * received from - and not from transports! */
        memcpy(&core->ldiscovery_db[free].transport_ip, ip, sizeof (wish_ip_addr_t));
        /* FIXME the port is hardcoded, should be read from transports */
        core->ldiscovery_db[free].transport_port = tcp_port;
        WISHDEBUG(LOG_DEBUG, "Inserted Local Discovered peer at index %d", free);
    }
    
    /* Save the pubkey to contact database, along with metadata.
     * But first, check if we already know this uid */
    wish_identity_t discovered_id;
    if (wish_load_identity(ruid, &discovered_id) > 0) {
        //WISHDEBUG(LOG_CRITICAL, "Auto-discovered uid is already in our contacts");
    } else {
        //WISHDEBUG(LOG_CRITICAL, "Ignoring auto discovery bcast for unknown uid");
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
    if (wish_core_get_local_hostid(core, local_hostid) == WISH_WHID_LEN) {
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
    wish_connection_t *new_ctx = wish_connection_init(core, my_uid, ruid);
    if (new_ctx != NULL) {
        /* FIXME the ipshould be read from * 'transports' */
        WISHDEBUG(LOG_CRITICAL, "wld: Will start connection to: %u.%u.%u.%u:%hu\n", 
            ip->addr[0], ip->addr[1], ip->addr[2], ip->addr[3], tcp_port);

        /* Request opening of a new wish connection, and associate the
         * new wish context with it */

        /* FIXME the port here is hardcoded! It should be read from 
         * 'transports' */
        wish_open_connection(core, new_ctx, ip, tcp_port, false);
    }

}

/* This function will create a 'transports' document in the memory
 * pointed to by the supplied pointer. 
 * @param transports_array   The pointer to memory where the document is to be
 * stored
 * @param transports_array_max_len The maxmimum allowed length of the document
 * @return Value 0, if no error
 */
static int create_transports_array(wish_core_t* core, uint8_t *transports_array, 
        size_t transports_array_max_len) {
    if (bson_init_doc(transports_array, transports_array_max_len) == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Failed initting transports doc");
        return 1;
    }
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
            
            if (bson_write_string(transports_array, transports_array_max_len,
                                  "0", transport_url) == BSON_FAIL) {
                WISHDEBUG(LOG_CRITICAL, "Failed writing to transports doc");
                freeifaddrs(ifap);
                return 1;
            }
            
            freeifaddrs(ifap);
            return 0;
            break;
        }
    }
    return 0;
#else
    if (wish_get_host_ip_str(core, host_part, WISH_MAX_TRANSPORT_LEN)) {
        WISHDEBUG(LOG_CRITICAL, "Could not get Host IP addr");
        return 1;
    }
    wish_platform_sprintf(transport_url, "wish://%s:%d", host_part, wish_get_host_port(core));

    if (bson_write_string(transports_array, transports_array_max_len, "0", transport_url) == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Failed writing to transports doc");
        return 1;
    }

    return 0;
#endif
}

/* Send out one "advertizement" message for wish identity my_uid */
void wish_ldiscover_advertize(wish_core_t* core, uint8_t *my_uid) {
    /* Advert message length:
     * uid len + hostid len + pubkey len + room for metadata */

    wish_identity_t my_identity;
    wish_load_identity(my_uid, &my_identity);

    // Local discovery will not advertise if we don't have a private key
    if (!my_identity.has_privkey) { return; }
    
    const size_t transports_array_max_len = 50;
    uint8_t transports_array[transports_array_max_len];
    if (create_transports_array(core, transports_array, transports_array_max_len)) {
        WISHDEBUG(LOG_CRITICAL, "Failed to create transports array");
        return;
    }

    const size_t advert_msg_max_len = 2*(20 + WISH_ID_LEN) + 20 + WISH_PUBKEY_LEN + 10 + bson_get_doc_len(transports_array) + WISH_MAX_ALIAS_LEN;
    uint8_t advert_msg[advert_msg_max_len];

    bson_init_doc(advert_msg, advert_msg_max_len);
    bson_write_binary(advert_msg, advert_msg_max_len, "wuid", my_uid, WISH_ID_LEN);

    uint8_t host_id[WISH_WHID_LEN];
    wish_core_get_local_hostid(core, host_id);
    bson_write_binary(advert_msg, advert_msg_max_len, "whid", host_id, WISH_ID_LEN);

    uint8_t pubkey[WISH_PUBKEY_LEN] = { 0 };

    if (wish_load_pubkey(my_uid, pubkey)) {
        bson_visit("failed to load pubkey for uid", advert_msg);
        return;
    }

    bson_write_binary(advert_msg, advert_msg_max_len, "pubkey", pubkey, WISH_PUBKEY_LEN);
    bson_write_embedded_doc_or_array(advert_msg, advert_msg_max_len, "transports", transports_array, BSON_KEY_ARRAY);
    bson_write_string(advert_msg, advert_msg_max_len, "alias", my_identity.alias);

    /* Send away the advert message, but first add the magic bytes in
     * front of the message */

    uint8_t advert_with_magic[2 + advert_msg_max_len];
    advert_with_magic[0] = 'W';
    advert_with_magic[1] = '.';
    memcpy(advert_with_magic + 2, advert_msg, bson_get_doc_len(advert_msg));
    size_t advert_with_magic_len = 2 + bson_get_doc_len(advert_msg);
    
    bson_visit("Advertisement message going out from core:", advert_msg);
    
    wish_send_advertizement(core, advert_with_magic, advert_with_magic_len);
}

void wish_ldiscover_clear(wish_core_t* core) {
    int i;
    for(i=0; i<WISH_LOCAL_DISCOVERY_MAX; i++) {
        core->ldiscovery_db[i].occupied = false;
    }
}

wish_ldiscover_t *wish_ldiscover_get(wish_core_t* core) {
    return core->ldiscovery_db;
}



