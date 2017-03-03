#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "wish_service_registry.h"
#include "wish_core.h"
#include "wish_protocol.h"
//#include "wish_acl.h"
#include "cbson.h"
#include "wish_debug.h"
#include "wish_core_rpc_func.h"
#include "wish_core_app_rpc_func.h"

struct wish_service_entry * wish_service_get_registry(wish_core_t* core) {
    return core->service_registry;
}

bool wish_service_entry_is_valid(wish_core_t* core, struct wish_service_entry *entry) {
    bool retval = false;
    if (strnlen(entry->service_name, WISH_APP_NAME_MAX_LEN) > 0) {
        retval = true;
    }
    return retval;
}

void wish_service_register_add(wish_core_t* core, uint8_t *src_wsid, char *name, uint8_t *protocols_array, uint8_t *permissions_array) {
    WISHDEBUG(LOG_DEBUG, "%s", "wish_service_register_add");

    int i = 0;
    /* First, check if the service is already in the register */
    for (i = 0; i < WISH_MAX_SERVICES; i++) {
        if (wish_service_entry_is_valid(core, &(core->service_registry[i]))) {
            /* We have found a valid entry in the service registery. Now
             * check if the wsids match */
            if (memcmp(src_wsid, core->service_registry[i].wsid, WISH_WSID_LEN) == 0) {
                WISHDEBUG(LOG_CRITICAL, "Service was already registered %s", name);
                return;
            }
        }
    }
    /* Service was not in the service register. */
    for (i = 0; i < WISH_MAX_SERVICES; i++) {
        if (wish_service_entry_is_valid(core, &(core->service_registry[i]))
                == false) {
            /* Found free service slot */
            memcpy(core->service_registry[i].wsid, src_wsid, WISH_WSID_LEN);
            strncpy(core->service_registry[i].service_name, name, WISH_APP_NAME_MAX_LEN);

            int j = 0;
            for (j = 0; j < WISH_APP_MAX_PROTOCOLS; j++) {
                /* FIXME horrible hack for array elem names here */
                char elem_name[2] = "0";
                elem_name[0] += j;
                char *protocol_name = NULL;
                int32_t protocol_name_len = 0;
                if (bson_get_string(protocols_array, elem_name, 
                        &protocol_name, &protocol_name_len) == BSON_SUCCESS) {
                    WISHDEBUG(LOG_DEBUG, "Registering protocol: %s", protocol_name);
                    strncpy((char *) &(core->service_registry[i].protocols[0][j]),
                        protocol_name, WISH_PROTOCOL_NAME_MAX_LEN);
                }
                else {
                    WISHDEBUG(LOG_DEBUG, "No more protocols found for service %s", core->service_registry[i].service_name);
                }
            }
            /* We now have registered all the protocols that the service
             * wants to handle */
            
            break;

        }
    }

}

void wish_service_register_remove(wish_core_t* core, uint8_t *wsid) {
    /* A service as ceased to exist, and it must now be removed from Wish core's internal tables.
     * We must also notify remote peers that the service has died. Also local services? */
    struct wish_service_entry *service_entry_offline = wish_service_get_entry(core, wsid);
    struct wish_service_entry *service_registry = wish_service_get_registry(core);
    if (service_entry_offline != NULL) {
        /* Send updates to services on remote cores */
        wish_send_peer_update(core, service_entry_offline, false);
        /*  Send update to services on our local core */
        int i = 0;
        for (i = 0; i < WISH_MAX_SERVICES; i++) {
            if (wish_service_entry_is_valid(core, &(core->service_registry[i]))) {
                /* FIXME support for multiple protocols */
                if (strncmp(&(core->service_registry[i].protocols[0][0]), &(service_entry_offline->protocols[0][0]), WISH_PROTOCOL_NAME_MAX_LEN) != 0) {
                    /* Protocols do not match */
                    continue;
                }
                /* Inform the other services on this core about the service which became offline */
                wish_send_peer_update_locals(core, core->service_registry[i].wsid, service_entry_offline, false);
            }
        }
        /* Delete the entry from service registry */
        memset(service_entry_offline, 0, sizeof (struct wish_service_entry));
        /* Clean up RPC requests which might have been left behind by the app */
        wish_core_app_rpc_cleanup_requests(core, wsid);
    } else {
        WISHDEBUG(LOG_CRITICAL, "Error: Could not find a service entry with the specified wsid");
    }
}


struct wish_service_entry *wish_service_get_entry(wish_core_t* core, uint8_t *wsid) {
    struct wish_service_entry *retval = NULL;
    int i = 0;
    for (i = 0; i < WISH_MAX_SERVICES; i++) {
        if (wish_service_entry_is_valid(core, &(core->service_registry[i]))) {
            /* We have found a valid entry in the service registery. Now
             * check if the wsids match */
            if (memcmp(wsid, core->service_registry[i].wsid, WISH_WSID_LEN) == 0) {
                retval = &(core->service_registry[i]);
            }
        }
    }
    return retval;
}

