#ifndef WISH_SERVICE_REGISTRY_H
#define WISH_SERVICE_REGISTRY_H

#include "wish_app.h"

#define WISH_MAX_SERVICES 5 /* contrast with NUM_WISH_APPS due to be
removed in wish_app.h */

#if WISH_MAX_SERVICES != NUM_WISH_APPS
#error WISH_MAX_SERVICES != NUM_WISH_APPS
#endif


struct wish_service_entry {
    uint8_t wsid[WISH_WSID_LEN];
    char service_name[WISH_APP_NAME_MAX_LEN];
    uint8_t protocols[WISH_PROTOCOL_NAME_MAX_LEN][WISH_APP_MAX_PROTOCOLS]; 
    //uint8_t permissions[WISH_PERMISSION_NAME_MAX_LEN][WISH_APP_MAX_PERMISSIONS];
};



void wish_service_register_add(uint8_t *src_wsid, char *name, 
    uint8_t *protocols_array, uint8_t *permissions_array);

void wish_service_register_remove(uint8_t *wsid);

struct wish_service_entry * wish_service_get_registry(void);
bool wish_service_entry_is_valid(struct wish_service_entry *entry);

struct wish_service_entry *wish_service_get_entry(uint8_t *wsid);



#endif  //WISH_SERVICE_REGISTRY_H
