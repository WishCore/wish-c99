/* 
 * File:   mist_mapping.h
 * Author: jan
 *
 * Created on December 1, 2016, 2:20 PM
 */

#ifndef MIST_MAPPING_H
#define MIST_MAPPING_H

#ifdef __cplusplus
extern "C" {
#endif

#include "wish_protocol.h"
#include "mist_model.h"
#include "wish_app.h"
    
#define MAPPINGS_MAX 2
    
#define MAPPING_ID_LEN 10

typedef struct {
    bool occupied;
    /* The peer which made this mapping */
    wish_protocol_peer_t peer;
    char mapping_id[MAPPING_ID_LEN];
    /* The endpoint id which is the target of this mapping (from the point of view of control.map) */
    char dst_endpoint_id[MIST_STRING_EP_MAX_LEN];
    /* The endpoint id which is the src of this mapping (from the point of view of control.map) */
    char src_endpoint_id[MIST_STRING_EP_MAX_LEN];
    /* The service id of the device that has is the target of this mapping. Note: this will be removed when mappings are moved to be part of app struct */
    uint8_t wsid[WISH_WSID_LEN];
} mist_mapping_t;

//void mist_mapping_init(mist_app_t *mist_app);

bool mist_mapping_save(mist_app_t *mist_app, wish_protocol_peer_t *peer, char *unique_id, char *src_epid, char *dst_epid);

void mist_mapping_notify(struct mist_model *model, mist_ep *ep);

int mist_mapping_get_new_id(mist_app_t *mist_app);

void mist_mapping_delete(mist_app_t *mist_app, wish_protocol_peer_t *peer, char *mapping_id);



#ifdef __cplusplus
}
#endif

#endif /* MIST_MAPPING_H */

