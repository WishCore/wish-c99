#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "mist_follow.h"
#include "mist_model.h"
#include "wish_debug.h"
#include "mist_handler.h"
#include "bson.h"
#include "mist_mapping.h"


void 
#ifdef COMPILING_FOR_ESP8266
__attribute__((section(".text"))) 
#endif
mist_value_changed(struct mist_model *model, char* ep_id) {
    int i = 0;
    mist_ep* ep;
    if (mist_find_endpoint_by_name(model, ep_id, &ep)) {
        return;
    }
    ep->dirty = true;
    mist_follow_task_signal(model, ep);

}

// FIXME This should really not need to be dependent on the COMPILING_FOR_ESP8266
#ifndef COMPILING_FOR_ESP8266
void mist_follow_task_signal(struct mist_model *model, mist_ep* endpoint) {
    mist_follow_task();
    /* Send notify messages for any mappings we might have */
    mist_mapping_notify(model, endpoint);
}
#endif

extern mist_app_t mist_apps[];

/* Once signaled, this task will send a "follow" message, if sending is
 * allowed, or signal its own event queue so that the call is deferred
 * to alter time.  */
void mist_follow_task(void) {
    /* Iterate through all the Mist apps we have */
    int i = 0;
    for (i = 0; i < NUM_MIST_APPS; i++) {
        if (mist_apps[i].occupied == false) {
            continue;
        }

        /* FIXME this can be optimized further!*/
        mist_ep* curr_ep = mist_apps[i].model.endpoint_list;
        /* Iterate through list of endpoints in the app's model */
        while (curr_ep != NULL) {
            if (curr_ep->dirty == true) {
                WISHDEBUG(LOG_DEBUG, "Dirty EP found: %s", curr_ep->id);
                generate_mist_follow_msg(&(mist_apps[i]), curr_ep);
                curr_ep->dirty = false;
            }
            curr_ep = curr_ep->next;
        }
    }
}



/**
 * Generate a follow message
 *
 * @return the App RPC id of the follow reply which was sent down
 */
void generate_mist_follow_msg(mist_app_t *mist_app, mist_ep* ep) {
    WISHDEBUG(LOG_DEBUG, "Generate follow message");
    
    /* This defines the maximum length of a follow reply's data element */
    int data_doc_max_len = 128;
    uint8_t data_doc[data_doc_max_len];

    bson bs;
    bson_init_buffer(&bs, data_doc, data_doc_max_len);
    bson_append_start_object(&bs, "data");
    bson_append_string(&bs, "id", ep->id);
    switch (ep->type) {
    case MIST_TYPE_INT:
        {
            int32_t value = 0;
            ep->read(ep, &value);
            bson_append_int(&bs, "data", value);
        }
        break;
    case MIST_TYPE_BOOL:
        {
            bool value = false;
            ep->read(ep, &value);
            bson_append_bool(&bs, "data", value);
        }
        break;
    case MIST_TYPE_FLOAT:
        {
            double value = 0.0;
            ep->read(ep, &value);
            bson_append_double(&bs, "data", value);
        }
        break;
    case MIST_TYPE_STRING:
        {
            /* FIXME This situation clearly illustrates that we should
             * pass the length of the object down the reader function.
             * Now we need to define that string endpoints have a
             * maximum length! */
            char string[MIST_STRING_EP_MAX_LEN + 1];
            ep->read(ep, string);
            string[MIST_STRING_EP_MAX_LEN] = 0; /* Ensure null termination */
            bson_append_string(&bs, "data", string);
        }
        break;
    case MIST_TYPE_INVOKE:
        /* Following an "invoke" is not meaningful */
        WISHDEBUG(LOG_DEBUG, "Following an type invoke is not meaningful");
        return;
        break;
    default:
        WISHDEBUG(LOG_CRITICAL, "Follow for unhandled endpoint type: %i", ep->type);
        return;
        break;
    } 
    bson_append_finish_object(&bs);
    bson_finish(&bs);
    if (bs.err) {
        WISHDEBUG(LOG_CRITICAL, "BSON error while constructing follow reply. Not emitting.");
    }
    else {
        //WISHDEBUG(LOG_CRITICAL, "control.follow broadcast:");
        //bson_visit((char*)bson_data(&bs), elem_visitor);
        wish_rpc_server_emit_broadcast(&(mist_app->device_rpc_server), "control.follow", bson_data(&bs), bson_size(&bs));
    }
}


