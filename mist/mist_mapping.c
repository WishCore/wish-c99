#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include "mist_model.h"
#include "mist_app.h"
#include "mist_mapping.h"
#include "bson.h"
#include "bson_visitor.h"

#include "wish_debug.h"
#include "wish_app.h"
#include "wish_rpc.h"
#include "wish_fs.h"

static void mist_mapping_save_to_nvram(mist_app_t *mist_app);
static void mist_mapping_load_from_nvram(mist_app_t *mist_app);

/* FIXME move the mapping store to be part of the Mist app's context, or model?*/
static mist_mapping_t mapping_store[MAPPINGS_MAX];
static bool initialised;
static int next_mapping_id;

static void mist_mapping_init(mist_app_t *mist_app) {
    mist_mapping_load_from_nvram(mist_app);
    initialised = true;
}

static mist_mapping_t* mist_mapping_get_free(void) {
    mist_mapping_t *free = NULL;
    int i = 0;
    for (i = 0; i < MAPPINGS_MAX; i++) {
        if (mapping_store[i].occupied == false) {
            free = &(mapping_store[i]);
            break;
        }
    }
    return free;
}

bool mist_mapping_save(mist_app_t *mist_app, wish_protocol_peer_t *peer, char *mapping_id, char *src_epid, char *dst_epid) {
    if (!initialised) { mist_mapping_init(mist_app); }
    
    mist_mapping_t *mapping = mist_mapping_get_free();
    if (mapping == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Cannot get a free mapping context");
        return false;
    }
    uint8_t *wsid = mist_app->app->wsid;
    memcpy(mapping->wsid, wsid, WISH_WSID_LEN);
    memcpy(&mapping->peer, peer, sizeof (wish_protocol_peer_t));
    strncpy(mapping->mapping_id, mapping_id, MAPPING_ID_LEN-1);
    strncpy(mapping->src_endpoint_id, src_epid, MIST_STRING_EP_MAX_LEN);
    strncpy(mapping->dst_endpoint_id, dst_epid, MIST_STRING_EP_MAX_LEN);
    mapping->occupied = true;
    /* Save all mappings to stable storage */
    mist_mapping_save_to_nvram(mist_app);
    return true;
}



static mist_mapping_t* mist_mapping_get_entry(mist_app_t *mist_app, mist_ep *ep) {
    mist_mapping_t *entry = NULL;
    int i = 0;
    for (i = 0; i < MAPPINGS_MAX; i++) {
        if (mapping_store[i].occupied) {
            WISHDEBUG(LOG_DEBUG, "Found occupied slot");
            if (memcmp(mist_app->app->wsid, mapping_store[i].wsid, WISH_WSID_LEN) == 0) {
                WISHDEBUG(LOG_DEBUG, "Found something with wsid");
                if (strncmp(ep->id, mapping_store[i].src_endpoint_id, MIST_STRING_EP_MAX_LEN-1) == 0) {
                    WISHDEBUG(LOG_DEBUG, "Found mapping entry!");
                    entry = &mapping_store[i];
                    break;
                }
                else {
                    WISHDEBUG(LOG_DEBUG, "... nothing with %s. Would have had for %s, 'tho", ep->id, mapping_store[i].src_endpoint_id );
                }
            }
        }
        else {
            WISHDEBUG(LOG_DEBUG, "Was not occupied!");
        }
        
    }
    return entry;
}



void mist_mapping_notify(struct mist_model *model, mist_ep *ep) {
    
    mist_app_t *mist_app = (mist_app_t *) model->mist_app;
    
    if (!initialised) { mist_mapping_init(mist_app); }
    
    mist_mapping_t *mapping = mist_mapping_get_entry(mist_app, ep);
    if (mapping == NULL) {
        /* No mapping found for this endpoint */
        WISHDEBUG(LOG_DEBUG, "No mapping found for this subscriber");
        return;
    }
            
    
    
    WISHDEBUG(LOG_CRITICAL, "Notifying subscriber");
    
    wish_app_t *app = wish_app_find_by_wsid(mapping->wsid);
    if (app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Could not get corresponding wish_app");
        return;
    }
    // send control.notify request
    size_t notify_buf_len = 100;
    uint8_t notify_buf[notify_buf_len];
    bson notify;
    bson_init_buffer(&notify, notify_buf, notify_buf_len);
    bson_append_start_array(&notify, "args");
    bson_append_string(&notify, "0", mapping->dst_endpoint_id);
    bson_append_string(&notify, "1", mapping->mapping_id);
    switch (ep->type) {
        case MIST_TYPE_BOOL:
        {
            bool value;
            ep->read(ep, &value);
            bson_append_bool(&notify, "2", value);
            break;
        }
        case MIST_TYPE_INT:
        {
            int32_t value;
            ep->read(ep, &value);
            bson_append_int(&notify, "2", value);
            break;
        } 
        case MIST_TYPE_FLOAT:
        {
            double value;
            ep->read(ep, &value);
            bson_append_double(&notify, "2", value);
            break;
        }
        case MIST_TYPE_STRING:
        {
            char *str_ptr = NULL;
            ep->read(ep, &str_ptr);
            bson_append_string(&notify, "2", str_ptr);
            break;
        }
        default:
            WISHDEBUG(LOG_CRITICAL, "Can't notify on this type");
    }
    
    bson_append_finish_array(&notify);
    bson_finish(&notify);
    if (notify.err) {
        WISHDEBUG(LOG_CRITICAL, "BSON error while creating notify message!");
        return;
    }
    
    int obuf_len = notify_buf_len + 100;
    char obuf[obuf_len];
    wish_rpc_client_bson(&mist_app->ucp_handler.rpc_client, "control.notify", (uint8_t*)bson_data(&notify), bson_size(&notify), NULL, obuf, obuf_len);
    bson obson;
    bson_init_buffer(&obson, obuf, obuf_len);
    bson_visit(obuf, elem_visitor);
    wish_app_send(mist_app->app, &mapping->peer, (uint8_t *) bson_data(&obson), bson_size(&obson), NULL);
}



int mist_mapping_get_new_id(mist_app_t *mist_app) {
    if (!initialised) { mist_mapping_init(mist_app); }
    return next_mapping_id++;
}

static mist_mapping_t* mist_mapping_get_entry_by_mapping_id(mist_app_t *mist_app, char *mapping_id) {
    mist_mapping_t *entry = NULL;
    int i = 0;
    for (i = 0; i < MAPPINGS_MAX; i++) {
        if (mapping_store[i].occupied) {
            if (memcmp(mist_app->app->wsid, mapping_store[i].wsid, WISH_WSID_LEN) == 0) {
                if (strncmp(mapping_id, mapping_store[i].mapping_id, MAPPING_ID_LEN-1) == 0) {
                    entry = &mapping_store[i];
                    break;
                }
            }
        }
        
    }
    return entry;
}

void mist_mapping_delete(mist_app_t *mist_app, wish_protocol_peer_t *peer, char *mapping_id) {
    if (!initialised) { mist_mapping_init(mist_app); }
    mist_mapping_t *mapping = mist_mapping_get_entry_by_mapping_id(mist_app, mapping_id);
    if (mapping == NULL) {
        WISHDEBUG(LOG_CRITICAL, "No mapping with mapping id '%s' found", mapping_id);
        return;
    }
    if (memcmp(peer, &mapping->peer, WISH_ID_LEN) != 0) {
        WISHDEBUG(LOG_CRITICAL, "Mapping delete: Only the peer who made the mapping may delete it!");
        return;
    }
    /* Clear the mapping */
    memset(mapping, 0, sizeof (mist_mapping_t));
    
    /* Update the mapping database on stable storage */
    mist_mapping_save_to_nvram(mist_app);
}

#define MAPPINGS_FILE   "mappings.bin"
 
static void mist_mapping_save_to_nvram(mist_app_t *mist_app) {
    wish_fs_remove(MAPPINGS_FILE);
    wish_file_t fd = wish_fs_open(MAPPINGS_FILE);
    if (fd <= 0) {
        WISHDEBUG(LOG_CRITICAL, "Error opening file!");
    }
    wish_fs_lseek(fd, 0, WISH_FS_SEEK_SET);
    /* In the beginning of file, put the current "next mapping id" */
    wish_fs_write(fd, (void*) &next_mapping_id, sizeof (next_mapping_id));
    /* Then, write the mapping store */
    int mapping_store_size = sizeof (mapping_store);
    wish_fs_write(fd, ((void*)mapping_store), mapping_store_size);
    wish_fs_close(fd);
}

static void mist_mapping_load_from_nvram(mist_app_t *mist_app) {
    wish_file_t fd = wish_fs_open(MAPPINGS_FILE);
    if (fd <= 0) {
        WISHDEBUG(LOG_CRITICAL, "Error opening file!");
    }
    wish_fs_lseek(fd, 0, WISH_FS_SEEK_SET);
    /* First, read in the next mapping id */
    int read_ret = wish_fs_read(fd, (void*) &next_mapping_id, sizeof (next_mapping_id));
    if (read_ret == 0) {
        //WISHDEBUG(LOG_CRITICAL, "Empty file, apparently");
        return;
    }
    /* Then recover the mapping store */
    int mapping_store_size = sizeof (mist_mapping_t)*MAPPINGS_MAX;
    wish_fs_read(fd, ((void*)mapping_store), mapping_store_size);
    wish_fs_close(fd);
}
