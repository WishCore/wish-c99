#include "wish_config.h"
#include "wish_version.h"
#include "wish_debug.h"
#include "wish_fs.h"
#include "bson.h"
#include "string.h"
#include "wish_relay_client.h"

#include "utlist.h"

#include "bson_visit.h"

#include "bson.h"
#include "wish_debug.h"
#include <stdint.h>
#include <string.h>





typedef struct {
    bson *bsout;
    //const void *bsdata2; //bsdata to merge with
    int nstack; //nested object stack pos
    //int matched; //number of matched merge fields
} _BSONMERGE3CTX;

static bson_visitor_cmd_t _bson_append_into_visitor(
        const char *ipath, int ipathlen, 
        const char *key, int keylen,
        const bson_iterator *it, 
        bool after, void *op) {
            
    _BSONMERGE3CTX *ctx = op;

    bson_type bt = BSON_ITERATOR_TYPE(it);
    
    char tpath[128];
    memcpy(tpath, ipath, ipathlen);
    tpath[ipathlen] = 0;
    
    WISHDEBUG(LOG_CRITICAL, "path: %s %s %s", tpath, bson_type_string(bt), after ? "after" : "before");
    
    /*
    if (bt == BSON_OBJECT || bt == BSON_ARRAY) {
        if (!after) {
            ctx->nstack++;
            if (bt == BSON_OBJECT) {
                bson_append_start_object2(ctx->bsout, key, keylen);
            } else if (bt == BSON_ARRAY) {
                bson_append_start_array2(ctx->bsout, key, keylen);
            }
            return BSON_VCMD_OK;
        } else {
            if (ctx->nstack > 0) {
                //do we have something to add into end of nested object?
                
                //bson_append_fpath_from_iterator(mpath + i + 1, &it2, ctx->bsout);
                
                ctx->nstack--;
                if (bt == BSON_OBJECT) {
                    bson_append_finish_object(ctx->bsout);
                } else if (bt == BSON_ARRAY) {
                    bson_append_finish_array(ctx->bsout);
                }
            }
            return BSON_VCMD_OK;
        }
    } else {
        bson_append_field_from_iterator(it, ctx->bsout);
        return BSON_VCMD_SKIP_AFTER;
    }
    */
    return BSON_VCMD_OK;
}

/*
 * This function traverses the bson_doc given as argument, and calls the
 * visitor_func for every element encountered. Document and
 * array elements be recursively handled in the same way. */
static void bson_append_into_inner(const bson* bs, const char* path) {
    bson_iterator i;
    bson_iterator_init(&i, bs);

    _BSONMERGE3CTX ctx = {
        .bsout = NULL,
        .nstack = 0
    };
    
    bson_visit_fields(&i, 0, _bson_append_into_visitor, &ctx);
}

/*
 * This function traverses the bson_doc given as argument, and calls the
 * visitor_func for every element encountered. Document and
 * array elements be recursively handled in the same way. */
static void bson_append_into(const bson* from, bson* to, const char* path) {
    bson_visit("bson_append_into:", bson_data(from));
    bson_append_into_inner(from, path);
}

int wish_core_config_load(wish_core_t* core) {
    wish_file_t fd = wish_fs_open(WISH_CORE_CONFIG_DB_NAME);
    if (fd <= 0) {
        WISHDEBUG(LOG_CRITICAL, "Error opening file! Configuration could not be loaded! " WISH_CORE_CONFIG_DB_NAME);
        return -1;
    }
    wish_fs_lseek(fd, 0, WISH_FS_SEEK_SET);

    int size = 0;
    
    /* First, read in the next mapping id */
    int read_ret = wish_fs_read(fd, (void*) &size, 4);

    if (read_ret != 4) {
        WISHDEBUG(LOG_CRITICAL, "Empty file, or read error in configuration load." WISH_CORE_CONFIG_DB_NAME);
        wish_core_config_save(core);
        return -2;
    }

    if(size>4*1024) {
        WISHDEBUG(LOG_CRITICAL, "Configuration load, file too large (4KiB limit). Found: %i bytes.", size);
        return -3;
    }
    
    bson bs;
    bson_init_size(&bs, size);
    
    /* Go back to start and read the whole file to bson buffer */
    wish_fs_lseek(fd, 0, WISH_FS_SEEK_SET);
    read_ret = wish_fs_read(fd, ((void*)bs.data), size);
    
    if (read_ret != size) {
        WISHDEBUG(LOG_CRITICAL, "Configuration failed to read %i bytes, got %i.", size, read_ret);
    }
    
    wish_fs_close(fd);
    
    //bson_visit("Configuration loaded this bson", bson_data(&bs));
    
    // read host id
    bson_iterator it;
    bson_find_from_buffer(&it, bs.data, "id");
    
    if ( BSON_BINDATA == bson_iterator_type(&it) && bson_iterator_bin_len(&it) == WISH_WHID_LEN ) {
        memcpy(core->id, bson_iterator_bin_data(&it), WISH_WHID_LEN);
    } else {
        WISHDEBUG(LOG_CRITICAL, "Failed reading hostid!");
    }
    
    
    // read relay servers list
    if ( bson_find_from_buffer(&it, bs.data, "relay") == BSON_ARRAY ) {

        int si = 0;
        char sindex[21];

        while (true) {
            BSON_NUMSTR(sindex, si++);
            bson_iterator sit;

            bson_iterator_subiterator(&it, &sit);
            bson_type type = bson_find_fieldpath_value(sindex, &sit);
            
            if ( type == BSON_EOO ) { break; }
            if ( type != BSON_STRING ) { continue; }
            
            const char* host = bson_iterator_string(&sit);
            
            wish_relay_client_add(core, host);
        }
    }

    bson bi;
    bson_init_size(&bi, 512);
    bson_append_start_object(&bi, "acl");
    bson_append_start_object(&bi, "roles");
    bson_append_start_array(&bi, "root");
    bson_append_string(&bi, "0", "uid1");
    bson_append_finish_array(&bi);
    bson_append_start_array(&bi, "user");
    bson_append_string(&bi, "0", "uid1");
    bson_append_string(&bi, "1", "uid2");
    bson_append_finish_array(&bi);
    bson_append_finish_object(&bi);

    bson_append_start_object(&bi, "permissions");
    bson_append_start_object(&bi, "root");
    bson_append_start_array(&bi, "remote_identity_list");
    bson_append_string(&bi, "0", "call");
    bson_append_finish_array(&bi);
    bson_append_start_array(&bi, "remote_identity_remove");
    bson_append_string(&bi, "0", "call");
    bson_append_finish_array(&bi);
    bson_append_finish_object(&bi);
    bson_append_start_object(&bi, "user");
    bson_append_start_array(&bi, "remote_identity_list");
    bson_append_string(&bi, "0", "call");
    bson_append_finish_array(&bi);
    bson_append_finish_object(&bi);
    bson_append_finish_object(&bi);
    
    bson_append_finish_object(&bi);
    bson_finish(&bi);
    
    bson bo;
    bson_init_size(&bo, 512);
    
    bson_append_into(&bi, &bo, "acl");
    
    bson_finish(&bo);
    
    bson_destroy(&bs);
    
    return 0;
}

int wish_core_config_save(wish_core_t* core) {
    wish_file_t fd;
    int32_t ret = 0;
    wish_fs_remove(WISH_CORE_CONFIG_DB_NAME);
    fd = wish_fs_open(WISH_CORE_CONFIG_DB_NAME);
    if (fd < 0) {
        /* error */
        WISHDEBUG(LOG_CRITICAL, "could not open configuration db");
        return -1;
    }

    int buf_len = 4*1024;
    char buf[buf_len];
    
    bson bs;
    bson_init_buffer(&bs, buf, buf_len);
    bson_append_string(&bs, "version", WISH_CORE_VERSION_STRING);
    bson_append_binary(&bs, "id", core->id, WISH_WHID_LEN);

    if (core->relay_db != NULL) {
        wish_relay_client_t* relay;
        
        bson_append_start_array(&bs, "relay");
            
        int i = 0;
        char index[21];
        
        LL_FOREACH(core->relay_db, relay) {
            
            char host[22];
            snprintf(host, 22, "%d.%d.%d.%d:%d", relay->ip.addr[0], relay->ip.addr[1], relay->ip.addr[2], relay->ip.addr[3], relay->port);
            
            BSON_NUMSTR(index, i++);
            bson_append_string(&bs, index, host);
        }
        
        bson_append_finish_array(&bs);
    }
    
    bson_finish(&bs);

    ret = wish_fs_write(fd, bson_data(&bs), bson_size(&bs));

    //bson_visit("Configuration saved this bson", (char*) bson_data(&bs));

    bson_destroy(&bs);
    
    if (ret <= 0) {
        /* error */
        WISHDEBUG(LOG_CRITICAL, "error writing configuration");
        return -3;
    }
    wish_fs_close(fd);

    return ret;

}