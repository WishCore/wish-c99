#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "wish_io.h"
#include "wish_identity.h"
#include "ed25519.h"
#include "mbedtls/sha256.h"
#include "wish_debug.h"
#include "wish_fs.h"
#include "cbson.h"
#include "bson_visitor.h"
#include "wish_port_config.h"
#include "wish_connection_mgr.h"

int wish_save_identity_entry(wish_identity_t *identity) {
    int num_uids_in_db = wish_get_num_uid_entries();
    wish_uid_list_elem_t uid_list[num_uids_in_db];
    int num_uids = wish_load_uid_list(uid_list, num_uids_in_db);

    if(num_uids >= WISH_PORT_MAX_UIDS) {
        // DB is full, return error
        WISHDEBUG(LOG_CRITICAL, "Too many identities in database");
        return -1;
    }
    
    const uint32_t identity_doc_max_len = sizeof (wish_identity_t) + 100;
    uint8_t identity_doc[identity_doc_max_len];
    /* Create the new BSON document in memory */
    bson_init_doc(identity_doc, identity_doc_max_len);
    bson_write_string(identity_doc, identity_doc_max_len, "alias", identity->alias);
    bson_write_binary(identity_doc, identity_doc_max_len, "uid", identity->uid, WISH_ID_LEN);
    bson_write_binary(identity_doc, identity_doc_max_len, "pubkey", identity->pubkey, WISH_PUBKEY_LEN);

    if (identity->has_privkey) {
        bson_write_binary(identity_doc, identity_doc_max_len, "privkey", identity->privkey, WISH_PRIVKEY_LEN);
    }

    size_t transports_doc_max_len = 100;
    uint8_t transports_doc[transports_doc_max_len];
    /* FIXME For now, just encode a single transport */
    if (strnlen(&(identity->transports[0][0]), WISH_MAX_TRANSPORT_LEN) > 0) {
        bson_init_doc(transports_doc, transports_doc_max_len);
        bson_write_string(transports_doc, transports_doc_max_len,
            "0", &(identity->transports[0][0]));
        bson_write_embedded_doc_or_array(identity_doc, identity_doc_max_len,
            "transports", transports_doc, BSON_KEY_ARRAY);
    }

    /* FIXME add the rest of the fields */

    int ret = wish_save_identity_entry_bson(identity_doc);
    if (ret <= 0) {
        WISHDEBUG(LOG_CRITICAL, "Failed to save identity entry");
    }
    return ret;
}

/* Save identity, expressed in BSON format, to the identity database */
int wish_save_identity_entry_bson(uint8_t *identity_doc) {
    wish_file_t fd;
    int32_t io_retval = 0;
    fd = wish_fs_open(WISH_ID_DB_NAME);
    if (fd < 0) {
        /* error */
        WISHDEBUG(LOG_CRITICAL, "could not open identity db");
        return 0;
    }

    /* FIXME Find if there is already an existing entry for this identity. If
     * there this, delete the old entry */

    /* APPEEND the new BSON document to stable storage file -  */
    io_retval = wish_fs_lseek(fd, 0, WISH_FS_SEEK_END);
    if (io_retval < 0) {
        /* error */
        WISHDEBUG(LOG_CRITICAL, "error seeking");
        return 0;
    }


    io_retval = wish_fs_write(fd, identity_doc, bson_get_doc_len(identity_doc));
    if (io_retval <= 0) {
        /* error */
        WISHDEBUG(LOG_CRITICAL, "error writing");
        return 0;
    }
    wish_fs_close(fd);

    return io_retval;

}

/** This function returns the number of entries in the identity database (number of true identities + contacts),
 * Returns the number of identities, or -1 for errors */
int wish_get_num_uid_entries(void) {
    int retval = 0;
    wish_file_t fd = wish_fs_open(WISH_ID_DB_NAME);
    wish_offset_t prev_offset = 0;

    int num_ids = 0;
    
    while (num_ids <= WISH_PORT_MAX_UIDS) {
        /* Determine length and uid of next element */
        int peek_len = sizeof (wish_identity_t) + 100;
        uint8_t peek_buf[peek_len];

        WISHDEBUG(LOG_DEBUG, "Seeking to offset %d", prev_offset);
        int io_retval = wish_fs_lseek(fd, prev_offset, WISH_FS_SEEK_SET);
        if (io_retval == -1) {
            WISHDEBUG(LOG_CRITICAL, "Error seeking");
            retval = -1;
            break;
        }
        io_retval = wish_fs_read(fd, peek_buf, peek_len);
        if (io_retval == 0) {
            WISHDEBUG(LOG_DEBUG, "End of file detected");
            /* Success exit */
            retval = num_ids;
            break;
        }
        else if (io_retval < 0) {
            WISHDEBUG(LOG_CRITICAL, "read error");
            retval = -1;
            break;
        }

        int32_t elem_len = bson_get_doc_len(peek_buf);
        if (elem_len < 4 || elem_len > peek_len) {
            WISHDEBUG(LOG_CRITICAL, "BSON Read error");
            retval =  -1;
            break;
        }
        /* Update prev offset so that we can later re-position the
         * stream */
        prev_offset+=elem_len;

        uint8_t* uid = 0;
        int32_t uid_len = 0;
        if (bson_get_binary(peek_buf, "uid", &uid, &uid_len) ==
                BSON_FAIL) {
            WISHDEBUG(LOG_CRITICAL, "Could not get uid");
            retval = -1;
            break;
        }
        WISHDEBUG(LOG_DEBUG, "Found identity!");
        num_ids++;
        
    }
    
    if (num_ids > WISH_PORT_MAX_UIDS) {
        WISHDEBUG(LOG_CRITICAL, "Number of identities in db exceeds allowable number of identities (%d)!", WISH_PORT_MAX_UIDS);
        retval = WISH_PORT_MAX_UIDS;
    }
    
    wish_fs_close(fd);
    return retval;
}


/**
 * This function returns the list of UIDs which are in the identity
 * database. A pointer to the list of UIDs are stored to the pointer given as
 * argument. 
 * Returns the number of uids in the list, or 0 if there are no
 * identities in the database, and a negative number for an error */
int wish_load_uid_list(wish_uid_list_elem_t *list, int list_len ) {

    if (list == NULL || list_len == 0) {
        return -1;
    }

    wish_file_t fd = wish_fs_open(WISH_ID_DB_NAME);
    wish_offset_t prev_offset = 0;

    int i = 0;
    for (i = 0; i < list_len; i++) {
        /* Determine length and uid of next element */
        int peek_len = sizeof (wish_identity_t) + 100;
        uint8_t peek_buf[peek_len];

        WISHDEBUG(LOG_DEBUG, "Seeking to offset %d", prev_offset);
        int io_retval = wish_fs_lseek(fd, prev_offset, WISH_FS_SEEK_SET);
        if (io_retval == -1) {
            WISHDEBUG(LOG_CRITICAL, "Error seeking");

        }
        io_retval = wish_fs_read(fd, peek_buf, peek_len);
        if (io_retval == 0) {
            WISHDEBUG(LOG_DEBUG, "End of file detected");
            break;
        }
        else if (io_retval < 0) {
            WISHDEBUG(LOG_CRITICAL, "read error");
            return -1;
        }

        int32_t elem_len = bson_get_doc_len(peek_buf);
        if (elem_len < 4 || elem_len > peek_len) {
            WISHDEBUG(LOG_CRITICAL, "BSON Read error");
            return -1;
        }
        /* Update prev offset so that we can later re-position the
         * stream */
        prev_offset+=elem_len;

        uint8_t* uid = 0;
        int32_t uid_len = 0;
        if (bson_get_binary(peek_buf, "uid", &uid, &uid_len) ==
                BSON_FAIL) {
            WISHDEBUG(LOG_CRITICAL, "Could not get uid");
            return -1;
        }
        WISHDEBUG(LOG_DEBUG, "Found identity!");
        /* Add element to uid list */
        memcpy(list[i].uid, uid, WISH_ID_LEN);
    } 
    wish_fs_close(fd);
    return i;
}


int wish_load_identity(uint8_t *uid, wish_identity_t *identity) {
    int retval = -1;

    if (uid == NULL) {
        return retval;
    }

    wish_file_t fd = wish_fs_open(WISH_ID_DB_NAME);
    wish_offset_t prev_offset = 0;

    do {
        /* Determine length and uid of next element */
        int peek_len = sizeof (wish_identity_t) + 100;
        uint8_t peek_buf[peek_len];
        /* Re-position the stream to the end of the previous BSON structure - 
         * so that the next bytes to be read will be of the next element
         * */
        int io_retval = wish_fs_lseek(fd, prev_offset, WISH_FS_SEEK_SET);
        if (io_retval == -1) {
            WISHDEBUG(LOG_CRITICAL, "Error seeking");
            break;

        }
        io_retval = wish_fs_read(fd, peek_buf, peek_len);
        if (io_retval == 0) {
            WISHDEBUG(LOG_DEBUG, "End of file detected (2)");
            break;
        }
        else if (io_retval < 0) {
            WISHDEBUG(LOG_CRITICAL, "read error");
            break;
        }

        int32_t elem_len = bson_get_doc_len(peek_buf);
        if (elem_len < 4 || elem_len > peek_len) {
            WISHDEBUG(LOG_CRITICAL, "BSON Read error");
            break;
        }
        /* Update prev offset so that we can later re-position the
         * stream */
        prev_offset+=elem_len;

        uint8_t* peek_uid = 0;
        int32_t peek_uid_len = 0;
        if (bson_get_binary(peek_buf, "uid", &peek_uid, &peek_uid_len) ==
                BSON_FAIL) {
            WISHDEBUG(LOG_CRITICAL, "Could not get uid");
            break;
        }
        if (memcmp(peek_uid, uid, WISH_ID_LEN) == 0) {
            WISHDEBUG(LOG_DEBUG, "Found identity (2)!");
            memcpy(&(identity->uid), peek_uid, WISH_ID_LEN);

            uint8_t* pubkey = 0;
            int32_t len = 0;
            if (bson_get_binary(peek_buf, "pubkey", &pubkey, &len) 
                    == BSON_FAIL) {
                WISHDEBUG(LOG_CRITICAL, "Could not load pubkey");
                break;
            }
            memcpy(&(identity->pubkey), pubkey, WISH_PUBKEY_LEN);
 
            uint8_t* privkey = 0;
            if (bson_get_binary(peek_buf, "privkey", &privkey, &len) 
                    == BSON_FAIL) {
                WISHDEBUG(LOG_DEBUG, "No privkey for this identity");
                identity->has_privkey = false;
            }
            else {
                WISHDEBUG(LOG_DEBUG, "Found privkey for identity");
                memcpy(&(identity->privkey), privkey, WISH_PRIVKEY_LEN);
                identity->has_privkey = true;
            }
            
            char* alias = NULL;
            if (bson_get_string(peek_buf, "alias", &alias, &len) 
                    == BSON_FAIL) {
                WISHDEBUG(LOG_CRITICAL, "Could not get alias");
                break;
            }
            strncpy(&(identity->alias[0]), alias, WISH_MAX_ALIAS_LEN);

            /* When we got this far, we are satisfied with import, the
             * rest is optional */
            retval = 1;

            uint8_t *transports_doc = NULL;
            int32_t transports_doc_len = 0;
            if (bson_get_array(peek_buf, "transports", &transports_doc,
                &transports_doc_len) == BSON_FAIL) {
                /* No transports found, but exit with success */
                break;
            }
            /* FIXME Just get the first transport */
            char *url = NULL;
            int32_t url_len = 0;
            if (bson_get_string(transports_doc, "0", &url, &url_len)
                    == BSON_FAIL) {
                /* No contents in transports, but exit with success
                 * anyway */
                break;
            }
            strncpy(&(identity->transports[0][0]), url, WISH_MAX_ALIAS_LEN);

            break;
        }
    } while (1); 
    wish_fs_close(fd);
    return retval;
}


// returns < 0 on error, == 0 is false, > 0 is true
int wish_identity_exists(uint8_t *uid) {
    int retval = 0;

    if (uid == NULL) {
        return -1;
    }

    wish_file_t fd = wish_fs_open(WISH_ID_DB_NAME);
    wish_offset_t prev_offset = 0;

    do {
        /* Determine length and uid of next element */
        int peek_len = sizeof (wish_identity_t) + 100;
        uint8_t peek_buf[peek_len];
        /* Re-position the stream to the end of the previous BSON structure - 
         * so that the next bytes to be read will be of the next element
         * */
        int io_retval = wish_fs_lseek(fd, prev_offset, WISH_FS_SEEK_SET);
        if (io_retval == -1) {
            WISHDEBUG(LOG_CRITICAL, "Error seeking");
            break;

        }
        io_retval = wish_fs_read(fd, peek_buf, peek_len);
        if (io_retval == 0) {
            WISHDEBUG(LOG_DEBUG, "End of file detected (2)");
            break;
        }
        else if (io_retval < 0) {
            WISHDEBUG(LOG_CRITICAL, "read error");
            break;
        }

        int32_t elem_len = bson_get_doc_len(peek_buf);
        if (elem_len < 4 || elem_len > peek_len) {
            WISHDEBUG(LOG_CRITICAL, "BSON Read error");
            break;
        }
        /* Update prev offset so that we can later re-position the
         * stream */
        prev_offset+=elem_len;

        uint8_t* peek_uid = 0;
        int32_t peek_uid_len = 0;
        if (bson_get_binary(peek_buf, "uid", &peek_uid, &peek_uid_len) ==
                BSON_FAIL) {
            WISHDEBUG(LOG_CRITICAL, "Could not get uid");
            break;
        }
        if (memcmp(peek_uid, uid, WISH_ID_LEN) == 0) {
            WISHDEBUG(LOG_DEBUG, "Found identity (2)!");
            retval = 1;
            break;
        }
    } while (1); 
    wish_fs_close(fd);
    return retval;
}


int wish_load_identity_bson(uint8_t *uid, uint8_t *identity_bson_doc,
        size_t identity_bson_doc_max_len) {
    int retval = -1;

    if (uid == NULL) {
        return retval;
    }

    wish_file_t fd = wish_fs_open(WISH_ID_DB_NAME);
    wish_offset_t prev_offset = 0;

    do {
        /* Determine length and uid of next element */
        int peek_len = sizeof (wish_identity_t) + 100;
        uint8_t peek_buf[peek_len];
        /* Re-position the stream to the end of the previous BSON structure - 
         * so that the next bytes to be read will be of the next element
         * */
        int io_retval = wish_fs_lseek(fd, prev_offset, WISH_FS_SEEK_SET);
        if (io_retval == -1) {
            WISHDEBUG(LOG_CRITICAL, "Error seeking");
            break;

        }
        io_retval = wish_fs_read(fd, peek_buf, peek_len);
        if (io_retval == 0) {
            WISHDEBUG(LOG_DEBUG, "End of file detected (2)");
            break;
        }
        else if (io_retval < 0) {
            WISHDEBUG(LOG_CRITICAL, "read error");
            break;
        }

        int32_t elem_len = bson_get_doc_len(peek_buf);
        if (elem_len < 4 || elem_len > peek_len) {
            WISHDEBUG(LOG_CRITICAL, "BSON Read error");
            break;
        }
        /* Update prev offset so that we can later re-position the
         * stream */
        prev_offset+=elem_len;

        uint8_t* peek_uid = 0;
        int32_t peek_uid_len = 0;
        if (bson_get_binary(peek_buf, "uid", &peek_uid, &peek_uid_len) ==
                BSON_FAIL) {
            WISHDEBUG(LOG_CRITICAL, "Could not get uid");
            break;
        }
        if (memcmp(peek_uid, uid, WISH_ID_LEN) == 0) {
            WISHDEBUG(LOG_DEBUG, "Found identity (3)!");
            if (identity_bson_doc_max_len >= elem_len) {
                memcpy(identity_bson_doc, peek_buf, elem_len);
                retval = 1;
            }
            else {
                WISHDEBUG(LOG_CRITICAL, "Buffer to small to copy BSON doc into!");
                retval = -1;
            }
            break;
        }
    } while (1);

    wish_fs_close(fd);
    return retval;

}

/**
 * This function calculates the uid and stores the uid matching the
 * pubkey. 
 */
void wish_pubkey2uid(uint8_t *pubkey, uint8_t *uid) {
    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0); 
    mbedtls_sha256_update(&sha256_ctx, pubkey, WISH_PUBKEY_LEN); 
    mbedtls_sha256_finish(&sha256_ctx, uid);
    mbedtls_sha256_free(&sha256_ctx);
}



static void wish_create_keypair(uint8_t *pubkey, uint8_t *privkey) {
    /* Test */
#if 0
    uint8_t seed[32] = {
        0x33, 0xda, 0x14, 0xdb, 0xf3, 0x2e, 0x01, 0xff, 0xcc, 0x2e,
        0x1e, 0x83, 0x64, 0x8b, 0x2e, 0xb1, 0x31, 0x20, 0x4c, 0x7e,
        0xda, 0x94, 0x4d, 0xe8, 0x12, 0x10, 0xa0, 0x65, 0x6c, 0x29,
        0xb1, 0x44,
    };
#else
    uint8_t seed[WISH_ED25519_SEED_LEN];
    wish_platform_fill_random(NULL, seed, WISH_ED25519_SEED_LEN);
#endif

    ed25519_create_keypair(pubkey, privkey, seed);


}


void wish_create_local_identity(wish_identity_t *id, char *alias) {
    wish_create_keypair(&(id->pubkey[0]), &(id->privkey[0]));
    id->has_privkey = true;
    wish_pubkey2uid(&(id->pubkey[0]), &(id->uid[0]));
    strncpy(&(id->alias[0]), alias, WISH_MAX_ALIAS_LEN);

    /* Encode our preferred relay server as first transport */
    wish_relay_get_preferred_server_url(&(id->transports[0][0]),
            WISH_MAX_TRANSPORT_LEN);
 
}

/* Return 1 if privkey is known, else 0 */
int wish_has_privkey(uint8_t *uid) {
    uint8_t privkey[WISH_PRIVKEY_LEN];
    if (wish_load_privkey(uid, privkey)) {
        return 0;
    }
    return 1;

}

int wish_load_pubkey(uint8_t *uid, uint8_t *dst_buffer) {
    wish_identity_t id;
    int retval = wish_load_identity(uid, &id);

    if (retval != 1) {
        WISHDEBUG(LOG_CRITICAL, "Identity not found");
        return -1;
    }

    
    memcpy(dst_buffer, id.pubkey, WISH_PUBKEY_LEN);

    return 0;

}


int wish_load_privkey(uint8_t *uid, uint8_t *dst_buffer) {
    wish_identity_t id;
    int retval = wish_load_identity(uid, &id);

    if (retval != 1) {
        WISHDEBUG(LOG_CRITICAL, "Identity not found");
        return -1;
    }

    if (id.has_privkey == false) {
        WISHDEBUG(LOG_DEBUG, "Identity found, but no privkey");
        return -1;
    }

    memcpy(dst_buffer, id.privkey, WISH_PRIVKEY_LEN);
    return 0;
}

/**
 * Populate a struct wish_identity_t based on information in a 'cert'
 * which is obtained for example from a 'friend request'
 * @param new_id a pointer to the identity struct which will be
 * populated
 * @param a pointer to BSON document from which the data will be read
 * from
 * @return 0 for success
 */
int wish_populate_id_from_cert(wish_identity_t *new_id, 
    uint8_t *cert_doc) {

    if (new_id == NULL) {
        WISHDEBUG(LOG_CRITICAL, "new_id is null");
        return 1;
    }

    int32_t pubkey_len = 0;
    uint8_t *pubkey = NULL;
    if (bson_get_binary(cert_doc, "pubkey", &pubkey, &pubkey_len) 
            != BSON_SUCCESS) {
        WISHDEBUG(LOG_CRITICAL, "Could not extract pubkey from cert");
        return 1;
    }

    int32_t alias_len = 0;
    char *alias = NULL;
    if (bson_get_string(cert_doc, "alias", &alias, &alias_len)
            != BSON_SUCCESS) {
        WISHDEBUG(LOG_CRITICAL, "Could not extract alias from cert");
        return 1;

    }

    wish_pubkey2uid(pubkey, new_id->uid);
    memcpy(new_id->pubkey, pubkey, WISH_PUBKEY_LEN);
    memcpy(new_id->alias, alias, strnlen(alias, WISH_MAX_ALIAS_LEN));
    new_id->has_privkey = false;
    memset(new_id->privkey, 0, WISH_PRIVKEY_LEN);

    /* FIXME copy transports */

    int32_t transports_len = 0;
    uint8_t *transports = NULL;
    if (bson_get_array(cert_doc, "transports", &transports, &transports_len)
            == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Could not extract transports from cert");
    }
    bson_visit("wish_populate_id_from_cert: transports:", transports);
    /* FIXME copy just the first transport */
    char *url = NULL;
    int32_t url_len = 0;
    if (bson_get_string(transports, "0", &url, &url_len) == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Could not extract first url from transports");
    }
    strncpy(&(new_id->transports[0][0]), url, url_len);

    /* FIXME update contacts */

    return 0;
}

/**
 * Remove an identity from the database 
 *
 * @param uid the uid of the identity to be removed
 * @return returns 1 if the identity was removed, or 0 for none
 */
int wish_identity_remove(wish_core_t* core, uint8_t uid[WISH_ID_LEN]) {
    int retval = 0;

    if (uid == NULL) {
        return retval;
    }

    const char *oldpath = WISH_ID_DB_NAME;
    const char *newpath = WISH_ID_DB_NAME ".tmp";
    wish_file_t old_fd = wish_fs_open(oldpath);
    wish_file_t new_fd = wish_fs_open(newpath);

    /* Truncate the new file */
    int32_t tmp = 0;
    int wr_len = wish_fs_write(new_fd, &tmp, 0);
    if (wr_len != 0) {
        WISHDEBUG(LOG_CRITICAL, "Error truncating tmp file");
    }

    wish_offset_t prev_offset = 0;

    do {
        /* Determine length and uid of next element */
        int peek_len = sizeof (wish_identity_t) + 100;
        uint8_t peek_buf[peek_len];
        /* Re-position the stream to the end of the previous BSON structure - 
         * so that the next bytes to be read will be of the next element
         * */
        int io_retval = wish_fs_lseek(old_fd, prev_offset, WISH_FS_SEEK_SET);
        if (io_retval == -1) {
            WISHDEBUG(LOG_CRITICAL, "Error seeking");
            break;

        }
        io_retval = wish_fs_read(old_fd, peek_buf, peek_len);
        if (io_retval == 0) {
            WISHDEBUG(LOG_DEBUG, "End of file detected (2)");
            break;
        }
        else if (io_retval < 0) {
            WISHDEBUG(LOG_CRITICAL, "read error");
            break;
        }

        int32_t elem_len = bson_get_doc_len(peek_buf);
        if (elem_len < 4 || elem_len > peek_len) {
            WISHDEBUG(LOG_CRITICAL, "BSON Read error");
            break;
        }
        uint8_t* peek_uid = 0;
        int32_t peek_uid_len = 0;
        if (bson_get_binary(peek_buf, "uid", &peek_uid, &peek_uid_len) ==
                BSON_FAIL) {
            WISHDEBUG(LOG_CRITICAL, "Could not get uid");
            break;
        }
        if (memcmp(peek_uid, uid, WISH_ID_LEN) == 0) {
            WISHDEBUG(LOG_DEBUG, "Remove: Found identity (2)!");
            retval = 1;
        }
        else {
            /* Write the document to new file */
            wr_len = wish_fs_write(new_fd, peek_buf, elem_len);
            if (wr_len == elem_len) {
                WISHDEBUG(LOG_DEBUG, "Writing identity to new file");
            }
            else {
                WISHDEBUG(LOG_CRITICAL, "Unexpected write len!");
            }
        }
         /* Update prev offset so that we can later re-position the
         * stream */
        prev_offset+=elem_len;
    } while (1);
    wish_fs_close(new_fd);
    wish_fs_close(old_fd);

    wish_fs_rename(newpath, oldpath);
    
    /* For all connections: if identity is either in luid or ruid, close the connection. */
    wish_context_t *wish_context_pool = wish_core_get_connection_pool(core);
    int i = 0;
    for (i = 0; i < WISH_CONTEXT_POOL_SZ; i++) {
        if (wish_context_pool[i].context_state == WISH_CONTEXT_FREE) {
            /* If the wish context is not in use, we can safely skip it */
            //WISHDEBUG(LOG_CRITICAL, "Skipping free wish context");
            continue;
        }
        if (memcmp(wish_context_pool[i].local_wuid, uid, WISH_ID_LEN) == 0) {
            WISHDEBUG(LOG_CRITICAL, "identity.remove: closing context because uid is luid of a connection");
            wish_close_connection(core, &wish_context_pool[i]);
        }
        else if (memcmp(wish_context_pool[i].remote_wuid, uid, WISH_ID_LEN) == 0) {
            WISHDEBUG(LOG_CRITICAL, "identity.remove: closing context because uid is ruid of a connection");
            wish_close_connection(core, &wish_context_pool[i]); 
        }
    }
    
    return retval;
}


void wish_identity_delete_db(void) {
    if (wish_fs_remove(WISH_ID_DB_NAME)) {
        WISHDEBUG(LOG_CRITICAL, "Unexpected while removing id db!");
    }
}

/** Get the the list of local identities, that is an array of id database entries which can be used for opening Wish connections, meaning that the privkey is also in the database.  
 * @param pointer to a caller-allocated list where result will be placed
 * @param length of the the caller-allocated list
 * @return number of local identities or 0 for an error
 */
int wish_get_local_identity_list(wish_uid_list_elem_t *list, int list_len) {
    int num_ids_in_db = wish_get_num_uid_entries();
    wish_uid_list_elem_t all_uids_list[num_ids_in_db];
    int num_uids = wish_load_uid_list(all_uids_list, num_ids_in_db);
    
    if(num_uids == 0) {
        return 0;
    }
    
    int i = 0;
    int j = 0;
    for (i = 0; i < num_uids; i++) {
        if (wish_has_privkey(all_uids_list[i].uid)) {
            memcpy(&(list[j++]), &(all_uids_list[i]), sizeof(wish_uid_list_elem_t));
        }
    }
    return j;
}