#include "wish_port_config.h"
#include "wish_debug.h"
#include "bson.h"
#include "bson_visit.h"

#include "fs_port.h"

#include <stdlib.h>
#include <stdio.h>

int main(int argc, char** argv) {
    wish_platform_set_malloc(malloc);
    wish_platform_set_realloc(realloc);
    wish_platform_set_free(free);
    
    wish_platform_set_rng(random);
    wish_platform_set_vprintf(vprintf);
    wish_platform_set_vsprintf(vsprintf);

    wish_fs_set_open(my_fs_open);
    wish_fs_set_read(my_fs_read);
    wish_fs_set_write(my_fs_write);
    wish_fs_set_lseek(my_fs_lseek);
    wish_fs_set_close(my_fs_close);
    wish_fs_set_rename(my_fs_rename);
    wish_fs_set_remove(my_fs_remove);
    
    WISHDEBUG(LOG_CRITICAL, "Running BSON test.");


    bson bi;
    bson_init_size(&bi, 512);
    bson_append_start_object(&bi, "bones");
    bson_append_finish_object(&bi);
    bson_append_start_object(&bi, "fees");
    bson_append_finish_object(&bi);
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
    
    bson_append_start_object(&bi, "last");
    bson_append_finish_object(&bi);
    bson_finish(&bi);

    bson_visit("Initial state:", bson_data(&bi));
    
    bson update;
    bson_init(&update);
    bson_append_null(&update, "acl");
    bson_append_start_object(&update, "fees");
    bson_append_string(&update, "text", "low");
    bson_append_double(&update, "number", 0.3);
    bson_append_finish_object(&update);
    bson_finish(&update);
    
    bson_visit("update:", bson_data(&update));
    
    bson_update(&bi, &update); //, &result);

    bson_visit("result:", bson_data(&bi));
    
    bson_destroy(&update);
    
    if (bi.err) {
        WISHDEBUG(LOG_CRITICAL, "We got an error while in bson_insert_string. %s", bson_first_errormsg(&bi));
    }
    
    return 0;
}
