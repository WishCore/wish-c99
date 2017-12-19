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

    bson_visit("Initial state:", bson_data(&bi));
    
    bson_insert_string(&bi, "acl.roles.user", "uid3");
    bson_insert_string(&bi, "acl.roles.user", "uid6");
    
    bson b;
    bson_init(&b);
    bson_append_start_object(&b, "data");
    bson_append_start_object(&b, "connectPolicy");
    bson_append_string(&b, "abdefbda", "always");
    bson_append_string(&b, "deadbeef", "sometimes");
    bson_append_finish_object(&b);
    bson_append_finish_object(&b);
    bson_finish(&b);
    
    bson_iterator i;
    bson_iterator_init(&i, &b);
    bson_find_fieldpath_value("data.connectPolicy", &i); // "connectPolicy");
    
    printf("iterator: %i", bson_iterator_type(&i));

    bson_insert_element(&bi, "acl.permissions.root", i);
    bson_insert_element(&bi, "acl.roles.user", i);
    
    bson_destroy(&b);
    
    bson_visit("After insert:", bson_data(&bi));
    
    bson_remove_string(&bi, "acl.roles.user", "uid3");

    bson_visit("After remove:", bson_data(&bi));
    
    bson_remove_path(&bi, "acl.permissions.root");

    bson_visit("After remove:", bson_data(&bi));
    
    bson_remove_path(&bi, "acl.roles.user");

    bson_visit("After remove:", bson_data(&bi));
    
    bson_remove_path(&bi, "acl.permissions");
    bson_remove_string(&bi, "acl.roles.root", "uid1");

    bson_visit("After remove:", bson_data(&bi));
    
    bson_remove_path(&bi, "acl.roles");

    bson_visit("After remove:", bson_data(&bi));
    
    if (bi.err) {
        WISHDEBUG(LOG_CRITICAL, "We got an error while in bson_insert_string. %s", bson_first_errormsg(&bi));
    }

    
    return 0;
}
