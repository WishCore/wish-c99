#include "wish_core.h"
#include "wish_identity.h"

#include "stdio.h"
#include "string.h"

int wish_core_update_identities(wish_core_t* core) {
    
    core->num_ids = wish_get_num_uid_entries();
    //printf("Number of identities in db: %i\n", num_ids);

    /* Load local user database (UID list) */
    memset(core->uid_list, 0, sizeof(core->uid_list));
    core->loaded_num_ids = wish_load_uid_list(core->uid_list, core->num_ids);
    
    //printf("Number of loaded identities: %i\n", core->loaded_num_ids);
    
    int i = 0;
    for (i = 0; i < core->num_ids; i++) {
        wish_identity_t recovered_id;
        memset(&recovered_id, 0, sizeof (wish_identity_t));
        int load_retval = wish_load_identity(core->uid_list[i].uid, &recovered_id);
        //printf("Loaded identity (ret %i), alias: %s\n", load_retval, recovered_id.alias);
    }
    return 0;
}
