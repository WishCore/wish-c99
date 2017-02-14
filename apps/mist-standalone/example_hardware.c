#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mist_app.h"
#include "mist_model.h"
#include "mist_handler.h"
#include "example_hardware.h"
#include "wish_app_mist_example.h"
#include "bson.h"
#include "bson_visitor.h"
#include "wish_port_config.h"

bool relay_state = false;

enum mist_error hw_read_relay(mist_ep* ep, void* result) {
    bool* bool_result = result;
    *bool_result = relay_state;

    return MIST_NO_ERROR;
}

enum mist_error hw_write_relay(mist_ep* ep, void* new_value) {
    bool* bool_value = new_value;
    relay_state = *bool_value;

    printf("Write to endpoint %s : %s\n", ep->label, relay_state == true ? "true" : "false");

    return MIST_NO_ERROR;
}

enum mist_error hw_read_string(mist_ep* ep, void* result) {
    memcpy(result, "Morjens", 8);
    
    return MIST_NO_ERROR;
}

enum mist_error hw_invoke_function(mist_ep* ep, mist_buf args) {
    printf("in hw_invoke_function\n");
    bson_visit(args.base, elem_visitor);
    
    int32_t response_max_len = WISH_PORT_RPC_BUFFER_SZ;
    uint8_t response[response_max_len];
    
    int rpc_id = 0;
    if (bson_get_int32(args.base, "id", &rpc_id) == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Could not snatch rpc id! %d", rpc_id);
        return MIST_ERROR;
    }
    
    bson bs;
    bson_init_buffer(&bs, response, response_max_len);
    bson_append_start_object(&bs, "data");
    bson_append_int(&bs, "number", 7);
    bson_append_bool(&bs, "cool", true);
    bson_append_finish_object(&bs);
    bson_finish(&bs);
    
    bson_iterator it;
    bson_iterator sit;
    bson_find_from_buffer(&it, args.base, "args");
    bson_iterator_subiterator(&it, &sit);
    bson_find_fieldpath_value("key1", &sit);
    printf("key1: %s\n", bson_iterator_string(&sit));
    bson_find_fieldpath_value("key2", &sit);
    printf("key2: %s\n", bson_iterator_string(&sit));
    mist_invoke_response(&(get_mist_app())->device_rpc_server, rpc_id, (uint8_t*) bson_data(&bs)); 

    return MIST_NO_ERROR;
}

