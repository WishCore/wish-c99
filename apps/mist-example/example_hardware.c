#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "mist_model.h"
#include "mist_app.h"
#include "mist_follow_funcs.h"
#include "wish_debug.h"
#include "example_hardware.h"
#include "cbson.h"
#include "bson_visitor.h"

bool relay_state = false;
bool relay_state2 = true;

enum mist_error example_hw_read(struct mist_model *model, char * id, enum mist_type type, void * result) {
    WISHDEBUG(LOG_DEBUG, "hw read: %s, type %d", id, type);
    if (strcmp(id, "relay") == 0) {
        if (type == MIST_TYPE_BOOL) {
            bool * bool_result = result;
            *bool_result = relay_state;
        }
    } else if (strcmp(id, "relay2") == 0) {
        if (type == MIST_TYPE_BOOL) {
            bool * bool_result = result;
            *bool_result = relay_state2;
        }
    }
    else if (strcmp(id, "my_str") == 0) {
        if (type == MIST_TYPE_STRING) {
            // Note that string have a fixed max len
            memcpy(result, "Morjens", MIST_STRING_EP_MAX_LEN);
        }
    }
 
    return MIST_NO_ERROR;
}

enum mist_error example_hw_write(struct mist_model *model, char * id, enum mist_type type, void * new_value) {
    WISHDEBUG(LOG_DEBUG, "hw write: %s, type %d", id, type);
    if (strcmp(id, "relay") == 0) {
        if (type == MIST_TYPE_BOOL) {
            bool* bool_value = new_value;
            relay_state = *bool_value;
            WISHDEBUG(LOG_CRITICAL, "Relay is now %s", relay_state == true ? "on" : "off" );
        }
        mist_value_changed(model, id);
    }
    if (strcmp(id, "relay2") == 0) {
        if (type == MIST_TYPE_BOOL) {
            bool* bool_value = new_value;
            relay_state2 = *bool_value;
        }
        mist_value_changed(model, id);
    }
 
    return MIST_NO_ERROR;
}

enum mist_error example_hw_invoke(struct mist_model *model, char * id, uint8_t *args_array, uint8_t *response, size_t response_max_len) {

    WISHDEBUG(LOG_CRITICAL, "In invoke handler,  endpoint %s.", id);
    /* Get the endpoint and value from "args" array */
    char* endpoint = 0;
    int endpoint_len = 0;
    bson_get_string(args_array, "0", &endpoint, &endpoint_len);

    /* Get the arguments to invoke */
    uint8_t arg_type = 0;
    uint8_t *arg_value = NULL;
    int32_t arg_len = 0;
    if (bson_get_elem_by_name(args_array, "1", &arg_type, &arg_value,
            &arg_len) == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Could not get arguments");
        return MIST_ERROR;
    }

    switch (arg_type) {
    case BSON_KEY_DOCUMENT:
    case BSON_KEY_ARRAY:
        WISHDEBUG(LOG_CRITICAL, "Got a document (or array) parameter:");
        bson_visit(arg_value, elem_visitor);
        break;
    case BSON_KEY_INT32:
        WISHDEBUG(LOG_CRITICAL, "Got a int parameter: %d", *arg_value);
        break;
    case BSON_KEY_BOOLEAN:
        WISHDEBUG(LOG_CRITICAL, "Got a bool parameter: %d", *arg_value);
        break;
    case BSON_KEY_STRING:
        WISHDEBUG(LOG_CRITICAL, "Got a string parameter of len: %s", arg_value);
        break;
    default:
        WISHDEBUG(LOG_CRITICAL, "Unhandled argument type %hhx", arg_type);
        break;
    }

    return MIST_NO_ERROR;
}

void example_hw_init(struct mist_model *model) {
    mist_set_ep_read_fn(model, example_hw_read);
    mist_set_ep_write_fn(model, example_hw_write);
    mist_set_ep_invoke_fn(model, example_hw_invoke);
}
