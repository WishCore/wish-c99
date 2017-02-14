#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "mist_model.h"
#include "wish_platform.h"
#include "cbson.h"
#include "wish_debug.h"
#include "wish_utils.h"
#include "bson.h"

/* This function will generate a complete "model" document, which is to
 * be embedded in the "data" document of the control.model reply. 
 * The document will be created in the buffer supplied as parameter
 * "model_doc". The buffer will be initialised as a document first.
 * The caller must make sure that the array is large enough, or else the
 * operation will fail and error is returned. 
 * */
int model_generate_bson(struct mist_model *model, bson *bs) {
    
    if (model->name != NULL) {
        bson_append_string(bs, "device", model->name);
    }
    
    bson_append_start_object(bs, "model");
    bson_append_start_object(bs, "mist");
    if (model->name != NULL) {
        bson_append_string(bs, "name", model->name);
    }
    if (model->custom_ui_url != NULL) {
        bson_append_string(bs, "type", "meta");
        bson_append_string(bs, "tag", "mist-ui-package");
        bson_append_string(bs, "value", model->custom_ui_url);
    }
    bson_append_finish_object(bs);  // End of 'mist' document
    
    mist_ep* curr_ep = model->endpoint_list;
    while (curr_ep != NULL) {
        bson_append_start_object(bs, curr_ep->id);
        bson_append_string(bs, "label", curr_ep->label);
        char* type_str = "";
        switch (curr_ep->type) {
        case MIST_TYPE_BOOL:
            type_str = "bool";
            break;
        case MIST_TYPE_FLOAT:
            type_str = "float";
            break;
        case MIST_TYPE_INT:
            type_str = "int";
            break;
        case MIST_TYPE_STRING:
            type_str = "string";
            break;
        case MIST_TYPE_INVOKE:
            type_str = "invoke";
            break;
        }
        bson_append_string(bs, "type", type_str);
        
        if (curr_ep->unit && strnlen(curr_ep->unit, 1)>0) {
            bson_append_string(bs, "unit", curr_ep->unit); }
        if (curr_ep->readable) {
            bson_append_bool(bs, "read", curr_ep->readable); }
        if (curr_ep->writable) {
            bson_append_bool(bs, "write", curr_ep->writable); }
        if (curr_ep->invokable) {
            bson_append_bool(bs, "invoke", curr_ep->invokable); }
        if (curr_ep->scaling != NULL && strnlen(curr_ep->scaling, 1)>0) {
            bson_append_string(bs, "scale", curr_ep->scaling);
        }

        /* TODO mappings */
        
        bson_append_finish_object(bs);
        curr_ep = curr_ep->next;
    }
    bson_append_finish_object(bs);  /* End of 'model' document */
 
    if (bs->err) {
        WISHDEBUG(LOG_CRITICAL, "Bson error %d in mist model", bs->err);
    }
    return 0;
}


enum mist_error mist_add_endpoint(struct mist_model *model, 
        char * id, char * label, enum mist_type type, char * unit, 
        enum mist_error (*read)(mist_ep* ep, void* result),
        enum mist_error (*write)(mist_ep* ep, void* value),
        enum mist_error (*invoke)(mist_ep* ep, mist_buf args)
        ) {

    enum mist_error retval = MIST_NO_ERROR;

    mist_ep* last_ep = 0;
    if (mist_endpoint_last(model, &last_ep)) {
        WISHDEBUG(LOG_CRITICAL, "Fail");
        return MIST_ERROR;
    }
    mist_ep* new_ep = 0;

    new_ep = (mist_ep*) wish_platform_malloc(sizeof (mist_ep));
    if (new_ep == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Malloc fail");

        return MIST_MALLOC_FAIL;
    }
    memset(new_ep, 0, sizeof (mist_ep));

    if (last_ep != NULL) {
        last_ep->next = new_ep;
        new_ep->prev = last_ep;
    }
    else {
        model->endpoint_list = new_ep;
    }
    new_ep->model = model;
    new_ep->next = NULL;
    new_ep->id = my_strdup(id);
    new_ep->label = my_strdup(label);
    new_ep->type = type;
    new_ep->unit = my_strdup(unit);
    new_ep->readable = read != NULL;
    new_ep->writable = write != NULL;
    new_ep->invokable = invoke != NULL;
    new_ep->read = read;
    new_ep->write = write;
    new_ep->invoke = invoke;
    model->num_endpoints++;

    return retval;
}

enum mist_error mist_add_ep(struct mist_model *model, mist_ep* ep) {

    enum mist_error retval = MIST_NO_ERROR;

    mist_ep* last_ep = 0;
    if (mist_endpoint_last(model, &last_ep)) {
        WISHDEBUG(LOG_CRITICAL, "Fail");
        return MIST_ERROR;
    }

    if (last_ep != NULL) {
        last_ep->next = ep;
        ep->prev = last_ep;
    }
    else {
        model->endpoint_list = ep;
    }
    ep->model = model;
    ep->readable = ep->read != NULL;
    ep->writable = ep->write != NULL;
    ep->invokable = ep->invoke != NULL;
    model->num_endpoints++;

    return retval;
}

enum mist_error mist_delete_endpoint(struct mist_model *model, char * id) {
    enum mist_error retval = MIST_NO_ERROR;

    mist_ep* target_ep;

    if (mist_find_endpoint_by_name(model, id, &target_ep)) {
        WISHDEBUG(LOG_CRITICAL, "Could not find the endpoint %s", id);
        return MIST_ERROR;
    }

    target_ep->prev->next = target_ep->next;

    wish_platform_free(target_ep->id);
    wish_platform_free(target_ep->label);
    wish_platform_free(target_ep->unit);
    wish_platform_free(target_ep->data);
    wish_platform_free(target_ep);

    return retval;
}

enum mist_error 
#ifdef COMPILING_FOR_ESP8266
__attribute__((section(".text"))) 
#endif
mist_find_endpoint_by_name(struct mist_model *model, char * id, mist_ep** result) {
    enum mist_error retval = MIST_ERROR;
    
    if(id == NULL) { return MIST_ERROR; }
    
    mist_ep* curr_ep = model->endpoint_list;
    
    while (curr_ep != NULL) {
        if (strcmp(curr_ep->id, id) == 0) { /* ESP8266 note: strcmp is in iram, so this is interrupt-safe */
            *result = curr_ep;
            retval = MIST_NO_ERROR;
            break;
        }
        curr_ep = curr_ep->next;
    }
    return retval;
}

enum mist_error mist_endpoint_last(struct mist_model *model, mist_ep** result) {
    mist_ep* curr_ep = model->endpoint_list;
    while (curr_ep != NULL && curr_ep->next != NULL) {
        curr_ep = curr_ep->next;
    }
    *result = curr_ep;
    return MIST_NO_ERROR;
}


