#ifndef MIST_MODEL_H
#define MIST_MODEL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "wish_rpc.h"
#include "bson.h"
    
/* Mist model-related functions */

#define MIST_MAX_ENDPOINTS  5

enum mist_type {
    MIST_TYPE_BOOL,     /* a true/false value (BSON bool) */
    MIST_TYPE_FLOAT,    /* A floating point value (actually a BSON double) */
    MIST_TYPE_INT,       /* A 32-bit signed integer (BSON int32) */
    MIST_TYPE_STRING,   /* A string, which can be MIST_STRING_EP_MAX_LEN
    bytes long at most */
    MIST_TYPE_INVOKE,   /* An endpoint which represent a function you
    can call, "invoke" so to speak */
};

/** This defines the maximum allowable length of the value of an
 * endpoint of type MIST_TYPE_STRING */
#define MIST_STRING_EP_MAX_LEN 32

enum mist_error {
    MIST_NO_ERROR,
    MIST_ERROR,
    MIST_ASYNC, // used when control.invoke is asynchronoulsy executed
    MIST_MAX_ENDPOINTS_REACHED,
    MIST_MALLOC_FAIL,
};

typedef struct mist_buffer {
    char* base;
    int len;
} mist_buf;

typedef struct mist_endpoint {
    char* id;       /* ID of the item (=the name of the document) */
    char* label;    /* Clear text label */
    enum mist_type type;
    char* unit;
    char* data;     /* Initial value encoded */
    bool readable;
    bool writable;
    bool invokable;
    enum mist_error (*read)(struct mist_endpoint* ep, void* result);
    enum mist_error (*write)(struct mist_endpoint* ep, void* value);
    enum mist_error (*invoke)(struct mist_endpoint* ep, mist_buf args);
    struct mist_endpoint * next;
    struct mist_endpoint * prev;
    bool dirty;
    /* Used in float type */
    char *scaling;
} mist_ep;

#define MIST_MODEL_NAME_MAX_LEN 16

typedef struct mist_model {
    /** The name of the model, which will be encoded int the model like this:
     * mist: { "name":<name> ...} 
     * FIXME this initialised to be a pointer to the mist app's name */
    char *name;
    char *custom_ui_url;
    mist_ep* endpoint_list;
    /* The current number of registered endpoints (the length of
     * endpoint_list) */
    int num_endpoints;
    /* Reference to mist app FIXME need help with forward declarations! */
    void *mist_app;
} mist_model_t;

enum mist_error mist_find_endpoint_by_name(struct mist_model *model, char * id, mist_ep** result);

enum mist_error mist_endpoint_last(struct mist_model *model, mist_ep** result);

enum mist_error mist_add_endpoint(struct mist_model *model, char * id, char * label, enum
    mist_type type, char * unit, 
    enum mist_error (*read)(mist_ep* ep, void* result),
    enum mist_error (*write)(mist_ep* ep, void* value),
    enum mist_error (*invoke)(mist_ep* ep, mist_buf args)
);

enum mist_error mist_add_ep(struct mist_model *model, mist_ep* ep);

enum mist_error mist_delete_endpoint(struct mist_model *model, char * id);

/* This function will generate a complete "model" document, which is to
 * be embedded in the "data" document of the control.model reply. 
 * The document will be created in the buffer supplied as parameter
 * "model_do"c. The buffer will be initialised as a document first.
 * The caller must make sure that the array is large enough, or else the
 * operation will fail and error is returned. 
 * */
int model_generate_bson(struct mist_model *model, bson *bs);

#ifdef __cplusplus
}
#endif

#endif //MIST_MODEL_H
