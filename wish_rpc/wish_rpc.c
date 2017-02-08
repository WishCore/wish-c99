#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "wish_rpc.h"
#include "wish_platform.h"
#include "wish_debug.h"
#include "cbson.h"
#include "bson.h"
#include "bson_visitor.h"
#include "utlist.h"

static wish_rpc_id_t create_request_entry(wish_rpc_client_t *c, rpc_client_callback cb) {
    struct wish_rpc_entry *new_entry = wish_platform_malloc(sizeof (struct wish_rpc_entry));

    if (new_entry == NULL) {
        WISHDEBUG(LOG_CRITICAL, "malloc fail");
        return 0;
    } else {
        memset(new_entry, 0, sizeof (struct wish_rpc_entry));
        
        // ensure rpc will not send a request with reqest id 0.
        if (c->next_id == 0) { c->next_id++; }
        
        new_entry->id = c->next_id++;
        new_entry->cb = cb;
        if (c->list_head == NULL) {
            /* list empty. Put new node as first on the list */
            c->list_head = new_entry;
        } else {
            struct wish_rpc_entry *entry = c->list_head;
            while (entry->next != NULL) {
                entry = entry->next;
            }
            /* node now points to the last item on the list */
            /* Save new request at end of list */
            entry->next = new_entry;
        }
        return new_entry->id;
    }
}

rpc_client_req* find_request_entry(wish_rpc_client_t *c, wish_rpc_id_t id) {
    struct wish_rpc_entry *entry = c->list_head;
    while (entry != NULL) {
        //WISHDEBUG(LOG_CRITICAL, "  iterating %i passthrough %i", entry->id, entry->passthru_id);
        if (entry->id == id) {
            break;
        }
        entry = entry->next;
    }
    return entry;
}

rpc_client_req* find_passthrough_request_entry(wish_rpc_client_t *c, wish_rpc_id_t id) {
    struct wish_rpc_entry *entry = c->list_head;
    while (entry != NULL) {
        if (entry->passthru_id == id) {
            break;
        }
        entry = entry->next;
    }
    return entry;
}

static rpc_client_req* find_request_entry_by_ctx(wish_rpc_client_t *c, void* ctx) {
    struct wish_rpc_entry *entry = c->list_head;
    while (entry != NULL) {
        if (entry->cb_context == ctx) {
            break;
        }
        entry = entry->next;
    }
    return entry;
}

static void delete_request_entry(wish_rpc_client_t *c, wish_rpc_id_t id) {
    struct wish_rpc_entry *entry = c->list_head;
    struct wish_rpc_entry *prev = NULL;
    
    int n = 0;
    
    while (entry != NULL) {
        n++;
        if (entry->id == id) {
            break;
        }
        prev = entry;
        entry = entry->next;
    }

    if (entry == NULL) {
        WISHDEBUG(LOG_DEBUG, "entry not found id: %i in client %p (checked %i entries) compile with DEBUG for more details.", id, c, n);

#ifdef DEBUG        
        entry = c->list_head;

        int n = 0;

        while (entry != NULL) {
            n++;
            WISHDEBUG(LOG_CRITICAL, "  checked: %i", entry->id);
            if (entry->id == id) {
                break;
            }
            entry = entry->next;
        }
#endif
        return;
    }

    /* Entry now points to entry with said id */

    if (prev != NULL) {
        struct wish_rpc_entry *tmp = entry;
        prev->next = entry->next;
        wish_platform_free(tmp);
    } else {
        /* Special case: when our RPC entry was first in list */
        struct wish_rpc_entry *tmp = c->list_head->next;
        wish_platform_free(c->list_head);
        c->list_head = tmp;
    }
}


wish_rpc_id_t wish_rpc_client(wish_rpc_client_t *c, char *op_str, 
        uint8_t *args_array, size_t args_len, rpc_client_callback cb,
        uint8_t *buffer, size_t buffer_len) {

    uint8_t *rpc_msg = buffer;
    size_t rpc_msg_max_len = buffer_len;
    bson_init_doc(rpc_msg, rpc_msg_max_len);

    bson_write_string(rpc_msg, rpc_msg_max_len, "op", op_str);
    if (args_array != NULL && args_len > 0) {
        /* args array is user-supplied */
        if (bson_write_embedded_doc_or_array(rpc_msg, rpc_msg_max_len, 
                "args", args_array, BSON_KEY_ARRAY) == BSON_FAIL) {
            WISHDEBUG(LOG_CRITICAL, "Could not write args to RPC message");
            bson_visit(args_array, elem_visitor);
        }
    }
    else {
        /* Create an empty args array, user did not specify args */
        const size_t empty_args_array_len = 10;
        uint8_t empty_args_array[empty_args_array_len];
        bson_init_doc(empty_args_array, empty_args_array_len);
        bson_write_embedded_doc_or_array(rpc_msg, rpc_msg_max_len, 
            "args", empty_args_array, BSON_KEY_ARRAY);
    }

    wish_rpc_id_t id = 0;
    
    if (cb != NULL) {
        id = create_request_entry(c, cb);
        bson_write_int32(rpc_msg, rpc_msg_max_len, "id", id);
    }
    return id;
}


wish_rpc_id_t wish_rpc_client_bson(wish_rpc_client_t *c, char *op, 
        uint8_t *args_array, size_t args_len, rpc_client_callback cb,
        uint8_t *buffer, size_t buffer_len) {
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_string(&bs, "op", op);
    
    bson_iterator it;
    bson_find_from_buffer(&it, args_array, "args");
    if(bson_iterator_type(&it) != BSON_ARRAY) {
        // args property must be array
        WISHDEBUG(LOG_CRITICAL, "Dumping request! Args property must be array!");
        return 0;
    }
    bson_append_element(&bs, "args", &it);
    
    wish_rpc_id_t id = 0;
    
    if (cb != NULL) {
        id = create_request_entry(c, cb);
        bson_append_int(&bs, "id", id);
    }
    
    bson_finish(&bs);

    
    // show active requests
    
    //WISHDEBUG(LOG_CRITICAL, "rpc_client %p", c);
    
    struct wish_rpc_entry *entry = c->list_head;
    while (entry != NULL) {
        WISHDEBUG(LOG_CRITICAL, "  entry: %i cb %p ctx: %p", entry->id, entry->cb, entry->cb_context);
        entry = entry->next;
    }
    
    //WISHDEBUG(LOG_CRITICAL,"wish_app_core: BSON Dump\n");
    //bson_visit(bs.data, elem_visitor);    
    
    return id;
}

void wish_rpc_client_end_by_ctx(wish_rpc_client_t *c, void* ctx) {
    WISHDEBUG(LOG_CRITICAL, "Should cleanup, what have we here? provided ctx is %p", ctx);
    struct wish_rpc_entry *entry = c->list_head;
    while (entry != NULL) {
        if (entry->cb_context == ctx) {
            WISHDEBUG(LOG_CRITICAL, "  delete: %i cb %p ctx: %p", entry->id, entry->cb, entry->cb_context);
            /* Save the pointer 'entry' to a tmp variable, because 'entry' might be deleted by 'delete_request_entry' */
            struct wish_rpc_entry *tmp = entry->next;
            delete_request_entry(c, entry->id); /* 'entry' pointer might be invalid after this! */
            entry = tmp;            /* Update loop variable */
        } else {
            WISHDEBUG(LOG_CRITICAL, "  spare:  %i cb %p ctx: %p", entry->id, entry->cb, entry->cb_context);
            entry = entry->next;    /* Update loop variable */
        }
    }
}

void wish_rpc_client_end_by_id(wish_rpc_client_t *c, int id) {
    struct wish_rpc_entry *entry = c->list_head;
    
    //WISHDEBUG(LOG_CRITICAL, "  wish_rpc_client_end_by_id, %p", entry);
    
    while (entry != NULL) {
        if (entry->id == id) {
            //WISHDEBUG(LOG_CRITICAL, "  delete: %i cb %p ctx: %p", entry->id, entry->cb, entry->cb_context);

            int buffer_len = 200;
            char buffer[buffer_len];

            bson bs;
            bson_init_buffer(&bs, buffer, buffer_len);
            bson_append_int(&bs, "end", entry->id);
            bson_finish(&bs);
            
            c->send(c->send_ctx, (uint8_t*) bson_data(&bs), bson_size(&bs));
            
            // FIXME wait for fin, to delete, now we just delete when sending end.
            delete_request_entry(c, entry->id);
            //break;
        } else {
            //WISHDEBUG(LOG_CRITICAL, "  spare:  %i cb %p ctx: %p", entry->id, entry->cb, entry->cb_context);
        }
        entry = entry->next;
    }
}

void wish_rpc_client_set_cb_context(wish_rpc_client_t *c, int id, void* ctx) {
    struct wish_rpc_entry *entry = c->list_head;
    
    while (entry != NULL) {
        if (entry->id == id) {
            entry->cb_context = ctx;
            WISHDEBUG(LOG_CRITICAL, "  wish_rpc_client_set_cb_context done, %p", ctx);
            return;
        }
        entry = entry->next;
    }
    
    /* Failed setting cb context */
    WISHDEBUG(LOG_CRITICAL, "Failed setting cb context!");
    
    
}

static void wish_rpc_passthru_cb(rpc_client_req* req, void *ctx, uint8_t *payload, size_t payload_len) {
    bool end = false;
    
    if (req == NULL) {
        WISHDEBUG(LOG_CRITICAL, "passthru callback with null request not allowed.");
        return;
    }
    
    /* Re-write the ack/sig/err/etc. codes */
    bson_iterator it;
    bson_find_from_buffer(&it, payload, "ack");
    if (bson_iterator_type(&it) != BSON_EOO) {
        bson_inplace_set_long(&it, req->passthru_id);
        end = true;
    } else {
        /* ack not found, try sig */
        bson_find_from_buffer(&it, payload, "sig");
        if (bson_iterator_type(&it) != BSON_EOO) {
            bson_inplace_set_long(&it, req->passthru_id);
        } else {
            /* sig not found, try err */
            bson_find_from_buffer(&it, payload, "err");
            if (bson_iterator_type(&it) != BSON_EOO) {
                bson_inplace_set_long(&it, req->passthru_id);
                end = true;
            }
        }
    }
    
    /* FIXME add support for end/fin, which ever it should be */
    
    //WISHDEBUG(LOG_CRITICAL, "passthru callback switched ack(id) back: %i to %i", bson_iterator_int(&it), req->passthru_id);
    
    rpc_client_callback cb = req->passthru_cb;
    cb(req, ctx, payload, payload_len);
    
    if (end) {
        //WISHDEBUG(LOG_CRITICAL, "END passthru cleanup");
        delete_request_entry(req->cb_context, req->id);
    } else {
        //WISHDEBUG(LOG_CRITICAL, "END passthru NOT cleaning up");
    }
}


static void wish_rpc_passthru_req_cb(rpc_client_req* req, void *ctx, uint8_t *payload, size_t payload_len) {
    bool end = false;
    
    if (req == NULL) {
        WISHDEBUG(LOG_CRITICAL, "passthru callback with null request not allowed.");
        return;
    }
    
    /* Re-write the ack/sig/err/etc. codes */
    bson_iterator it;
    bson_find_from_buffer(&it, payload, "ack");
    if (bson_iterator_type(&it) != BSON_EOO) {
        bson_inplace_set_long(&it, req->passthru_id);
        end = true;
    } else {
        /* ack not found, try sig */
        bson_find_from_buffer(&it, payload, "sig");
        if (bson_iterator_type(&it) != BSON_EOO) {
            bson_inplace_set_long(&it, req->passthru_id);
        } else {
            /* sig not found, try err */
            bson_find_from_buffer(&it, payload, "err");
            if (bson_iterator_type(&it) != BSON_EOO) {
                bson_inplace_set_long(&it, req->passthru_id);
                end = true;
            }
        }
    }
    
    /* FIXME add support for end/fin, which ever it should be */
    
    //WISHDEBUG(LOG_CRITICAL, "passthru callback switched ack(id) back: %i to %i", bson_iterator_int(&it), req->passthru_id);
    
    rpc_client_callback cb = req->passthru_cb;
    cb(req, ctx, payload, payload_len);
    
    if (end) {
        //WISHDEBUG(LOG_CRITICAL, "END passthru cleanup req? %p", req->cb_context);
        //delete_request_entry(req->cb_context, req->id);
        wish_rpc_server_delete_rpc_ctx(req->cb_context);
    } else {
        //WISHDEBUG(LOG_CRITICAL, "END passthru NOT cleaning up");
    }
}

int wish_rpc_passthru(wish_rpc_client_t* client, bson* bs, rpc_client_callback cb) {
    if(client->send == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Passthru has no send function");
        return 0;
    }
    
    wish_rpc_id_t id = create_request_entry(client, wish_rpc_passthru_cb);
    rpc_client_req* e = find_request_entry(client, id);
    
    int len = bson_size(bs);
    uint8_t buffer[len];
    
    memcpy(buffer, bson_data(bs), len);

    //WISHDEBUG(LOG_CRITICAL, "passthru...");
    //bson_visit(buffer, elem_visitor);
    
    bson_iterator it;
    bson_find_from_buffer(&it, buffer, "id");
    e->passthru_id = bson_iterator_int(&it);
    e->passthru_cb = cb;
    
    //WISHDEBUG(LOG_CRITICAL, "Passthru setting cb_context to client pointer: %p", client);
    e->cb_context = client;

    // FIXME: the passthrough context should probably be removed when each peer gets its own rpc_client
    e->passthru_ctx = client->send_ctx;

    bson_inplace_set_long(&it, id);
    
    //WISHDEBUG(LOG_CRITICAL, "Switched id in passthru: %i for %i", e->passthru_id, id);
    //bson_visit(buffer, elem_visitor);
    
    client->send(client->send_ctx, buffer, len);
    return id;
}

int wish_rpc_passthru_req(wish_rpc_ctx* server_rpc_ctx, wish_rpc_client_t* client, bson* bs, rpc_client_callback cb) {
    if(client->send == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Passthru has no send function");
        return 0;
    }
    
    wish_rpc_id_t id = create_request_entry(client, wish_rpc_passthru_req_cb);
    rpc_client_req* e = find_request_entry(client, id);
    
    int len = bson_size(bs);
    uint8_t buffer[len];
    
    memcpy(buffer, bson_data(bs), len);

    //WISHDEBUG(LOG_CRITICAL, "passthru...");
    //bson_visit(buffer, elem_visitor);
    
    bson_iterator it;
    bson_find_from_buffer(&it, buffer, "id");
    e->passthru_id = bson_iterator_int(&it);
    e->passthru_cb = cb;
    
    //WISHDEBUG(LOG_CRITICAL, "Passthru setting cb_context to server pointer: %p", server_rpc_ctx->server);
    //WISHDEBUG(LOG_CRITICAL, "Passthru setting cb_context to server pointer: %p %p %s", server_rpc_ctx, server_rpc_ctx->server, server_rpc_ctx->server->server_name);
    e->cb_context = server_rpc_ctx;
    
    //WISHDEBUG(LOG_CRITICAL, "Passthru setting cb_context to client pointer: %p", client);
    //e->cb_context = client;

    // FIXME: the passthrough context should probably be removed when each peer gets its own rpc_client
    e->passthru_ctx = client->send_ctx;

    bson_inplace_set_long(&it, id);
    
    //WISHDEBUG(LOG_CRITICAL, "Switched id in passthru: %i for %i", e->passthru_id, id);
    //bson_visit(buffer, elem_visitor);
    
    client->send(client->send_ctx, buffer, len);
    return id;
}


void wish_rpc_passthru_end(wish_rpc_client_t* client, int id) {
    rpc_client_req* e = find_request_entry(client, id);
    wish_rpc_client_end_by_id(client, id);
}


void wish_rpc_server_delete_rpc_ctx(struct wish_rpc_context *rpc_ctx) {
    //WISHDEBUG(LOG_CRITICAL, "Searching for something to delete..");
    struct wish_rpc_context_list_elem *list_elem = NULL;
    struct wish_rpc_context_list_elem *tmp = NULL;
    LL_FOREACH_SAFE(rpc_ctx->server->request_list_head, list_elem, tmp) {
        if (&(list_elem->request_ctx) == rpc_ctx) {
            //WISHDEBUG(LOG_CRITICAL, "Deleting rpc ctx");
           
#ifdef WISH_RPC_SERVER_STATIC_REQUEST_POOL
            memset(rpc_ctx->op_str, 0, MAX_RPC_OP_LEN);
#else
#error not implemented
            //wish_platform_free....
#endif
            LL_DELETE(rpc_ctx->server->request_list_head, list_elem);
            break;
        }
    }
}


/* { data: bson_element ack: req_id } */
int wish_rpc_server_send(struct wish_rpc_context *ctx, const uint8_t *response, size_t response_len) {
    
    int buffer_len = response_len + 512;
    char buffer[buffer_len];
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);

    if(response == NULL) {
        // send ack without any data
        bson_append_int(&bs, "ack", ctx->id);
        bson_finish(&bs);
    } else {
        // expect bson document with data property
        bson_iterator it;
        bson_find_from_buffer(&it, response, "data");
        
        bson_type type = bson_iterator_type(&it);
        
        // FIXME check type under iterator is valid
        if (type == BSON_STRING) {
            bson_append_string(&bs, "data", bson_iterator_string(&it));
        } else if (type == BSON_BINDATA) {
            bson_append_binary(&bs, "data", bson_iterator_bin_data(&it), bson_iterator_bin_len(&it));
        } else if (type == BSON_BOOL) {
            bson_append_bool(&bs, "data", bson_iterator_bool(&it));
        } else if (type == BSON_INT) {
            bson_append_int(&bs, "data", bson_iterator_int(&it));
        } else if (type == BSON_DOUBLE) {
            bson_append_double(&bs, "data", bson_iterator_double(&it));
        } else if (type == BSON_OBJECT) {
            bson_append_element(&bs, "data", &it);
        } else if (type == BSON_BINDATA) {
            bson_append_element(&bs, "data", &it);
        } else if (type == BSON_ARRAY) {
            bson_append_element(&bs, "data", &it);
        } else {
            WISHDEBUG(LOG_CRITICAL, "Unsupported bson type %i in wish_rpc_server_send", type);
        }

        bson_append_int(&bs, "ack", ctx->id);
        bson_finish(&bs);
    }
    if (bs.err) {
        WISHDEBUG(LOG_CRITICAL, "BSON error in wish_rpc_server_send");
        return 1;
    }
    
    ctx->send(ctx->send_context, (char*)bson_data(&bs), bson_size(&bs));
    wish_rpc_server_delete_rpc_ctx(ctx);
    return 0;
}

/* { data: bson_element ack: req_id } */
int wish_rpc_server_emit(struct wish_rpc_context *ctx, const uint8_t *response, size_t response_len) {
    
    int buffer_len = response_len + 512;
    char buffer[buffer_len];
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);

    if(response == NULL) {
        // send ack without any data
        bson_append_int(&bs, "sig", ctx->id);
        bson_finish(&bs);
    } else {
        // expect bson document with data property
        bson_iterator it;
        bson_find_from_buffer(&it, response, "data");

        bson_append_element(&bs, "data", &it);
        bson_append_int(&bs, "sig", ctx->id);
        bson_finish(&bs);
    }
    if (bs.err) {
        WISHDEBUG(LOG_CRITICAL, "BSON error in wish_rpc_server_emit");
        return 1;
    }
    
    ctx->send(ctx->send_context, (char*)bson_data(&bs), bson_size(&bs));
    return 0;
}

/* { data: { code: errno, msg: errstr } err: req_id } */
int wish_rpc_server_error(struct wish_rpc_context *ctx, int code, const uint8_t *msg) {
    if (strnlen(msg, WISH_RPC_ERR_MSG_MAX_LEN) == WISH_RPC_ERR_MSG_MAX_LEN) {
        WISHDEBUG(LOG_CRITICAL, "Error message too long in wish_rpc_server_error");
        return 1;
    }
    
    int buffer_len = WISH_RPC_ERR_MSG_MAX_LEN + 128;
    char buffer[buffer_len];
    memset(buffer, 0, buffer_len);

    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_int(&bs, "code", code);
    bson_append_string(&bs, "msg", msg);
    bson_append_int(&bs, "err", ctx->id);
    bson_finish(&bs);
    if (bs.err) {
        WISHDEBUG(LOG_CRITICAL, "BSON error in wish_rpc_server_error");
        return 1;
    }
    
    ctx->send(ctx->send_context, (char*)bson_data(&bs), bson_size(&bs));
    wish_rpc_server_delete_rpc_ctx(ctx);
    return 0;
}

void wish_rpc_server_emit_broadcast(wish_rpc_server_t* s, char* op, const uint8_t *data, size_t data_len) {
    /* Traverse the list of requests in the given server, and for each request where op_str equals given op, emit the data */
    struct wish_rpc_context_list_elem *request;
    LL_FOREACH(s->request_list_head, request) {

        if (strncmp(request->request_ctx.op_str, op, MAX_RPC_OP_LEN) == 0) {
            //WISHDEBUG(LOG_CRITICAL, "emit_broadcast:");
            //bson_visit((uint8_t*)data, elem_visitor);
            //WISHDEBUG(LOG_CRITICAL, "(end)");

            wish_rpc_server_emit(&(request->request_ctx), data, data_len);
        }
    }
}


/**
 * @return 1, if RPC entry was not found , else 0
 */
int wish_rpc_client_handle_res(wish_rpc_client_t *c, void *ctx, uint8_t *data, size_t data_len) {
    
    bool sig = false;
    bool fin = false;
    bool err = false;
    int retval = 0;
    wish_rpc_id_t id = -1;
    if (bson_get_int32(data, "ack", &id) == BSON_FAIL) {
        if (bson_get_int32(data, "sig", &id) == BSON_SUCCESS) {
            //WISHDEBUG(LOG_DEBUG, "Sig id %i", id);
            /* Do not remove the callback if we get "sig" instead of
             * ack" */
            sig = true;
        } else if (bson_get_int32(data, "err", &id) == BSON_SUCCESS) {
            //WISHDEBUG(LOG_CRITICAL, "Error return for RPC id %d, message follows:", id);
            //bson_visit(data, elem_visitor);
            err = true;
        } else if (bson_get_int32(data, "fin", &id) == BSON_SUCCESS) {
            //WISHDEBUG(LOG_CRITICAL, "Fin message for RPC id %d", id);
            fin = true;
        } else {
            WISHDEBUG(LOG_CRITICAL, "RPC error: no ack, sig or err, message follows:");
            bson_visit(data, elem_visitor);
        }
    }

    /* If we get here, then we have an ack or err to an id */
    rpc_client_req* rpc_entry = find_request_entry(c, id);
    
    if (rpc_entry == NULL) {
        WISHDEBUG(LOG_CRITICAL, "No RPC entry for id %d", id);
        retval = 1;
    } else {
        
        if (fin) {
            delete_request_entry(c, id);
            return retval;
        }
        
        rpc_entry->err = err;
        
        if (rpc_entry->cb != NULL) {
            //WISHDEBUG(LOG_CRITICAL, "RPC callback (id %d):", id);
            //bson_visit(data, elem_visitor);
            rpc_entry->cb(rpc_entry, ctx, data, data_len);
        } else {
            WISHDEBUG(LOG_CRITICAL, "RPC callback is null! (id %d)", id);
        }
        
        if (sig == false) {
            delete_request_entry(c, id);
        } else {
            //WISHDEBUG(LOG_CRITICAL, "wish_rpc_client_handle_res NOT cleanup (id %d)", id);
        }
    }
    return retval;
}

/** Server: Add a RPC handler */
void wish_rpc_server_add_handler(wish_rpc_server_t *s, 
        char *op_str, rpc_op_handler handler_fn) {
    struct wish_rpc_server_handler *new_h = NULL;
    new_h = (struct wish_rpc_server_handler*) 
        wish_platform_malloc(sizeof (struct wish_rpc_server_handler));
    if (new_h == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Malloc fail, cannot add RPC handler");
        return;
    }
    memcpy(new_h->op_str, op_str, MAX_RPC_OP_LEN);
    new_h->handler = handler_fn;
    new_h->next = NULL;

    /* Find correct place to add the new handler new_h */
    struct wish_rpc_server_handler *h = s->list_head;

    if (h == NULL) {
        WISHDEBUG(LOG_DEBUG, "The RPC server %s does not have any handlers, adding first entry", s->server_name);
        s->list_head = new_h;
    }
    else {
        while (h->next != NULL) {
            h = h->next;
        }
        h->next = new_h;
    }
}

/** Server: Add a RPC handler */
void wish_rpc_server_register(wish_rpc_server_t *s, struct wish_rpc_server_handler* handler) {
    /* Find correct place to add the new handler new_h */
    struct wish_rpc_server_handler *h = s->list_head;

    if (h == NULL) {
        WISHDEBUG(LOG_DEBUG, "The RPC server %s does not have any handlers, adding first entry", s->server_name);
        s->list_head = handler;
    } else {
        while (h->next != NULL) {
            h = h->next;
        }
        h->next = handler;
    }
}

struct wish_rpc_context_list_elem *wish_rpc_server_get_free_rpc_ctx_elem(wish_rpc_server_t *s) {
    struct wish_rpc_context_list_elem *free_elem = NULL;
#ifdef WISH_RPC_SERVER_STATIC_REQUEST_POOL
    if (s == NULL || s->rpc_ctx_pool_num_slots == 0 || s->rpc_ctx_pool == NULL) {
        WISHDEBUG(LOG_CRITICAL, "RPC server %s: Cannot save RPC request context!", s->server_name);
    } else {
        int i = 0;
        for (i = 0; i < s->rpc_ctx_pool_num_slots; i++) {
            /* A request pool slot is empty if the op_str is empty. */
            if (strnlen(s->rpc_ctx_pool[i].request_ctx.op_str, MAX_RPC_OP_LEN) == 0) {
                /* Found free request pool slot */
                free_elem = &(s->rpc_ctx_pool[i]);
                LL_APPEND(s->request_list_head, free_elem);
                break;
            } 
        }
        /*
        // Count the active number of requests
        int c = 0;
        for (i = 0; i < s->rpc_ctx_pool_num_slots; i++) {
            // A request pool slot is empty if the op_str is empty.
            if (strnlen(s->rpc_ctx_pool[i].request_ctx.op_str, MAX_RPC_OP_LEN) != 0) {
                c++;
            }
        }
        WISHDEBUG(LOG_CRITICAL, "RPC server %s: requests registered %i", s->server_name, c);
        */
    }
#else
#error not implemented
#endif
    return free_elem;
}

void wish_rpc_server_print(wish_rpc_server_t *s) {
    WISHDEBUG(LOG_CRITICAL, "RPC server %s:", s->server_name);
    // Count the active number of requests
    int i;
    int c = 0;
    for (i = 0; i < s->rpc_ctx_pool_num_slots; i++) {
        // A request pool slot is empty if the op_str is empty.
        if (strnlen(s->rpc_ctx_pool[i].request_ctx.op_str, MAX_RPC_OP_LEN) != 0) {
            c++;
            WISHDEBUG(LOG_CRITICAL, "  %s", s->rpc_ctx_pool[i].request_ctx.op_str);
        }
    }
    WISHDEBUG(LOG_CRITICAL, "  requests registered %i", c);
}

/* Handle an RPC request to an RPC server
 * Returns 0, if the request was valid, and 1 if there was no handler to
 * this "op" 
 * @param s the RPC server instance
 * @param rpc_ctx the RPC request context, NOTE: it must be obtained via wish_rpc_server_get_free_rpc_ctx_elem()
 * @param args_array the request argument BSON array
 * @return 0 for success, 1 for fail
 */
int wish_rpc_server_handle(wish_rpc_server_t *s, wish_rpc_ctx *rpc_ctx, uint8_t *args) {

    int retval = 1;
    struct wish_rpc_server_handler *h = rpc_ctx->server->list_head;
    // Searching for RPC handler op rpc_ctx->op_str
    if (h == NULL) {
        WISHDEBUG(LOG_CRITICAL, "RPC server %s does not have handlers. Req id: %d.", s->server_name, rpc_ctx->id);
        bson_visit(args, elem_visitor);
    } else {
        do {
            if (strncmp(h->op_str, rpc_ctx->op_str, MAX_RPC_OP_LEN) == 0) {
                // Found handler
                       
                /* Call the RPC handler. */
                h->handler(rpc_ctx, args);
                retval = 0;
                
                if (rpc_ctx->id == 0) {
                    /* No request id. Delete the request context immediately. */
                    wish_rpc_server_delete_rpc_ctx(rpc_ctx);
                }
                break;
            }
            h = h->next;
        } while (h != NULL);
        
        if(retval) {
            WISHDEBUG(LOG_CRITICAL, "RPC server %s does not contain op: %s.", s->server_name, rpc_ctx->op_str);
            wish_rpc_server_error(rpc_ctx, 8, "Command not found or permission denied.");
            /* Not an existing handler. Delete the request context immediately. */
            wish_rpc_server_delete_rpc_ctx(rpc_ctx);
        }
    }
    return retval;
}

wish_rpc_ctx* wish_rpc_server_req_by_id(wish_rpc_server_t *s, int id) {
    struct wish_rpc_context_list_elem* request;
    LL_FOREACH(s->request_list_head, request) {

        if (request->request_ctx.id == id) {
            return &request->request_ctx;
            break;
        }
    }

    return NULL;
}

void wish_rpc_server_end(wish_rpc_server_t *s, int id) {
    wish_rpc_ctx *rpc_ctx = NULL;
    /* Traverse the list of requests in the given server, and for each request where op_str equals given op, emit the data */
    struct wish_rpc_context_list_elem *request;
    LL_FOREACH(s->request_list_head, request) {

        if (request->request_ctx.id == id) {
            rpc_ctx = &request->request_ctx;
            break;
        }
    }    
    
    // Searching for RPC handler op rpc_ctx->op_str
    if (rpc_ctx != NULL) {
        /* Call the end handler if it is set */
        if(rpc_ctx->end != NULL) { rpc_ctx->end(rpc_ctx); }

        /* Delete the request context */
        wish_rpc_server_delete_rpc_ctx(rpc_ctx);
        
        //WISHDEBUG(LOG_CRITICAL, "RPC server %s cleaned up request with id: %i.", s->server_name, id);
    } else {
        WISHDEBUG(LOG_DEBUG, "RPC server %s has no request with id: %i.", s->server_name, id);
    }
}

void wish_rpc_server_end_by_ctx(wish_rpc_server_t *s, void* ctx) {
    wish_rpc_ctx *rpc_ctx = NULL;
    /* Traverse the list of requests in the given server, and for each request where op_str equals given op, emit the data */
    struct wish_rpc_context_list_elem *request;
    LL_FOREACH(s->request_list_head, request) {

        if (request->request_ctx.ctx == ctx) {
            rpc_ctx = &request->request_ctx;
            break;
        }
    }    
    
    // Searching for RPC handler op rpc_ctx->op_str
    if (rpc_ctx != NULL) {
        /* Call the end handler if it is set */
        if(rpc_ctx->end != NULL) { rpc_ctx->end(rpc_ctx); }

        /* Delete the request context */
        wish_rpc_server_delete_rpc_ctx(rpc_ctx);
        
        //WISHDEBUG(LOG_CRITICAL, "RPC server %s cleaned up request with id: %i and ctx pointer: %p.", s->server_name, rpc_ctx->id, ctx);
    } else {
        WISHDEBUG(LOG_DEBUG, "RPC server %s has no request with ctx: %p.", s->server_name, ctx);
    }
}


