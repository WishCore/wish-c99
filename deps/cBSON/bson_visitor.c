#include <stdint.h>
#include <string.h>
#include "cbson.h"
#include "bson_visitor.h"

/*
 * This function traverses the bson_doc given as argument, and calls the
 * visitor_func for every element encountered. Document and
 * array elements be recursively handled in the same way. */
void bson_visit(uint8_t *bson_doc,
        void (*visitor_func)(char *elem_name, uint8_t elem_type, 
                                uint8_t *elem, uint8_t depth)) {
    uint8_t depth = 0;
    bson_visit_inner(bson_doc, depth, visitor_func);
}

/*
 * This function traverses the bson_doc given as argument, and calls the
 * visitor_func for every element encountered. Document and
 * array elements be recursively handled in the same way. */
void bson_visit_inner(uint8_t *bson_doc, uint8_t depth,
        void (*visitor_func)(char *elem_name, uint8_t elem_type, 
                                uint8_t *elem, uint8_t depth)) {
    char* elem_name = 0;
    uint8_t elem_type = 0;
    uint8_t* value = 0;
    int value_len = 0;
    uint8_t* next = bson_doc + BSON_SZ_INT32; /* The first element of
         the document */
    /* Traverse the document's members */
    while (bson_get_elem_members(next, &elem_type, &elem_name,
                             &value, &value_len) != BSON_FAIL) {

        switch (elem_type) {
        case BSON_KEY_DOCUMENT:
        case BSON_KEY_ARRAY:
            visitor_func(elem_name, elem_type, value, depth);
            /* Recurse */
            bson_visit_inner(value, depth+1, visitor_func);
            break;
        default:
            visitor_func(elem_name, elem_type, value, depth);
            break;
        }

        next = value + value_len; /* Update iterator */
        if (*next == 0) {   /* A document is terminated by the null byte */
            /* Document overrun */
            break;
        }
    }
}

/**
 * Filter out the named element from source_doc, storing the new
 * document in target_doc. The documents may not overlap.
 * @param elem_name the name of the element which will be filtered out
 * from the document.
 * @param source_doc the original document
 * @param target_doc the new document which will containt all other
 * elements, but not the named element.
 * @return BSON_SUCCESS, if the operation succeeded
 */
int bson_filter_out_elem(char *unwanted_elem_name, uint8_t *source_doc, uint8_t *target_doc) {
    int retval = BSON_FAIL;
    const int32_t source_doc_len = bson_get_doc_len(source_doc);

    /* Find the unwanted element's position*/
    char* elem_name = 0;
    uint8_t elem_type = 0;
    uint8_t* value_ptr = 0;
    int value_len = 0;
    uint8_t* next = source_doc + BSON_SZ_INT32; /* The first element of
         the document */
    /* Traverse the document's members */
    while (bson_get_elem_members(next, &elem_type, &elem_name,
                             &value_ptr, &value_len) != BSON_FAIL) {

        if (strcmp(elem_name, unwanted_elem_name) == 0) {
            /* We found our unwanted element. Copy the contents of the
             * original document upto our current position */
            int32_t doc_prefix_len = next - source_doc;
            memcpy(target_doc, source_doc, doc_prefix_len);
            /* Copy the rest of the document */
            int32_t doc_trailer_len = source_doc_len 
                - ((value_ptr+value_len)-source_doc);
            memcpy(target_doc + doc_prefix_len, value_ptr + value_len,
                doc_trailer_len);

            /* Fix the new document length */
            int32_t new_doc_len = doc_prefix_len + doc_trailer_len;
            int32_t tmp = int32_native2le(new_doc_len);
            memcpy(target_doc, &tmp, BSON_SZ_INT32);

            retval = BSON_SUCCESS;
            break;
        }
        else {
        
            next = value_ptr + value_len; /* Update iterator */
            if (*next == 0) {   /* A document is terminated by the null byte */
                /* Document overrun */
                break;
            }
        }
    }
    return retval;
}

