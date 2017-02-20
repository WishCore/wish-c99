#include "bson_visitor.h"
#include "cbson.h"
#include "wish_debug.h"
#include <stdint.h>
#include <string.h>


/* This is a generic BSON element visitor function which can be used
 * with bson_visit function. It just prints out the name of elements */
static void elem_visitor(char *elem_name, uint8_t elem_type, uint8_t *elem, uint8_t depth) {

    depth += 1;
    char indent[32];
    memset(indent, ' ', 32);
    indent[depth*4] = 0;
    
    switch (elem_type) {
    case BSON_KEY_ARRAY:
        WISHDEBUG(LOG_CRITICAL, "%s" AC_WHITE_STRING ": [", indent, elem_name);
        break;
    case BSON_KEY_DOCUMENT:
        WISHDEBUG(LOG_CRITICAL, "%s" AC_WHITE_STRING ": {", indent, elem_name);
        break;
    case BSON_KEY_BINARY:
        WISHDEBUG(LOG_CRITICAL, "%s" AC_WHITE_STRING ": Buffer(" ANSI_COLOR_CYAN "0x%02x %02x %02x %02x" ANSI_COLOR_RESET " ...)", indent, elem_name, elem[0], elem[1], elem[2], elem[3]);
        break;
    case BSON_KEY_STRING:
        WISHDEBUG(LOG_CRITICAL, "%s" AC_WHITE_STRING ": " ANSI_COLOR_YELLOW "'%s'" ANSI_COLOR_RESET, indent, elem_name, elem);
        break;
    case BSON_KEY_INT32:
        WISHDEBUG(LOG_CRITICAL, "%s" AC_WHITE_STRING ": " ANSI_COLOR_GREEN "%d" ANSI_COLOR_RESET, indent, elem_name, int32_le2native(elem));
        break;
    case BSON_KEY_BOOLEAN:
        WISHDEBUG(LOG_CRITICAL, "%s" AC_WHITE_STRING ": " ANSI_COLOR_BLUE "%s" ANSI_COLOR_RESET, indent, elem_name, ((uint8_t)*elem) == 0 ? "false" : "true" );
        break;
    default:
        WISHDEBUG(LOG_CRITICAL, "%s" AC_WHITE_STRING ": ", indent, elem_name);
    }

}



/*
 * This function traverses the bson_doc given as argument, and calls the
 * visitor_func for every element encountered. Document and
 * array elements be recursively handled in the same way. */
void bson_visit(char* title, uint8_t *bson_doc) {
    uint8_t depth = 0;
    WISHDEBUG(LOG_CRITICAL, "%s", title);
    bson_visit_inner(bson_doc, depth, elem_visitor);
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

