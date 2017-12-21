#include "bson_visit.h"
#include "bson.h"
#include "wish_debug.h"
#include <stdint.h>
#include <string.h>

/*
 * This function traverses the bson_doc given as argument, and calls the
 * visitor_func for every element encountered. Document and
 * array elements be recursively handled in the same way. */
void bson_visit(const char* title, const uint8_t* data) {
    uint8_t depth = 0;
    
    bson b;
    bson_init_with_data(&b, data);
    int size = bson_size(&b);
    
    WISHDEBUG(LOG_CRITICAL, "%s (%i bytes)", title, size);
    bson_visit_inner(data, depth);
}

/*
 * This function traverses the bson_doc given as argument, and calls the
 * visitor_func for every element encountered. Document and
 * array elements be recursively handled in the same way. */
void bson_visit_inner(const uint8_t* data, uint8_t depth) {

    bson_iterator i;
    const char *key;
    bson_timestamp_t ts;
    BSON_ITERATOR_FROM_BUFFER(&i, data);

    while (bson_iterator_next(&i)) {
        bson_type t = BSON_ITERATOR_TYPE(&i);
        if (t == 0) { break; }
        key = BSON_ITERATOR_KEY(&i);

        char indent[33];
        memset(indent, ' ', 32);
        indent[(depth+1)*4] = 0;
        
        const char* elem = NULL;
        
        switch (t) {
            case BSON_STRING:
                WISHDEBUG(LOG_CRITICAL, "%s" AC_WHITE_STRING ": " ANSI_COLOR_YELLOW "'%s'" ANSI_COLOR_RESET, indent, key, bson_iterator_string(&i));
                break;
            case BSON_BINDATA:
                elem = bson_iterator_bin_data(&i);
                WISHDEBUG(LOG_CRITICAL, "%s" AC_WHITE_STRING ": Buffer(" ANSI_COLOR_CYAN "0x%02x %02x %02x %02x" ANSI_COLOR_RESET " ...)", 
                        indent, key, elem[0] & 0xff, elem[1] & 0xff, elem[2] & 0xff, elem[3] & 0xff);
                break;
            case BSON_INT:
            case BSON_LONG:
            case BSON_DOUBLE:
                WISHDEBUG(LOG_CRITICAL, "%s" AC_WHITE_STRING ": " ANSI_COLOR_GREEN "%d" ANSI_COLOR_RESET, indent, key, bson_iterator_int(&i));
                break;
            case BSON_BOOL:
                WISHDEBUG(LOG_CRITICAL, "%s" AC_WHITE_STRING ": " ANSI_COLOR_BLUE "%s" ANSI_COLOR_RESET, indent, key, bson_iterator_bool(&i) ? "true" : "false" );
                break;
            case BSON_OBJECT:
                WISHDEBUG(LOG_CRITICAL, "%s" AC_WHITE_STRING ": {", indent, key);
                bson_visit_inner(bson_iterator_value(&i), depth + 1);
                break;
            case BSON_ARRAY:
                WISHDEBUG(LOG_CRITICAL, "%s" AC_WHITE_STRING ": [", indent, key);
                bson_visit_inner(bson_iterator_value(&i), depth + 1);
                break;
            case BSON_NULL:
                WISHDEBUG(LOG_CRITICAL, "%s" AC_WHITE_STRING ": " ANSI_COLOR_RED "null" ANSI_COLOR_RESET, indent, key);
                break;
            case BSON_TIMESTAMP:
            case BSON_SYMBOL:
            case BSON_OID:
            case BSON_DATE:
            case BSON_UNDEFINED:
            case BSON_REGEX:
            case BSON_CODE:
            case BSON_CODEWSCOPE:
            default:
                WISHDEBUG(LOG_CRITICAL, "%s" AC_WHITE_STRING ": ", indent, key);
        }
    }

}
