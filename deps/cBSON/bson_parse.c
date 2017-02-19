/* 
 * cBSON - a minimal BSON implementation for embedded systems
 * Functions for extracting key/value pairs from BSON documents
 *
 * Author: Jan Nyman, jan.nyman@controlthings.fi
 *
 * See BSON specification at http://bsonspec.org/spec.html
 *
 */

#include <string.h>
#include "cbson.h"

#include <inttypes.h>

/* Set this to 0 for when not debugging */
#define BSON_DEBUG 0

/* This helper function parses an element pointed by elem_ptr, 
 * saving the element type to localtion pointed by parameter value_type,
 * pointer to the element (key) name the location pointed by parameter 
 * key_name, pointer to the start of the element data (value) to the 
 * location pointed by parameter value, and the length of the element data 
 * to the location pointed by value_len. 
 */
int bson_get_elem_members(uint8_t* elem_ptr, uint8_t* value_type, 
            char** key_name, uint8_t** value, int32_t* value_len) {

    int retval = BSON_SUCCESS; /* Assume success */

    *value_type = elem_ptr[0];
    if (*value_type == 0) {
        /* Value type cannot be 0 - in fact, this signals the end of the
         * BSON document to my understanding */
        retval = BSON_FAIL;
    }

    *key_name = (char*) &(elem_ptr[1]);
    int i = 2;  /* First two bytes are already consumed, start at offset +2*/
    /* Find the length of the key (the key must be null-terminated per
     * spec) */
    while (elem_ptr[i] != 0) {
            i++;
    }
    /* 'i' is now the end of the key name, not counting the null byte */
    switch (*value_type) {
        case BSON_KEY_BOOLEAN:
        *value_len = BSON_SZ_BOOLEAN;
        *value = elem_ptr+i+1;
        break;
        case BSON_KEY_STRING:
        /* Length of the string is saved after the null byte ending the
         * key name */
        {
            int32_t tmp = 0;
            memcpy(&tmp, (elem_ptr+i+1), BSON_SZ_INT32);
            *value_len = int32_le2native((uint8_t*)&tmp);
        }
        /* The string starts right after the 4 bytes defining length */
        *value = elem_ptr+i+1+BSON_SZ_INT32;
        break;
        case BSON_KEY_BINARY:
        /* Length of the binary array is saved after the null byte
         * ending the key name */
        {
            int32_t tmp = 0;
            memcpy(&tmp, (elem_ptr+i+1), BSON_SZ_INT32);
            *value_len = int32_le2native((uint8_t*)&tmp);
        }
        /* Calculate the start of of the actual binary array:
         * (end of key string) + (null byte) 
         *  + (length of data as int32, 4 bytes) + (binary subtype, 1 byte) */
        *value = elem_ptr+i+1+BSON_SZ_INT32+1;
        /* Note: binary "subtype" is ignored by this implementation */
        break;
        case BSON_KEY_DOUBLE:
        *value_len = BSON_SZ_DOUBLE;
        *value = elem_ptr+i+1;
        break;
        case BSON_KEY_INT32:
        *value_len = BSON_SZ_INT32;
        *value = elem_ptr+i+1;
        break;
        case BSON_KEY_ARRAY:    /* Encoded similarly to "document" type */
        /* FALLTHROUGH */
        case BSON_KEY_DOCUMENT:
        {
            int32_t tmp = 0;
            memcpy(&tmp, (elem_ptr+i+1), BSON_SZ_INT32);
            *value_len = int32_le2native((uint8_t*)&tmp);
        }
        /* Note: When we return the document, we want to return all of
         * it, including the length! */
        *value = elem_ptr+i+1; /* SIC! */
        break;

        default:
        /* Bad or unknown type */
        retval = BSON_FAIL; /* Signal failure */
        break;
    }
    return retval;
}

int bson_get_elem_by_name(uint8_t* doc, char *e_name, 
        uint8_t* e_type, uint8_t** value, int32_t* value_len) {
    int32_t doc_len = bson_get_doc_len(doc);
    char* elem_name = 0;

    uint8_t* next = doc + BSON_SZ_INT32; /* The first element of the document */
    /* Traverse the document's members */
    while (bson_get_elem_members(next, e_type, &elem_name,
        value, value_len) != BSON_FAIL) {

        if ((strcmp(elem_name, e_name) == 0)) {
#if BSON_DEBUG
            printf("type %i with name %s found, len %i\n", *e_type, elem_name, *value_len);
#endif
            return BSON_SUCCESS;
        }
        else {
            next = *value + *value_len;
            if (next >= (doc + doc_len - 1)) {
                /* Document overrun */
                return BSON_FAIL;
            }
        }
    }
    /* Not found */
    return BSON_FAIL;
}

int bson_get_double(uint8_t *doc, char *e_name, double* value) {
    uint8_t type = 0;
    uint8_t* raw_value = 0;
    int32_t value_len = 0;
    int retval = bson_get_elem_by_name(doc, e_name, &type, &raw_value, &value_len);
    if (raw_value == NULL) {
        /* Not found */
        return BSON_FAIL;
    }
    
    if (retval == 1 && type == BSON_KEY_DOUBLE) {
        memcpy(value, raw_value, BSON_SZ_DOUBLE);
        return BSON_SUCCESS;
    }
    return BSON_FAIL;
}



/* This function traverses the document and returns the integer with
 * name 'e_name', and saves the integer to location pointed by 'value'.
 * On success, 1 is returned, else 0 */
int bson_get_int32(uint8_t* doc, char *e_name, int32_t* value) {
    uint8_t type = 0;
    uint8_t* raw_value = 0;
    int32_t value_len = 0;
    int retval = bson_get_elem_by_name(doc, e_name, &type, &raw_value, &value_len);
    int32_t tmp = 0;
    if (raw_value == NULL) {
        /* Not found */
        return BSON_FAIL;
    }
    memcpy(&tmp, raw_value, BSON_SZ_INT32);
    
    if (retval == 1 && type == BSON_KEY_INT32) {
        *value = int32_le2native((uint8_t*)&tmp);
        return BSON_SUCCESS;
    }
    return BSON_FAIL;

}

/* This function searches and returns the buffer with name 'e_name', and
 * returns a pointer to the buffer. The length of the buffer is saved to
 * an integer pointed by buffer_len.
 */
int bson_get_binary(void* doc, char *e_name, uint8_t** buffer, int32_t *buffer_len) {
    uint8_t type = 0;
    int retval = bson_get_elem_by_name(doc, e_name, &type, buffer, buffer_len);
    if (retval == BSON_SUCCESS && type == BSON_KEY_BINARY) {
        return BSON_SUCCESS;
    }
    return BSON_FAIL;
}

int bson_get_document(void* doc, char *e_name, uint8_t** buffer, int32_t *buffer_len) {

    uint8_t type = 0;
    int retval = bson_get_elem_by_name(doc, e_name, &type, buffer, buffer_len);
    if (retval == BSON_SUCCESS && type == BSON_KEY_DOCUMENT) {
        return BSON_SUCCESS;
    }
    return BSON_FAIL;
}


int bson_get_array(void* doc, char *e_name, uint8_t** buffer, int32_t *buffer_len) {
    uint8_t type = 0;
    int retval = bson_get_elem_by_name(doc, e_name, &type, buffer, buffer_len);
    if (retval == BSON_SUCCESS && type == BSON_KEY_ARRAY) {
        return BSON_SUCCESS;
    }
    return BSON_FAIL;
}


int bson_get_string(void* doc, char *e_name, char** buffer, int32_t *buffer_len) {
    uint8_t type = 0;
    int retval = bson_get_elem_by_name(doc, e_name, &type, (uint8_t **)buffer, buffer_len);
    if (retval == BSON_SUCCESS && type == BSON_KEY_STRING) {
        return BSON_SUCCESS;
    }
    return BSON_FAIL;
}

int bson_get_boolean(void* doc, char *e_name, bool* value) {
    uint8_t type = 0;
    uint8_t* raw_value = 0;
    int32_t raw_value_len = 0;
    int retval = bson_get_elem_by_name(doc, e_name, &type, &raw_value, &raw_value_len);
    if (retval == BSON_SUCCESS && type == BSON_KEY_BOOLEAN) {
        *value = *raw_value;
        return BSON_SUCCESS;
    }
    return BSON_FAIL;
}

/* This function returns the document length */
int32_t bson_get_doc_len(uint8_t* doc) {
    return int32_le2native(doc);
}

/* This function returns an int32 in little endian byte order as an
 * int32 in native byte order */
int32_t int32_le2native(uint8_t* data) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return (int32_t)(data[3] << 24 | data[2] << 16 | data[1] << 8 | data[0]);
#else 
#error Big endian platform detected, please check imlementation
    /* A union for holding 4 bytes of data, which can be accessed as int32
     * or as an array of 4 bytes. */
    union int32_le_data {
        int32_t le_order;
        char raw[4];
    } data;

    data.le_order = le_int;
    int32_t native_int32 = 0;
    native_int32 |= data.raw[3];
    native_int32 <<= 8;
    native_int32 |= data.raw[2];
    native_int32 <<= 8;
    native_int32 |= data.raw[1];
    native_int32 <<= 8;
    native_int32 |= data.raw[0];
    return native_int32;
#endif
}


