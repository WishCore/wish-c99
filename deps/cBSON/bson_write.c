/* 
 * cBSON - a minimal BSON implementation for embedded systems
 * Functions for encoding key/value pairs into BSON documents
 *
 * Author: Jan Nyman, jan.nyman@controlthings.fi
 *
 * See BSON specification at http://bsonspec.org/spec.html
 *
 */

#include <inttypes.h>
#include "cbson.h"
#include <string.h>


int bson_init_doc(uint8_t* doc, int32_t max_doc_len) {
    /* Initialise the first 4 bytes to document length (total number of
     * bytes comprising the document), which is 5 for empty document 
     * (doc len: 4 bytes + terminating null byte) */
    const int min_doc_len = BSON_SZ_INT32+1;
    if (min_doc_len > max_doc_len) {
        return BSON_FAIL;
    }

    int32_t new_doc_len = int32_native2le(5);
    memcpy(doc, &new_doc_len, BSON_SZ_INT32);
    *(doc+4) = 0;
    return BSON_SUCCESS;
}


int bson_write_double(uint8_t *doc, int32_t max_doc_len, char *e_name, double value) {
    int32_t doc_len = bson_get_doc_len(doc);
    int name_len = strlen(e_name);
    /* The length of the document document with the a double element added is:
     * old doc len + type byte + length of elem name + null 
     *      + length of int32 data
     */
    int32_t updated_doc_len = doc_len + 1 + name_len + 1 + BSON_SZ_DOUBLE;
    if (updated_doc_len > max_doc_len) {
        return BSON_FAIL;
    }

    /* Writer pointer, the location of our "quill" */
    uint8_t* writer_ptr = doc+doc_len-1;
    /* Write value type */
    *writer_ptr = BSON_KEY_DOUBLE;
    writer_ptr++; /* Advance */
    memcpy(writer_ptr, e_name, name_len);
    writer_ptr += name_len; /* Advance "quill location" */
    *writer_ptr = 0;    /* Null terminate the name */
    writer_ptr++;   /* Advance "quill location" */
    memcpy(writer_ptr, &value, BSON_SZ_DOUBLE);
    writer_ptr += BSON_SZ_DOUBLE; /* Advance quill */
    *writer_ptr = 0; /* Document terminating null */
    
    /* Update document length */
    int32_t tmp_doc_len = int32_native2le(updated_doc_len);
    memcpy(doc, &tmp_doc_len, BSON_SZ_INT32);

    return BSON_SUCCESS;
}

int bson_write_int32(uint8_t* doc, int32_t max_doc_len, char* e_name, int32_t value) {
    /* 1) Check current length of document 
     * if 0, clear the entire buffer and initialise length to '5'
     * 2) find the place of the new element to be encoded using the
     * length (length - 1 actually?)
     * 3) encode the new element
     * 4) Update the length
     * 5) Ensure that the last byte is 0.
     */

    int32_t doc_len = bson_get_doc_len(doc);
    int name_len = strlen(e_name);
    /* The length of the document document with the an int32 element added is:
     * old doc len + type byte + length of elem name + null 
     *      + length of int32 data
     */
    int32_t updated_doc_len = doc_len + 1 + name_len + 1 + BSON_SZ_INT32;
    if (updated_doc_len > max_doc_len) {
        return BSON_FAIL;
    }

    /* Writer pointer, the location of our "quill" */
    uint8_t* writer_ptr = doc+doc_len-1;
    /* Write value type */
    *writer_ptr = BSON_KEY_INT32;
    writer_ptr++; /* Advance */
    memcpy(writer_ptr, e_name, name_len);
    writer_ptr += name_len; /* Advance "quill location" */
    *writer_ptr = 0;    /* Null terminate the name */
    writer_ptr++;   /* Advance "quill location" */
    int32_t tmp_value =  int32_native2le(value);
    memcpy(writer_ptr, &tmp_value, BSON_SZ_INT32);
    writer_ptr += BSON_SZ_INT32; /* Advance quill */
    *writer_ptr = 0; /* Document terminating null */
    
    /* Update document length */
    int32_t tmp_doc_len = int32_native2le(updated_doc_len);
    memcpy(doc, &tmp_doc_len, BSON_SZ_INT32);

    return BSON_SUCCESS;
}


int bson_write_binary(uint8_t* doc, int32_t max_doc_len, char* e_name, 
        uint8_t* buffer, int32_t buffer_len) {

    int32_t doc_len = bson_get_doc_len(doc);
    int name_len = strlen(e_name);
    /* The length of the document document with the an int32 element added is:
     * old doc len + type byte + length of elem name + null 
     *      + length of buffer (4 bytes) + subtype (1 byte) + length of buffer
     */
    int32_t updated_doc_len = doc_len + 1 + name_len + 1 + BSON_SZ_INT32
        + 1 + buffer_len;
    if (updated_doc_len > max_doc_len) {
        return BSON_FAIL;
    }
    uint8_t* writer_ptr = doc+doc_len-1; /* Intialise it here, so that
    the document-terminating null byte is overwritten */

    *writer_ptr = BSON_KEY_BINARY;
    writer_ptr++;

    memcpy(writer_ptr, e_name, name_len);
    writer_ptr += name_len;
    *writer_ptr = 0;     /* Terminate e_name string with 0 */
    writer_ptr++;
    int32_t tmp =  int32_native2le(buffer_len);
    memcpy(writer_ptr, &tmp, BSON_SZ_INT32);
    writer_ptr+=BSON_SZ_INT32;
    *writer_ptr = 0;    /* Use subtype 0 always */
    writer_ptr++;
    memcpy(writer_ptr, buffer, buffer_len);
    writer_ptr += buffer_len;
    *writer_ptr = 0;    /* Document terminating NULL byte */

    /* Updated doc len */
    tmp =  int32_native2le(updated_doc_len);
    memcpy(doc, &tmp, BSON_SZ_INT32);

    return BSON_SUCCESS;
}

int bson_write_embedded_doc_or_array(uint8_t* doc, int32_t max_doc_len, char*
e_name, uint8_t* embedded_doc, uint8_t type_doc_or_array) {
    /* First decide if the call is valid */
    if (type_doc_or_array != BSON_KEY_DOCUMENT &&
        type_doc_or_array != BSON_KEY_ARRAY) {
        return BSON_FAIL;
    }
    /* Get the length of the document to which a document will be
     * embedded to */
    int32_t doc_len = bson_get_doc_len(doc);
    /* Get the length of the document to be embedded */
    int32_t embedded_doc_len = bson_get_doc_len(embedded_doc);

    int name_len = strlen(e_name);
    /* Size of the updated document is:
     * original doc len + type byte + length of name + null 
     *      + embedded doc len */
    int32_t updated_doc_len = doc_len + 1 + name_len + 1 + embedded_doc_len;

    if (updated_doc_len > max_doc_len) {
#if BSON_DEBUG
        printf("Too long document in %s @ %d, writing %s maxlen: %d\n", __FILE__, __LINE__, e_name, max_doc_len);
#endif
        return BSON_FAIL;
    }

    /* Writer pointer, the location of our "quill" */
    uint8_t* writer_ptr = doc+doc_len-1;
    /* Write value type */
    *writer_ptr = type_doc_or_array;
    writer_ptr++; /* Advance */
    memcpy(writer_ptr, e_name, name_len);
    writer_ptr += name_len; /* Advance "quill location" */
    *writer_ptr = 0;    /* Null terminate the name */
    writer_ptr++;   /* Advance "quill location" */
    memcpy(writer_ptr, embedded_doc, embedded_doc_len);
    writer_ptr += embedded_doc_len;
    *writer_ptr = 0;  /* Document terminating null */

    /* Update doc len */
    int32_t tmp_doc_len = int32_native2le(updated_doc_len);
    memcpy(doc, &tmp_doc_len, BSON_SZ_INT32);
    return BSON_SUCCESS;
}



int32_t int32_native2le(int32_t native_int32) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return native_int32;
#else 
#error Big endian platform detected, please check imlementation
    /* A union for holding 4 bytes of data, which can be accessed as int32
     * or as an array of 4 bytes. */
    union int32_be_data {
        int32_t be_order;
        char raw[4];
    } data;

    data.be_order = native_int32;
    int32_t le_int32 = 0;
    le_int32 |= data.raw[0];
    le_int32 <<= 8;
    le_int32 |= data.raw[1];
    le_int32 <<= 8;
    le_int32 |= data.raw[2];
    le_int32 <<= 8;
    le_int32 |= data.raw[3];
    return le_int32;
#endif
}

int bson_write_string(uint8_t* doc, int32_t doc_max_len, char* e_name, char* embedded_str) {
    int32_t curr_doc_len = bson_get_doc_len(doc);
    int32_t embedded_str_len = strlen(embedded_str);
    int32_t name_len = strlen(e_name);
    /* The length of the document document with the the string element added is:
     * old doc len + type byte + length of elem name + null 
     *      + length of string (4 bytes) + strlen(str) + null +
     *          final_terminating_null 
     */
    int32_t updated_doc_len = curr_doc_len + 1 + name_len + 1 + BSON_SZ_INT32
        + embedded_str_len + 1;

    uint8_t* quill = doc+curr_doc_len-1;
    *quill = BSON_KEY_STRING;
    quill++;    /* Advance quill */
    memcpy(quill, e_name, name_len);
    quill+=name_len;
    *quill='\0'; /* Null-terminate name */
    quill++;
    int32_t tmp =  int32_native2le(embedded_str_len+1); /* +1, account
    for terminating null char */
    memcpy(quill, &tmp, BSON_SZ_INT32);
    quill += BSON_SZ_INT32;
    memcpy(quill, embedded_str, embedded_str_len);
    quill+=embedded_str_len;
    *quill='\0'; /* Null-terminate string */
    quill++;
    /* Update new doc len */
    tmp = int32_native2le(updated_doc_len);
    memcpy(doc, &tmp, BSON_SZ_INT32);
    *quill = 0; /* Document terminating null */

    return BSON_SUCCESS;
}


int bson_write_boolean(uint8_t* doc, int32_t max_doc_len, char* e_name, bool value) {
    int32_t curr_doc_len = bson_get_doc_len(doc);
    int32_t name_len = strlen(e_name);
    /* The length of the document document with the a boolean element added is:
     * old doc len + type byte + length of elem name + null 
     *      +boolean value (1 byte)
     */
    int32_t updated_doc_len = curr_doc_len + 1 + name_len + 1 + 1;
    if (updated_doc_len > max_doc_len) {
        return BSON_FAIL;
    }
    /* Writer pointer, the location of our "quill" */
    uint8_t* writer_ptr = doc+curr_doc_len-1;
    /* Write value type */
    *writer_ptr = BSON_KEY_BOOLEAN;
    writer_ptr++; /* Advance */
    memcpy(writer_ptr, e_name, name_len);
    writer_ptr += name_len; /* Advance "quill location" */
    *writer_ptr = 0;    /* Null terminate the e_name */
    writer_ptr++;   /* Advance "quill location" */
    *writer_ptr = value; /* Encode boolean value */
    writer_ptr++;   /* Advance quill */
    *writer_ptr = 0; /* Document terminating null */
    
    /* Update document length */
    int32_t tmp_doc_len = int32_native2le(updated_doc_len);
    memcpy(doc, &tmp_doc_len, BSON_SZ_INT32);

    return BSON_SUCCESS;

}
