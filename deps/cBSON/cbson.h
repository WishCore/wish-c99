/*
 * cBSON - a minimal BSON implementation for embedded systems
 *
 * Author: Jan Nyman, jan.nyman@controlthings.fi
 *
 * BSON document marshalling/unmarshalling functions
 *
 * Design rationale: The unmarshalling functions will work "in-place"
 * meaning that the pointers point to data on an existing buffer. This
 * rationale was chosen so that the least memory overhead would occur.
 * The user can then copy the contents to other buffers if need be.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include <stdbool.h>

#define BSON_KEY_INT32 0x10
#define BSON_KEY_BOOLEAN 0x08
#define BSON_KEY_BINARY 0x05
#define BSON_KEY_ARRAY 0x04
#define BSON_KEY_DOCUMENT 0x03
#define BSON_KEY_STRING 0x02
#define BSON_KEY_DOUBLE 0x01

/* Number of bytes comprising an int32 in BSON */
#define BSON_SZ_INT32 4 
#define BSON_SZ_BOOLEAN 1
#define BSON_SZ_DOUBLE 8

#define BSON_SUCCESS 1
#define BSON_FAIL 0

/* Functions for reading */

/* This helper function parses an element pointed by elem_ptr, 
 * saving the element type to localtion pointed by parameter value_type,
 * pointer to the element (key) name the location pointed by parameter 
 * key_name, pointer to the start of the element data (value) to the 
 * location pointed by parameter value, and the length of the element data 
 * to the location pointed by value_len. 
 */
int bson_get_elem_members(uint8_t* elem_ptr, uint8_t* value_type, 
            char** key_name, uint8_t** value, int32_t* value_len);

/* Search the double with name 'e_name' from BSON document 'doc', and 
 * save the double value to location pointed by 'value'
 *
 * Returns BSON_SUCCESS if the element is found, else BSON_FAIL.
 */
int bson_get_double(uint8_t *doc, char *e_name, double* value);

/* Search the integer with name 'e_name' from BSON document 'doc', and 
 * save the interger's value to location pointed by 'value'
 *
 * Returns BSON_SUCCESS if the element is found, else BSON_FAIL.
 */
int bson_get_int32(uint8_t* doc, char *e_name, int32_t* value);

/* Search the binary buffer with name 'e_name' from BSON document 'doc', and
 * save a pointer to the buffer's start to location pointed by
 * 'buffer'. The length of the buffer is saved to located pointed by
 * 'buffer_len'.
 *
 * Returns BSON_SUCCESS if the element is found, else BSON_FAIL.
 */
int bson_get_binary(void* doc, char *e_name, uint8_t** buffer, int32_t *buffer_len);

/* Search the embedded BSON document with name 'e_name' from 
 * BSON document 'doc', and save a pointer to the document's start 
 * to location pointed by 'buffer'. The length of the embedded document is 
 * saved to location pointed by 'buffer_len'.
 *
 * Returns BSON_SUCCESS if the element is found, else BSON_FAIL.
 */
int bson_get_document(void* doc, char *e_name, uint8_t** buffer, int32_t *buffer_len);

/* Search for the array with name 'e_name'. The function
 * works like bson_get_document - in fact they seem to be encoded in a
 * similar way.
 */
int bson_get_array(void* doc, char *e_name, uint8_t** buffer, int32_t *buffer_len);

/* Search the string with name 'e_name' from BSON document 'doc', and 
 * save the interger's value to location pointed by 'value'
 *
 * Returns BSON_SUCCESS if the element is found, else BSON_FAIL.
 */
int bson_get_string(void* doc, char *e_name, char** buffer, int32_t *buffer_len);

/* Search and return value of the boolean element named 'e_name' */
int bson_get_boolean(void* doc, char *e_name, bool* value);

/* Traverse the BSON document 'doc' searching for element of name
 * 'e_name', save its type to location pointed by 'e_type', save a
 * pointer to the start of the element's value data to location 'value', 
 * and save the length of the value to location pointed by 'value_len'.
 */
int bson_get_elem_by_name(uint8_t* doc, char *e_name, 
        uint8_t* e_type, uint8_t** value, int32_t* value_len);

/* Return the BSON document length */
int32_t bson_get_doc_len(uint8_t* doc);

/* Convert an int32 in little endian byte order as an
 * int32 in native byte order */
int32_t int32_le2native(uint8_t* data);

/* Convert an int32 in native (host) byte order as an
 * int32 in little endian byte order */
int32_t int32_native2le(int32_t native_int32);

/* Functions for writing BSON documents */

/* Initialize a BSON document to buffer 'doc' of length 'doc_max_len' */
int bson_init_doc(uint8_t* doc, int32_t doc_max_len);

int bson_write_double(uint8_t *doc, int32_t doc_max_len, char *e_name, double value);

/* Encode the BSON document to document pointed by 'doc' (which must be
 * initilised first, if the document started from scratch). */
int bson_write_int32(uint8_t* doc, int32_t doc_max_len, char* e_name, int32_t value);
/* Encode a binary buffer to document pointed by 'doc' (which must be
 * initialised first, if the document is started from scratch)
 */
int bson_write_binary(uint8_t* doc, int32_t doc_max_len, char* e_name,
        uint8_t* buffer, int32_t buffer_len);

/* Embed the BSON document or array 'embedded_doc' to BSON document 'doc'. 
 * Note that as parameter "type_doc_or_array" you must supply either
 * 0x03 (for a docuemnt) or 0x04 (for an array). */
int bson_write_embedded_doc_or_array(uint8_t* doc, int32_t max_doc_len, char* e_name, uint8_t* embedded_doc, uint8_t type_doc_or_array);

int bson_write_string(uint8_t* doc, int32_t doc_max_len, char* e_name, char* value);

/* Encode a boolean value to boolean element 'e_name' */
int bson_write_boolean(uint8_t* doc, int32_t max_doc_len, char* e_name, bool value);

#ifdef __cplusplus
}
#endif
