#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "stdint.h"
    
/*
 * This function traverses the bson_doc given as argument, and calls the
 * visitor_func for every element encountered. Document and
 * array elements be recursively handled in the same way. */
void bson_visit(char* title, uint8_t *bson_doc);

void bson_visit_inner(uint8_t *bson_doc, uint8_t depth, void (*visitor_func)(char *elem_name, uint8_t elem_type, uint8_t *elem, uint8_t depth));

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
int bson_filter_out_elem(char *unwanted_elem_name, uint8_t
*source_doc, uint8_t *target_doc);

#ifdef __cplusplus
}
#endif
