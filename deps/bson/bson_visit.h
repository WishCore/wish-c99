#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "stdint.h"
    
/*
 * This function traverses the bson_doc given as argument, and calls the
 * visitor_func for every element encountered. Document and
 * array elements be recursively handled in the same way. */
void bson_visit(const char* title, const uint8_t* data);

void bson_visit_inner(const uint8_t* data, uint8_t depth);

#ifdef __cplusplus
}
#endif
