#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "limits.h"    
    
typedef enum {
    ret_success = INT_MIN,
    ret_fail,
} return_t;

#ifdef __cplusplus
}
#endif
