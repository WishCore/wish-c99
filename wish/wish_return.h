#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "limits.h"    
    
typedef enum {
    RET_SUCCESS = INT_MIN,
    RET_FAIL,
    RET_E_NO_IDENTITY,
    RET_E_NO_PRIVKEY,
    RET_E_INVALID_INPUT
} return_t;

#ifdef __cplusplus
}
#endif
