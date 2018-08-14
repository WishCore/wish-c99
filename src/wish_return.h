/**
 * Copyright (C) 2018, ControlThings Oy Ab
 * Copyright (C) 2018, André Kaustell
 * Copyright (C) 2018, Jan Nyman
 * Copyright (C) 2018, Jepser Lökfors
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * @license Apache-2.0
 */
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
