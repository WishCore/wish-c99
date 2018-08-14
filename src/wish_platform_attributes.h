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
/**
 * Useful linker attributes for the Wish project
 */

/* Declaration specifier for moving an array to flash */

#ifdef COMPILING_FOR_ESP8266
/* Declaration specific for ESP8266 */
#define WISH_ROM_DECL_SPEC __attribute__((section(".irom0.text"))) __attribute__((aligned(4)))
#else
/* It can be empty if you do not have special needs - as you probably
+ * not have if you are on a large system such a "normal computer"  */
#define WISH_ROM_DECL_SPEC
#endif


