#ifndef WISH_APP_MIST_EXAMPLE_HARDWARE_H
#define WISH_APP_MIST_EXAMPLE_HARDWARE_H

#include <stddef.h>
#include <stdint.h>
#include "mist_model.h"

enum mist_error hw_read_relay(mist_ep* ep, void* result);

enum mist_error hw_write_relay(mist_ep* ep, void* new_value);

enum mist_error hw_read_string(mist_ep* ep, void* result);

enum mist_error hw_invoke_function(mist_ep* ep, mist_buf args);

#endif