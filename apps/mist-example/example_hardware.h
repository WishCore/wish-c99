#ifndef WISH_APP_MIST_EXAMPLE_HARDWARE_H
#define WISH_APP_MIST_EXAMPLE_HARDWARE_H

#include <stddef.h>
#include <stdint.h>
#include "mist_model.h"

enum mist_error example_hw_read(struct mist_model *model, char * id, enum mist_type type, void * result);

enum mist_error example_hw_write(struct mist_model *model, char * id, enum mist_type type, void * new_value);

enum mist_error example_hw_invoke(struct mist_model *model, char * id, uint8_t *args_array, uint8_t *response, size_t response_max_len);

void example_hw_init(struct mist_model *model);

#endif