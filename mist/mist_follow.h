#ifndef MIST_FOLLOW_H
#define MIST_FOLLOW_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#include "mist_app.h"
#include "mist_model.h"

void mist_follow_task_init(void);

void mist_follow_task(void);

void mist_follow_task_signal(struct mist_model *model, mist_ep* endpoint);

void mist_value_changed(struct mist_model *model, char* ep_name);

/* Generate and send a Mist "follow" reply message */
void generate_mist_follow_msg(mist_app_t *mist_app, mist_ep* endpoint);
    
#ifdef __cplusplus
}
#endif

#endif //MIST_FOLLOW_H
