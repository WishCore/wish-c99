/* 
 * Wish message processor task for ESP8266 runtime 
 */

#include "c_types.h"
#include "espmissingincludes.h"
#include "user_interface.h"
#include "../wish/wish_io.h"
#include "os_type.h"
#include "user_task.h"
#include "osapi.h"
#include "user_config.h"
#include "mem.h"
#include "wish_event.h"
#include "mist_follow.h"
#include "mist_app.h"
#include "mist_model.h"
#include "user_hw_config.h"

#define MESSAGE_PROCESSOR_TASK_ID 0
#define MIST_FOLLOW_TASK_ID 1

#define TASK_EVENT_QUEUE_LEN 4
#define FOLLOW_EVENT_QUEUE_LEN 4

os_event_t *task_event_queue;

os_event_t *follow_event_queue;

static void my_message_processor_task(ETSEvent *e) {
    struct wish_event ev = { .event_type = e->sig, 
        .context = (wish_context_t *)e->par };
    wish_message_processor_task(&ev);
}

/* Initialise a event queue for handling messages. */
void wish_message_processor_init(void) {
    task_event_queue 
        = (os_event_t*) os_malloc(sizeof(os_event_t)*TASK_EVENT_QUEUE_LEN);
    system_os_task(my_message_processor_task, MESSAGE_PROCESSOR_TASK_ID, 
        task_event_queue, TASK_EVENT_QUEUE_LEN);
}

static void my_follow_task(ETSEvent *e) {
    mist_follow_task();
    /* FIXME get these from intermediate */
    struct mist_model *model = (struct mist_model *) e->sig;
    mist_ep* endpoint = (mist_ep *) e->par;
    /* Send notify messages for any mappings we might have */
    mist_mapping_notify(model, endpoint);
}

/* This will initialize an OS task for generating "follow" messages.
 * Will setup a timer, but will not start it */
void mist_follow_task_init(void) {
    /* Set up a task which will send "follow replies" when data is
     * written */
    follow_event_queue 
        = (os_event_t*) os_malloc(sizeof(os_event_t)*FOLLOW_EVENT_QUEUE_LEN);
    system_os_task(my_follow_task, MIST_FOLLOW_TASK_ID, 
        follow_event_queue, FOLLOW_EVENT_QUEUE_LEN);

}

void mist_follow_task_signal(struct mist_model *model, mist_ep* endpoint) {
    /* FIXME this is quite bad, but needed to convey information about mappings.
     * We should have an array of intermediate objects instead? */
    system_os_post(MIST_FOLLOW_TASK_ID, (uint32_t) model, (uint32_t) endpoint); 
}



void wish_message_processor_notify(struct wish_event *ev) {
    system_os_post(MESSAGE_PROCESSOR_TASK_ID, ev->event_type, (uint32_t) ev->context);
}

void user_display_malloc(void) {
#ifdef MEMLEAK_DEBUG
    system_show_malloc();
#else
    os_printf("no malloc info available\n\r");
#endif  //MEMLEAK_DEBUG
}
