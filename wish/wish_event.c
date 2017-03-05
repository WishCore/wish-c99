#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "wish_core.h"
#include "wish_event.h"
#include "wish_debug.h"
#include "wish_rpc.h"
#include "wish_connection_mgr.h"
#include "wish_core_rpc_func.h"
#include "wish_identity.h"
#include "wish_utils.h"



/* This task will be set up at the by of message_processor_task_init().
 * The OS task system will be notified from tcp_recv_cb, 
 * when new data becomes available. The Task system will then call this
 * function. Note that this not a thread, the system is still
 * single-tasking and not pre-empting. If you spend too much time in
 * this function, chaos will ensue. */
void wish_message_processor_task(wish_core_t* core, struct wish_event *e) {
    switch (e->event_type) {
    case WISH_EVENT_CONTINUE:
        WISHDEBUG(LOG_DEBUG,"Message processing started (continuation)\n\r");
        break;
    case WISH_EVENT_NEW_DATA:
        WISHDEBUG(LOG_DEBUG,"Message processing started (new data received)\n\r");
        break;
    case WISH_EVENT_NEW_CORE_CONNECTION:
        {
            /* Load the aliases of the connection partners from DB */
            wish_identity_t *tmp_id = wish_platform_malloc(sizeof (wish_identity_t));
            if (tmp_id == NULL) {
                WISHDEBUG(LOG_CRITICAL, "message processor task: Could not allocate memory");
                break;
            }
            
            return_t load_retval = wish_load_identity(e->context->local_wuid, tmp_id);
            char *local_alias = my_strdup(tmp_id->alias);
            
            return_t load_retval2 = wish_load_identity(e->context->remote_wuid, tmp_id);
            char *remote_alias = my_strdup(tmp_id->alias);
            
            if (load_retval != ret_success || load_retval2 != ret_success) {
                WISHDEBUG(LOG_CRITICAL, "Unexpected problem with id db!");
            }

            if (local_alias != NULL && remote_alias != NULL) {
                WISHDEBUG(LOG_CRITICAL ,"Connection established: %s > %s", local_alias, remote_alias);

                wish_platform_free(tmp_id);
                wish_platform_free(local_alias);
                wish_platform_free(remote_alias);
            }

            e->context->context_state = WISH_CONTEXT_CONNECTED;
        }
        break;
    default:
        break;
    }

    wish_connection_t* connection = e->context;

    switch (e->event_type) {
    case WISH_EVENT_CONTINUE:
    case WISH_EVENT_NEW_DATA:
        wish_core_process_data(core, connection);
        break;
    case WISH_EVENT_NEW_CORE_CONNECTION:
        wish_core_send_peers_rpc_req(core, connection);
        break;
    case WISH_EVENT_FRIEND_REQUEST:
        WISHDEBUG(LOG_CRITICAL, "Received friend request");
        
#ifdef WISH_ACCEPT_ANY_FRIEND_REQ_IF_NO_FRIENDS
        /* If WISH_ACCEPT_ANY_FRIEND_IF_NO_FRIENDS is defined, then we allow a
         * friend request if there is only one identity in the id
         * database. */
        {
            wish_uid_list_elem_t uid_list[2];
            memset(uid_list, 0, sizeof (uid_list));

            int num_ids = wish_load_uid_list(uid_list, 2);
            if (num_ids > 1) {
                WISHDEBUG(LOG_CRITICAL, "Since number of identities in db is %d, we deny the friend request automatically.", num_ids);
                break;
            }
            else {
                WISHDEBUG(LOG_CRITICAL, "Since number of identities in db is %d we accept the friend request automatically.", num_ids);
                
                struct wish_event new_evt = {
                    .event_type = WISH_EVENT_ACCEPT_FRIEND_REQUEST,
                    .context = connection,
                };
                wish_message_processor_notify(&new_evt);
                
            }
        }
#endif
        
        break;
    case WISH_EVENT_ACCEPT_FRIEND_REQUEST:
        if (connection->curr_protocol_state == PROTO_SERVER_STATE_READ_FRIEND_CERT) {
            connection->curr_protocol_state = PROTO_SERVER_STATE_REPLY_FRIEND_REQ_ACCEPTED;
            wish_core_handle_payload(core, connection, NULL, 0);
        }
        else {
            WISHDEBUG(LOG_CRITICAL, "Unexpected state, closing connection!");
            wish_close_connection(core, connection);
        }

        break;
    case WISH_EVENT_DECLINE_FRIEND_REQUEST:
        if (connection->curr_protocol_state == PROTO_SERVER_STATE_READ_FRIEND_CERT) {
            connection->curr_protocol_state = PROTO_SERVER_STATE_REPLY_FRIEND_REQ_DECLINED;
            wish_core_handle_payload(core, connection, NULL, 0);
        }
        else {
            WISHDEBUG(LOG_CRITICAL, "Unexpected state, closing connection!");
            wish_close_connection(core, connection);
        }

        break;
    case WISH_EVENT_REQUEST_CONNECTION_CLOSING:
        wish_close_connection(core, connection);
        break;
    default:
        WISHDEBUG(LOG_CRITICAL,"Uknown event type %d\n\r", e->event_type);
        break;
 
    }
}


