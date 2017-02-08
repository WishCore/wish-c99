/**
 * Service IPC layer App interface, for routing messages between the Wish
 * core and Wish services. This header file abstracts the
 * implementation, so that the actual IPC mechanism is hidden away.
 *
 * The Service IPC layer must be able to route an incoming frame to the
 * correct service's handler functions saved in wish_app_t.
 */


/**
 * Function for sending a frame from the app to core
 * This is called from the "send" function pointer in wish_app_t, with
 * the wsid obtained from the very same struct
 */
void send_app_to_core(uint8_t *wsid, uint8_t *data, size_t len);

/* 
 * Function called by service IPC layer when sending a frame from the 
 * core to app. 
 * We must then parse the message, and call the on_frame,
 * on_peer or on_ready callback of this object.
 */
void receive_core_to_app(wish_app_t *app, uint8_t *data, size_t len);

