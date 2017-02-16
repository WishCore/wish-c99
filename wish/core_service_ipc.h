/*
 * Service IPC, core interface.
 *
 * This is the interface that is used by the Service IPC layer to
 * transfer data in and out of the Wish core 
 */


/* 
 * wsid: the id of the app talking to core 
 */
void receive_app_to_core(uint8_t wsid[WISH_ID_LEN], uint8_t *data, size_t len);

/* wsid: the id the app which should receive the data */
void send_core_to_app(uint8_t wsid[WISH_ID_LEN], uint8_t *data, size_t len);

