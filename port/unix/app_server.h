#define NUM_APP_CONNECTIONS 20

#define APP_RX_RB_SZ 1024

void setup_app_server(uint16_t port);

/* This defines the possible states of an App connection */
enum app_state { APP_CONNECTION_INITIAL, APP_CONNECTION_CONNECTED };
enum app_transport_state { APP_TRANSPORT_INITIAL, APP_TRANSPORT_WAIT_FRAME_LEN, 
    APP_TRANSPORT_WAIT_PAYLOAD, APP_TRANSPORT_CLOSING };

void app_connection_feed(int i, uint8_t *buffer, size_t buffer_len);

void app_connection_cleanup(int i);

void send_core_to_app_via_tcp(uint8_t wsid[WISH_ID_LEN], uint8_t *data, size_t len);
bool is_app_via_tcp(uint8_t wsid[WISH_WSID_LEN]);
