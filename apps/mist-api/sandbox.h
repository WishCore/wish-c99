#ifndef SANDBOX_H
#define SANDBOX_H

#include "wish_app.h"

#define SANDBOX_NAME_LEN    32
#define SANDBOX_ID_LEN      32

#ifdef __cplusplus
extern "C" {
#endif

    #include "stdbool.h"

    
    typedef struct sandbox_peers_t {
        wish_protocol_peer_t peer;
        struct sandbox_peers_t* next;
        struct sandbox_peers_t* prev;
    } sandbox_peers_t;

    typedef struct sandbox_t {
        uint8_t name[SANDBOX_NAME_LEN];
        uint8_t sandbox_id[SANDBOX_ID_LEN];
        bool online;
        sandbox_peers_t* peers;
        struct sandbox_t* next;
        struct sandbox_t* prev;
    } sandbox_t;

    sandbox_t* sandbox_init();

    bool sandbox_add_peer(sandbox_t* sandbox, wish_protocol_peer_t* peer);
    
    bool sandbox_remove_peer(sandbox_t* sandbox, wish_protocol_peer_t* peer);
    
#ifdef __cplusplus
}
#endif

#endif /* SANDBOX_H */

