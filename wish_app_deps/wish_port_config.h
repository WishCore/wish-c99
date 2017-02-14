#ifndef WISH_PORT_CONFIG_H
#define WISH_PORT_CONFIG_H

/** Port-specific config variables */

/** This specifies the size of the receive ring buffer */
#define WISH_PORT_RX_RB_SZ (10*1024)

/** This specifies the maximum number of simultaneous Wish connections
 * */
#define WISH_PORT_CONTEXT_POOL_SZ   10

/** This specifies the maximum size of the buffer where some RPC handlers build the reply (1400) */
#define WISH_PORT_RPC_BUFFER_SZ ( 16*1024 )

/** If this is defined, include support for the App TCP server */
#define WITH_APP_TCP_SERVER

/** If this is defined, any friend request is accepted automatically if
 * id database contains just one entry */
//#define WISH_ACCEPT_ANY_FRIEND_REQ_IF_NO_FRIENDS

/** If this is defined, all fried requests are automatically accepted! */
#define WISH_ALLOW_ALL_FRIEND_REQS

#ifndef __ANDROID__
/** With this define you get fancy ANSI colored output on the console */
#define WISH_CONSOLE_COLORS
#endif

#endif
