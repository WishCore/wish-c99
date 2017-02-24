#pragma once

/** Port-specific config variables */

/** This specifies the size of the receive ring buffer */
#define WISH_PORT_RX_RB_SZ ( 32*1024 )

/** This specifies the maximum number of simultaneous Wish connections
 * */
#define WISH_PORT_CONTEXT_POOL_SZ   10

/** This specifies the maximum size of the buffer where some RPC handlers build the reply (1400) */
#define WISH_PORT_RPC_BUFFER_SZ ( 16*1024 )

/** This defines the maximum number of entries in the Wish local discovery table (4).
 * You should make sure that in the worst case any message will fit into WISH_PORT_RPC_BUFFFER_SZ  */
#define WISH_LOCAL_DISCOVERY_MAX ( 64 ) /* wld.list: 64 local discoveries should fit in 16k RPC buffer size */

/** This defines the maximum number of uids in database (max number of identities + contacts) (4) 
     You should make sure that in the worst case any message will fit into WISH_PORT_RPC_BUFFFER_SZ */
#define WISH_PORT_MAX_UIDS ( 128 ) /* identity.list: 128 uid entries should fit into 16k RPC buffer */


/** If this is defined, include support for the App TCP server */
#define WITH_APP_TCP_SERVER
//#define WITH_APP_INTERNAL

/** If this is defined, any friend request is accepted automatically if
 * id database contains just one entry */
//#define WISH_ACCEPT_ANY_FRIEND_REQ_IF_NO_FRIENDS

/** If this is defined, all fried requests are automatically accepted! */
//#define WISH_ALLOW_ALL_FRIEND_REQS

/** With this define you get fancy ANSI colored output on the console */
#define WISH_CONSOLE_COLORS
