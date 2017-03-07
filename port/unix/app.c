#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <time.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>

#include "wish_version.h"
#include "wish_io.h"
#include "wish_event.h"
#include "wish_platform.h"


#include "cbson.h"

#include "wish_core.h"
#include "wish_local_discovery.h"
#include "wish_connection_mgr.h"
#include "wish_core_rpc_func.h"
#include "wish_app.h"
#include "wish_identity.h"
#include "wish_time.h"
#include "bson_visitor.h"
#include "wish_debug.h"

#include "fs_port.h"
#include "wish_relay_client.h"

#include "wish_port_config.h"

#ifdef WITH_APP_TCP_SERVER
#include "app_server.h"
#endif

wish_core_t core_inst;

wish_core_t* core = &core_inst;

void hw_init(void);

extern wish_connection_t wish_context_pool[];  /* Defined in wish_io.c */

void error(const char *msg)
{
    perror(msg);
    exit(0);
}

int write_to_socket(void *sockfd_ptr, unsigned char* buffer, int len) {
    int retval = 0;
    int sockfd = *((int *) sockfd_ptr);
    int n = write(sockfd,buffer,len);
    
    if (n < 0) {
         printf("ERROR writing to socket: %s", strerror(errno));
         retval = 1;
    }

    return retval;
}

#define LOCAL_DISCOVERY_UDP_PORT 9090

void socket_set_nonblocking(int sockfd) {
    int status = fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK);

    if (status == -1){
        perror("When setting socket to non-blocking mode");
        exit(1);
    }
}



/* When the wish connection "i" is connecting and connect succeeds
 * (socket becomes writable) this function is called */
void connected_cb(wish_connection_t *ctx) {
    //printf("Signaling wish session connected \n");
    wish_core_signal_tcp_event(ctx->core, ctx, TCP_CONNECTED);
}

void connected_cb_relay(wish_connection_t *ctx) {
    //printf("Signaling relayed wish session connected \n");
    wish_core_signal_tcp_event(ctx->core, ctx, TCP_RELAY_SESSION_CONNECTED);
}

void connect_fail_cb(wish_connection_t *ctx) {
    printf("Connect fail... \n");
    wish_core_signal_tcp_event(ctx->core, ctx, TCP_DISCONNECTED);
}

int wish_open_connection(wish_core_t* core, wish_connection_t *ctx, wish_ip_addr_t *ip, uint16_t port, bool relaying) {
    ctx->core = core;
    
    //printf("should start connect\n");
    int *sockfd_ptr = malloc(sizeof(int));
    if (sockfd_ptr == NULL) {
        printf("Malloc fail");
        exit(1);
    }
    *(sockfd_ptr) = socket(AF_INET, SOCK_STREAM, 0);
    

    int sockfd = *(sockfd_ptr);
    socket_set_nonblocking(sockfd);

    wish_core_register_send(core, ctx, write_to_socket, sockfd_ptr);

    //printf("Opening connection sockfd %i\n", sockfd);
    if (sockfd < 0) {
        perror("ERROR opening socket");
    }

    // set ip and port to wish connection
    memcpy(ctx->rmt_ip_addr, ip->addr, WISH_IPV4_ADDRLEN);
    ctx->remote_port = port;
    
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    
    // set ip
    char ip_str[20];
    snprintf(ip_str, 20, "%d.%d.%d.%d", ip->addr[0], ip->addr[1], ip->addr[2], ip->addr[3]);
    inet_aton(ip_str, &serv_addr.sin_addr);
    
    // set port
    serv_addr.sin_port = htons(port);
    
    int ret = connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr));
    if (ret == -1) {
        if (errno == EINPROGRESS) {
            WISHDEBUG(LOG_DEBUG, "Connect now in progress");
            ctx->curr_transport_state = TRANSPORT_STATE_CONNECTING;
        }
        else {
            perror("Unhandled connect() errno");
        }
    }
    else if (ret == 0) {
        printf("Cool, connect succeeds immediately!\n");
        if (ctx->via_relay) {
            connected_cb_relay(ctx);
        }
        else {
            connected_cb(ctx);
        }
    }
    return 0;
}

void wish_close_connection(wish_core_t* core, wish_connection_t *ctx) {
    /* Note that because we don't get a callback invocation when closing
     * succeeds, we need to excplicitly call TCP_DISCONNECTED so that
     * clean-up will happen */
    ctx->context_state = WISH_CONTEXT_CLOSING;
    int sockfd = *((int *)ctx->send_arg);
    close(sockfd);
    free(ctx->send_arg);
    wish_core_signal_tcp_event(core, ctx, TCP_DISCONNECTED);
}

char usage_str[] = "Wish Core v" WISH_CORE_VERSION_STRING
"\n\n  Usage: %s [options]\n\
    -b broadcast own uid over local discovery\n\
    -l listen to local discovery broadcasts\n\
\n\
    -s start accepting incoming connections (\"server\" mode)\n\
    -p <port> listen for incoming connections at this TCP port\n\
    -r connect to a relay server, for accepting incoming connections via the relay.\n\
\n\
    -a <port> start \"App TCP\" interface server at port\n\
\n\
    Direct client connection:\n\
    -c <ip_addr> open a direct client connection to this IP addr\n\
    -C <port> use specified TCP destination port when connecting as direct client\n\
    -R <alias> The remote party's alias name (in local contact DB)\n";

static void print_usage(char *executable_name) {
    printf(usage_str, executable_name);
}

/* -b Start the "server" part, and start broadcastsing local discovery
 * adverts */
bool advertize_own_uid = false;
/* -l Start to listen to adverts, and connect when advert is received */
bool listen_to_adverts = false;

/* -c <addr> Start as a client, connecting to a specified addr */
bool as_client = false;
struct in_addr peer_addr;
uint16_t peer_port;
/* -R remote identity's name */
char* remote_id_alias = NULL;
/* When as_client is true, the remote identity to be contacted is here */
wish_identity_t remote_identity;

/* -s Accept incoming connections  */
bool as_server = false;

/* -p The Wish TCP port to listen to (when -l or -s is given), or the port
 * to connect to when -c */
uint16_t port = 0;

/* -r <relay_host> Start a relay client session to relay host for
 * accepting connections relayed by the relay host */
struct in_addr relay_server_addr;
bool as_relay_client = false;

#ifdef WITH_APP_TCP_SERVER
/* -a <app_port> The port number of the "Application" TCP port */
bool as_app_server = false;
uint16_t app_port = 0;
extern int app_serverfd; /* Defined in app_server.c */
extern int app_fds[];
extern enum app_state app_states[];
#endif


/* Process the command line options. The function will set global
 * variables accordingly */
static void process_cmdline_opts(int argc, char** argv) {
    int opt = 0;
    while ((opt = getopt(argc, argv, "hblc:C:R:sp:ra:")) != -1) {
        switch (opt) {
        case 'b':
            printf("Would start as advertizer\n");
            advertize_own_uid = true;
            break;
        case 'l':
            printf("Would start as ad listener\n");
            listen_to_adverts = true;
            break;
        case 'c':
            printf("Would start as client to ip %s\n", optarg);
            if (inet_pton(AF_INET, optarg, &peer_addr) == 0) {
                printf("Badly formmet IP addr\n");
                exit(1);
            }
            as_client = true;
            break;
        case 'C':
            peer_port = atoi(optarg);
            break;
        case 'R':
            /* -R is to be used mainly with -c so that the remote ID can
             * be provided */ 
            printf("Remote identity %s\n", optarg);
            remote_id_alias = strdup(optarg);
            break;
        case 's':
            printf("Would start as server\n");
            as_server = true;
            break;
        case 'p':
            port = atoi(optarg);
            wish_set_host_port(core, port);
            printf("Would use port %hu\n", port);
            break;
        case 'r':
            printf("Acting as relay client to relay server\n");
            //inet_pton(AF_INET, optarg, &relay_server_addr);
            as_relay_client = true;
            break;
        case 'a':
#ifdef WITH_APP_TCP_SERVER
            app_port = atoi(optarg);
            printf("Starting the app port at %hu\n", app_port);
            as_app_server = true;
#else // WITH_APP_TCP_SERVER
            printf("App tcp server not included in build!\n");
            exit(1);
#endif
            break;
        default:
            print_usage(argv[0]);
            exit(1);
            break;
        }
    }

}


/* The different sockets we are using */

/* The UDP Wish local discovery socket */
int wld_fd = 0;
struct sockaddr_in sockaddr_wld;

/* This function sets up a UDP socket for listening to UDP local
 * discovery broadcasts */
void setup_wish_local_discovery(void) {
    wld_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (wld_fd == -1) {
        error("udp socket");
    }

#if 1
    /* Set socketoption REUSEADDR on the UDP local discovery socket so
     * that we can have several programs listening on the one and same
     * local discovery port 9090 */
    int option = 1;
    setsockopt(wld_fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
#endif

    socket_set_nonblocking(wld_fd);

    memset((char *) &sockaddr_wld, 0, sizeof(struct sockaddr_in));
    sockaddr_wld.sin_family = AF_INET;
    sockaddr_wld.sin_port = htons(LOCAL_DISCOVERY_UDP_PORT);
    sockaddr_wld.sin_addr.s_addr = INADDR_ANY;

    if (bind(wld_fd, (struct sockaddr*) &sockaddr_wld, 
            sizeof(struct sockaddr_in))==-1) {
        error("local discovery bind()");
    }

}

/* This function reads data from the local discovery socket. This
 * function should be called when select() indicates that the local
 * discovery socket has data available */
void read_wish_local_discovery(void) {
    const int buf_len = 1024;
    uint8_t buf[buf_len];
    int blen;
    socklen_t slen = sizeof(struct sockaddr_in);

    blen = recvfrom(wld_fd, buf, sizeof(buf), 0, (struct sockaddr*) &sockaddr_wld, &slen);
    if (blen == -1) {
      error("recvfrom()");
    }

    if (blen > 0) {
        //printf("Received from %s:%hu\n\n",inet_ntoa(sockaddr_wld.sin_addr), ntohs(sockaddr_wld.sin_port));
        union ip {
           uint32_t as_long;
           uint8_t as_bytes[4];
        } ip;
        /* XXX Don't convert to host byte order here. Wish ip addresses
         * have network byte order */
        //ip.as_long = ntohl(sockaddr_wld.sin_addr.s_addr);
        ip.as_long = sockaddr_wld.sin_addr.s_addr;
        wish_ip_addr_t ip_addr;
        memcpy(&ip_addr.addr, ip.as_bytes, 4);
        //printf("UDP data from: %i, %i, %i, %i\n", ip_addr.addr[0],
        //    ip_addr.addr[1], ip_addr.addr[2], ip_addr.addr[3]);

        wish_ldiscover_feed(core, &ip_addr, 
           ntohs(sockaddr_wld.sin_port), buf, blen);
    }
}

void cleanup_local_discovery(void) {
    close(wld_fd);

}

int wish_send_advertizement(wish_core_t* core, uint8_t *ad_msg, size_t ad_len) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("Could not create socket for broadcasting");
        exit(1);
    }

    int broadcast = 1;
    if (setsockopt(s, SOL_SOCKET, SO_BROADCAST, 
            &broadcast, sizeof(broadcast))) {
        error("set sock opt");
    }


    struct sockaddr_in sockaddr_src;
    memset(&sockaddr_src, 0, sizeof (struct sockaddr_in));
    sockaddr_src.sin_family = AF_INET;
    sockaddr_src.sin_port = 0;
    if (bind(s, (struct sockaddr *)&sockaddr_src, sizeof(struct sockaddr_in)) != 0) {
        error("Send local discovery: bind()");
    }
    struct sockaddr_in si_other;
    si_other.sin_family = AF_INET;
    si_other.sin_port = htons(LOCAL_DISCOVERY_UDP_PORT);
    inet_aton("255.255.255.255", &si_other.sin_addr);
    socklen_t addrlen = sizeof(struct sockaddr_in);

    if (sendto(s, ad_msg, ad_len, 0, 
            (struct sockaddr*) &si_other, addrlen) == -1) {
        if (errno == ENETUNREACH || errno == ENETDOWN) {
            printf("wld: Network currently unreachable, or down. Retrying later.\n");
        } else {
            error("sendto()");
        }
    }

    close(s);
    return 0;
}

/* The fd for the socket that will be used for accepting incoming
 * Wish connections */
int serverfd = 0;


/* This functions sets things up so that we can accept incoming Wish connections
 * (in "server mode" so to speak)
 * After this, we can start select()ing on the serverfd, and we should
 * detect readable condition immediately when a TCP client connects.
 * */
void setup_wish_server(wish_core_t* core) {
    serverfd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverfd < 0) {
        perror("server socket creation");
        exit(1);
    }
    int option = 1;
    setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
    socket_set_nonblocking(serverfd);

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof (server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(wish_get_host_port(core));
    if (bind(serverfd, (struct sockaddr *) &server_addr, 
            sizeof(server_addr)) < 0) {
        perror("ERROR on binding wish server socket");
        printf("setup_wish_server: Trying to bind port %d failed.\n", server_addr.sin_port);
        exit(1);
    }
    int connection_backlog = 1;
    if (listen(serverfd, connection_backlog) < 0) {
        perror("listen()");
    }
}

/* The relay control connection sockfd */
extern int relay_sockfd;    /* Defined in relay_client.c */

void relay_ctrl_connected_cb(wish_core_t* core, wish_relay_client_ctx_t *relay);
void relay_ctrl_connect_fail_cb(wish_core_t* core, wish_relay_client_ctx_t *relay);
void relay_ctrl_disconnect_cb(wish_core_t* core, wish_relay_client_ctx_t *relay);


static void update_max_fd(int fd, int *max_fd) {
    if (fd >= *max_fd) {
        *max_fd = fd + 1;
    }
}

static int seed_random_init() {
    unsigned int randval;
    
    FILE *f;
    f = fopen("/dev/urandom", "r");
    
    int c;
    for (c=0; c<32; c++) {
        fread(&randval, sizeof(randval), 1, f);
        srandom(randval);
    }
    
    fclose(f);
    
    return 0;
}

#define IO_BUF_LEN 1000

int main(int argc, char** argv) {
    wish_platform_set_malloc(malloc);
    wish_platform_set_realloc(realloc);
    wish_platform_set_free(free);
    
    wish_platform_set_rng(random);
    wish_platform_set_vprintf(vprintf);
    wish_platform_set_vsprintf(vsprintf);

    wish_fs_set_open(my_fs_open);
    wish_fs_set_read(my_fs_read);
    wish_fs_set_write(my_fs_write);
    wish_fs_set_lseek(my_fs_lseek);
    wish_fs_set_close(my_fs_close);
    wish_fs_set_rename(my_fs_rename);
    wish_fs_set_remove(my_fs_remove);

    // Will provide some random, but not to be considered cryptographically secure
    seed_random_init();
    
#if 0
    /* Tests for parsing IP addr */
    char *url = "wish://192.168.255.255:3333";
    uint8_t ip[4];
    wish_parse_transport_ip(url, strlen(url), ip);
    wish_debug_print_array(LOG_CRITICAL, ip, 4);
    url = "wish://11.1.0.1:23";
    wish_parse_transport_ip(url, strlen(url), ip);
    wish_debug_print_array(LOG_CRITICAL, ip, 4);
#endif

    /* Process command line options */
    if (argc >= 2) {
        printf("Parsing command line options.\n");
        process_cmdline_opts(argc, argv);
    } else {
        printf("Using default parameters. Start with -h for options.\n");

        advertize_own_uid = true;
        listen_to_adverts = true;
        as_server = true;
        as_relay_client = true;
        app_port = 9094;
        as_app_server = true;
    }

    /* Iniailise Wish core (RPC servers) */
    wish_core_init(core);

    wish_core_update_identities(core);
    
    if (as_server) {
        setup_wish_server(core);
    }

    if (listen_to_adverts) {
        setup_wish_local_discovery();
    }

#ifdef WITH_APP_TCP_SERVER
    if (as_app_server) {
        setup_app_server(core, app_port);
    }
#endif

#if 0
    wish_app_mist_modbus_init();
    wish_app_mist_example_init();
#endif
    //wish_app_chat_init();

    
    
    

    while (1) {
        /* The filedescriptor to be polled for reading */
        fd_set rfds;
        /* The filedescriptor to be polled for writing */
        fd_set wfds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);

        /* This variable holds the largest socket fd + 1. It must be
         * updated every time new fd is added to either of the sets */
        int max_fd = 0;

        if (as_server) {
            FD_SET(serverfd, &rfds);
            update_max_fd(serverfd, &max_fd);
        }

        if (listen_to_adverts) {
            FD_SET(wld_fd, &rfds);
            update_max_fd(wld_fd, &max_fd);
        }

        if (as_relay_client) {
            if (core->relay_ctx->curr_state == WISH_RELAY_CLIENT_OPEN) {
                FD_SET(relay_sockfd, &wfds);
                update_max_fd(relay_sockfd, &max_fd);
            }
            else if (core->relay_ctx->curr_state == WISH_RELAY_CLIENT_WAIT_RECONNECT) {
                /* connect to relay server has failed or disconnected and we wait some time before retrying */
            }
            else if (core->relay_ctx->curr_state != WISH_RELAY_CLIENT_INITIAL) {
                FD_SET(relay_sockfd, &rfds);
                update_max_fd(relay_sockfd, &max_fd);
            }
        }

#ifdef WITH_APP_TCP_SERVER
        if (as_app_server) {
            FD_SET(app_serverfd, &rfds);
            update_max_fd(app_serverfd, &max_fd);
            int i;
            for (i = 0; i < NUM_APP_CONNECTIONS; i++) {
                if (app_states[i] == APP_CONNECTION_CONNECTED) {
                    FD_SET(app_fds[i], &rfds);
                    update_max_fd(app_fds[i], &max_fd);
                }
            }
        }
#endif

        int i = -1;
        for (i = 0; i < WISH_PORT_CONTEXT_POOL_SZ; i++) {
            wish_connection_t* ctx = &(core->wish_context_pool[i]);
            if (ctx->context_state == WISH_CONTEXT_FREE) {
                continue;
            }
            int sockfd = *((int *) ctx->send_arg);
            if (ctx->curr_transport_state == TRANSPORT_STATE_CONNECTING) {
                /* If the socket has currently a pending connect(), set
                 * the socket in the set of writable FDs so that we can
                 * detect when connect() is ready */
                FD_SET(sockfd, &wfds);
            }
            else {
                FD_SET(sockfd, &rfds);
            }
            update_max_fd(sockfd, &max_fd);
        }

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        
        fd_set exceptfds;
        
        for (i = 0; i < max_fd; i++) {
            if (FD_ISSET(i, &rfds)) {
                FD_SET(i, &exceptfds);
            }
            if (FD_ISSET(i, &wfds)) {
                FD_SET(i, &exceptfds);
            }
        }

        int select_ret = select(max_fd, &rfds, &wfds, &exceptfds, &tv);

        if (select_ret > 0) {

            if (FD_ISSET(wld_fd, &rfds)) {
                read_wish_local_discovery();
            }

            if (as_relay_client) {
                if (FD_ISSET(relay_sockfd, &wfds)) {
                    int connect_error = 0;
                    socklen_t connect_error_len = sizeof(connect_error);
                    if (getsockopt(relay_sockfd, SOL_SOCKET, SO_ERROR, 
                            &connect_error, &connect_error_len) == -1) {
                        perror("Unexepected getsockopt error");
                        exit(1);
                    }
                    if (connect_error == 0) {
                        /* connect() succeeded, the connection is open */
                        //printf("Relay client connected\n");
                        relay_ctrl_connected_cb(core, core->relay_ctx);
                        wish_relay_client_periodic(core, core->relay_ctx);
                    }
                    else {
                        /* connect fails. Note that perror() or the
                         * global errno is not valid now */
                        printf("relay control connect() failed: %s\n", strerror(connect_error));
                        
                        // FIXME only one relay context assumed!
                        relay_ctrl_connect_fail_cb(core, core->relay_ctx);
                    }
                }

                if (FD_ISSET(relay_sockfd, &rfds)) {
                    uint8_t byte;   /* That's right, we read just one
                        byte at a time! */
                    int read_len = read(relay_sockfd, &byte, 1);
                    if (read_len > 0) {
                        wish_relay_client_feed(core, core->relay_ctx, &byte, 1);
                        wish_relay_client_periodic(core, core->relay_ctx);
                    }
                    else if (read_len == 0) {
                        printf("Relay control connection disconnected\n");
                        relay_ctrl_disconnect_cb(core, core->relay_ctx);
                    }
                    else {
                        perror("relay control read()");
                    }
                }
            }

#ifdef WITH_APP_TCP_SERVER
            if (as_app_server) {
                if (FD_ISSET(app_serverfd, &rfds)) {
                    /* New connection to app server port */
                    //printf("Detected incoming App connection\n");
                    int newsockfd = accept(app_serverfd, NULL, NULL);
                    if (newsockfd < 0) {
                        perror("on accept");
                        exit(1);
                    }
                    socket_set_nonblocking(newsockfd);
                    int i = 0;
                    /* Find a vacant app connection "slot" */
                    for (i = 0; i < NUM_APP_CONNECTIONS; i++) {
                        if (app_states[i] == APP_CONNECTION_INITIAL) {
                            app_fds[i] = newsockfd;
                            app_states[i] = APP_CONNECTION_CONNECTED;
                            break;
                        }
                    }
                    if (i >= NUM_APP_CONNECTIONS) {
                        printf("No vacant app connection found!\n");
                        close(newsockfd);
                    }
 
                }
                
                int i = 0;
                for (i = 0; i < NUM_APP_CONNECTIONS; i++) {
                    if (app_states[i] != APP_CONNECTION_CONNECTED) {
                        /* If the app state is something else than "app connected", then don't do anything. */
                        continue;
                    }
                    if (FD_ISSET(app_fds[i], &rfds)) {
                        /* Existing App connection has become readable */
                        size_t buffer_len = 100;
                        uint8_t buffer[buffer_len];
                        int read_len = read(app_fds[i], buffer, buffer_len);
                        if (read_len > 0) {
                            /* App data can be read */
                            app_connection_feed(core, i, buffer, read_len);
                        }
                        else if (read_len == 0) {
                            /* App has disconnected. Do clean-up */
                            //printf("App has disconnected\n");
                            app_connection_cleanup(core, i);
                            close(app_fds[i]);
                        }
                        else {
                            perror("app connection read()");
                            app_connection_cleanup(core, i);
                            close(app_fds[i]);
                        }
                    }
                }
            }
#endif

            /* Check for Wish connections status changes */
            for (i = 0; i < WISH_PORT_CONTEXT_POOL_SZ; i++) {
                wish_connection_t* ctx = &(core->wish_context_pool[i]);
                if (ctx->context_state == WISH_CONTEXT_FREE) {
                    continue;
                }
                int sockfd = *((int *)ctx->send_arg);
                if (FD_ISSET(sockfd, &rfds)) {
                    /* The Wish connection socket is now readable. Data
                     * can be read without blocking */
                    int rb_free = wish_core_get_rx_buffer_free(core, ctx);
                    if (rb_free == 0) {
                        /* Cannot read at this time because ring buffer
                         * is full */
                        printf("ring buffer full\n");
                        continue;
                    }
                    if (rb_free < 0) {
                        printf("Error getting ring buffer free sz\n");
                        exit(1);
                    }
                    const size_t read_buf_len = rb_free;
                    uint8_t buffer[read_buf_len];
                    int read_len = read(sockfd, buffer, read_buf_len);
                    if (read_len > 0) {
                        //printf("Read some data\n");
                        wish_core_feed(core, ctx, buffer, read_len);
                        struct wish_event ev = { 
                            .event_type = WISH_EVENT_NEW_DATA,
                            .context = ctx };
                        wish_message_processor_notify(&ev);
                    }
                    else if (read_len == 0) {
                        //printf("Connection closed?\n");
                        close(sockfd);
                        free(ctx->send_arg);
                        wish_core_signal_tcp_event(core, ctx, TCP_DISCONNECTED);
                        continue;
                    }
                }
                if (FD_ISSET(sockfd, &wfds)) {
                    /* The Wish connection socket is now writable. This
                     * means that a previous connect succeeded. (because
                     * normally we don't select for socket writability!)
                     * */
                    int connect_error = 0;
                    socklen_t connect_error_len = sizeof(connect_error);
                    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, 
                            &connect_error, &connect_error_len) == -1) {
                        perror("Unexepected getsockopt error");
                        exit(1);
                    }
                    if (connect_error == 0) {
                        /* connect() succeeded, the connection is open
                         * */
                        if (ctx->curr_transport_state 
                                == TRANSPORT_STATE_CONNECTING) {
                            if (ctx->via_relay) {
                                connected_cb_relay(ctx);
                            }
                            else {
                                connected_cb(ctx);
                            }
                        }
                        else {
                            printf("There is somekind of state inconsistency\n");
                            exit(1);
                        }
                    }
                    else {
                        /* connect fails. Note that perror() or the
                         * global errno is not valid now */
                        printf("wish connection connect() failed: %s\n", 
                            strerror(connect_error));
                        connect_fail_cb(ctx);
                    }
                }

            }

            /* Check for incoming Wish connections to our server */
            if (as_server) {
                if (FD_ISSET(serverfd, &rfds)) {
                    //printf("Detected incoming connection!\n");
                    int newsockfd = accept(serverfd, NULL, NULL);
                    if (newsockfd < 0) {
                        perror("on accept");
                        exit(1);
                    }
                    socket_set_nonblocking(newsockfd);
                    /* Start the wish core with null IDs. 
                     * The actual IDs will be established during handshake
                     * */
                    uint8_t null_id[WISH_ID_LEN] = { 0 };
                    wish_connection_t *ctx = wish_connection_init(core, null_id, null_id);
                    if (ctx == NULL) {
                        /* Fail... no more contexts in our pool */
                        printf("No new Wish connections can be accepted!\n");
                        close(newsockfd);
                    }
                    else {
                        int *fd_ptr = malloc(sizeof(int));
                        *fd_ptr = newsockfd;
                        /* New wish connection can be accepted */
                        wish_core_register_send(core, ctx, write_to_socket, fd_ptr);
                        wish_core_signal_tcp_event(core, ctx, TCP_CLIENT_CONNECTED);
                    }
                }
            }


        }
        else if (select_ret == 0) {
            //printf("select() timeout\n");

        }
        else {
            /* Select error return */
            printf("Select error: %i: %s\n", select_ret, strerror(select_ret));
            exit(0);
        }
        
        static time_t timestamp = 0;
        if (time(NULL) > timestamp + 10) {
            timestamp = time(NULL);
            /* Perform periodic action 10s interval
             */
        }

        if (as_relay_client) {
            static time_t relay_check_timestamp = 0;
            if (time(NULL) > relay_check_timestamp + 10) {
                relay_check_timestamp = time(NULL);
                
                if (core->relay_ctx->curr_state == WISH_RELAY_CLIENT_WAIT_RECONNECT) {
                    core->relay_ctx->curr_state = WISH_RELAY_CLIENT_INITIAL;
                }
                
                if (core->relay_ctx->curr_state == WISH_RELAY_CLIENT_INITIAL) {
                    if (core->loaded_num_ids > 0) {
                        // Assume first identity in db is the one we want
                        wish_relay_client_open(core, core->relay_ctx, core->uid_list[0].uid);
                    }
                }
                
            }

        }

        while (1) {
            /* FIXME this loop is bad! Think of something safer */
            /* Call wish core's connection handler task */
            struct wish_event *ev = wish_get_next_event();
            if (ev != NULL) {
                wish_message_processor_task(core, ev);
            }
            else {
                /* There is nothing more to do, exit the loop */
                break;
            }
        }

        static time_t periodic_timestamp = 0;
        if (time(NULL) > periodic_timestamp) {
            /* 1-second periodic interval */
            periodic_timestamp = time(NULL);
            wish_time_report_periodic(core);
        }

        //mist_follow_task();
    }

    return 0;
}
 

/* This function is called when a new service is first detected */
void wish_report_new_service(wish_connection_t *ctx, uint8_t *wsid,
    char *protocol_name_str) {
    printf("Detected new service, protocol %s",
        protocol_name_str);
}

/* This function is called when a Wish service goes up or down */
void wish_report_service_status_change(wish_connection_t *ctx, uint8_t *wsid, bool online) {
    printf("Detected service status change");
}

