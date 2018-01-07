#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "wish_utils.h"
#include "wish_debug.h"

int wish_parse_transport_ip_port(const char *url, size_t url_len, wish_ip_addr_t *ip, uint16_t *port) {
    int ret;
    ret = wish_parse_transport_ip(url, url_len, ip);
    
    if (ret != 0) { return ret; }
    
    wish_parse_transport_port(url, url_len, port);

    return ret;
}

int wish_parse_transport_port(const char *url, size_t url_len, uint16_t *port) {
    /* FIXME implement parsing of ip address */
    int retval = 1;
    if (port == NULL) {
        return retval;
    }

    /* Parse port number by finding the first ':' character when
     * starting from the end of the string */
    char *colon_ptr = strrchr(url, ':');
    if (colon_ptr == NULL) {
        /* colon not found. */
        return retval;
    }
    
    uint16_t parsed_port = atoi(colon_ptr+sizeof (char));
    /* XXX assumption: TCP port number cannot be 0 */
    if (parsed_port != 0) {
        *port = parsed_port;
        retval = 0;
    }
    return retval;
}


int wish_parse_transport_ip(const char *url, size_t url_len, wish_ip_addr_t *ip) {
    int retval = 1;
    const int ip_str_max_len = 4*3+3; /* t.ex. 255.255.255.255 */
    const int ip_str_min_len = 4+3;   /* t.ex. 1.1.1.1 */
    char* first_slash = strchr(url, '/');
    const char* start_of_ip_str;
    if (first_slash == NULL) {
        // maybe only ip:port ?
        start_of_ip_str = url;
    } else {
        start_of_ip_str = first_slash+2;
    }
    char* colon = strchr(start_of_ip_str, ':');
    if (colon == NULL) {
        WISHDEBUG(LOG_CRITICAL, "IP addr parse error");
        return retval;
    }
    
    int actual_ip_str_len = colon-start_of_ip_str;
    if (actual_ip_str_len > ip_str_max_len) {
        WISHDEBUG(LOG_CRITICAL, "Parse error, IP part seems too long");
        return retval;
    }
    if (actual_ip_str_len < ip_str_min_len) {
        WISHDEBUG(LOG_CRITICAL, "Parse error, IP part seems too short");
        return retval;
    }

    if (ip == NULL) {
        return retval;
    }

    /* We now have a valid looking IP address in start_of_ip_str, of
     * length actual_ip_str_len */

    /* Parse out the bytes */
    const int num_bytes = 4; /* There are always 4 dots */
    const char *curr_byte_str = start_of_ip_str;
    int i = 0;
    for (i = 0; i < num_bytes; i++) {
        //WISHDEBUG(LOG_CRITICAL, "curr_byte_str: %s", curr_byte_str);
        ip->addr[i] = atoi(curr_byte_str);
        curr_byte_str = strchr(curr_byte_str, '.') + 1;
        if (curr_byte_str == NULL) {
            WISHDEBUG(LOG_CRITICAL, "IP parse error");
            return retval;
        }
    }
    /* Note that curr_byte_str is invalid after this */
    
    retval = 0;
    return retval;
}



