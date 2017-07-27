#ifndef WISH_IP_ADDR_H
#define WISH_IP_ADDR_H

#define WISH_IPV4_ADDRLEN 4

//enum wish_addr_domain { WISH_ADDR_IPV4, WISH_ADDR_IPV6 };

typedef struct {
    //enum wish_addr_domain domain;
    
    /* Wish IPv4 address bytes are saved like this: An address expressed
     * in dotted-decimal notation A.B.C.D is saved into an array like
     * this: byte A is in addr[0], B in addr[1], C in addr[2] and D in addr[3]
     * In other words IP addresses in wish shall have network byte order
     * (big endian).
     */
    uint8_t addr[WISH_IPV4_ADDRLEN];
} wish_ip_addr_t;


#endif
