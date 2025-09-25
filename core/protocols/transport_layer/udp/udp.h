#ifndef UDP_H
#define UDP_H

#include <stdint.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "ipv4.h"
#include "ipv6.h"
#include "check_sum.h"

#ifdef __linux
#define IPPROTO_IPV4 IPPROTO_IPIP
#endif

/*
User Datagram Header Format https://www.ietf.org/rfc/rfc768.txt

        0      7 8     15 16    23 24    31  
        +--------+--------+--------+--------+ 
        |     Source      |   Destination   | 
        |      Port       |      Port       | 
        +--------+--------+--------+--------+ 
        |                 |                 | 
        |     Length      |    Checksum     | 
        +--------+--------+--------+--------+ 
        |                                     
        |          data octets ...            
        +---------------- ...                 
*/

typedef struct my_udp_header{
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length; // in octets (header + data)

    uint16_t checksum; // using a different size (addresses are longer with IPv6) pseudo-header for IPv4 and IPv6
                       // IPv6 : https://datatracker.ietf.org/doc/html/rfc2460#section-8.1
                       // IPv4 : https://datatracker.ietf.org/doc/html/rfc768 [Page 2]
    uint16_t calculated_checksum;
    bool checksum_correct;

} my_udp_header_t;

my_udp_header_t parse_udp(const uint8_t *packet, uint8_t *src_add, uint8_t *dst_add, uint8_t net_protocol, bool verbose);

#endif