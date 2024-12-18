#ifndef ICMPV6_H
#define ICMPV6_H

#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include "check_sum.h"
#include "ipv6.h"

#define ICMPV6_TYPE_DESC_SIZE 64
#define ICMPV6_CODE_DESC_SIZE 90
#define MY_DEST_UNREACH_MINLEN 32 // 8 bytes 

#ifdef __linux__
#define ICMPV6_PLD_MAXLEN 1232
#endif 

/*
Destination Unreachable Message
https://datatracker.ietf.org/doc/html/rfc4443#section-3.1 [Page 8]

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |     Type      |     Code      |          Checksum             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                             Unused                            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                    As much of invoking packet                 |
      +                as possible without the ICMPv6 packet          +
      |                exceeding the minimum IPv6 MTU [IPv6]          |


Echo Request Message & Echo Reply Message
https://datatracker.ietf.org/doc/html/rfc4443#section-4.1 [page 13]
https://datatracker.ietf.org/doc/html/rfc4443#section-4.2 [page 14]

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |     Type      |     Code      |          Checksum             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |           Identifier          |        Sequence Number        |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |     Data ...
      +-+-+-+-+-

Neighbor Solicitation Message Format
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     Type      |     Code      |          Checksum             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                           Reserved                            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     +                                                               +
     |                                                               |
     +                       Target Address                          +
     |                                                               |
     +                                                               +
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   Options ...
     +-+-+-+-+-+-+-+-+-+-+-+-
*/

#define MY_ICMPV6_MIN_LEN 8

typedef struct my_icmpv6 {
    uint8_t type;
    char icmpv6_type_desc[ICMPV6_TYPE_DESC_SIZE];

    uint8_t code;
    char icmpv6_code_desc[ICMPV6_CODE_DESC_SIZE];

    uint16_t checksum;
    bool checksum_valid;

    uint16_t identifier;
    uint16_t sequence_number;
    uint8_t *payload; // this is reserved for the ICMPv6 payload

    my_ipv6_header_t og_ipv6_header;

} my_icmpv6_t;


my_icmpv6_t parse_icmpv6(const uint8_t *packet, size_t packet_length, uint8_t *src_ipv6, uint8_t *dst_ipv6, bool verbose);
// helpers
uint16_t* build_icmpv6_pseudo_header_and_packet(uint8_t *packet, int packet_len, uint8_t *src_ip, uint8_t *dst_ip, uint8_t next_header, int *combined_len);
void get_icmpv6_type_desc(uint8_t type, char *desc, bool verbose);
void get_icmpv6_code_desc(uint8_t type, uint8_t code, char *desc, bool verbose);

#endif