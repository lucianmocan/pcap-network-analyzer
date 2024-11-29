#ifndef IPV4_H
#define IPV4_H

#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <stdbool.h>

#include "mac_address.h"

typedef struct my_ipv4_header {
    uint8_t version : 4;
    uint8_t header_length : 4;

    /*  
    ToS no longer used, DSCP and ECN instead
    DSCP: https://datatracker.ietf.org/doc/html/rfc2474#section-3
    DSCP: first 6 bits of ToS 
    */
    char dscp_desc[32];      // DSCP [0-63]
    uint8_t dscp_value;    // Description of the DSCP value

    /*
    ECN: https://datatracker.ietf.org/doc/html/rfc3168#section-5 [Page 8]
    ECN: last 2 bits of ToS
    */
    char ecn_desc[40];       // ECN [0-3]
    uint8_t ecn_value;     // Description of the ECN value

    uint16_t total_length;  
    uint16_t identification;

    /*
    flags: https://datatracker.ietf.org/doc/html/rfc791#section-3.1 [Page 13]
    flags R: 1 bit reserved, should be 0
    flags DF: 0 = May Fragment, 1 = Don't Fragment
    flags MF: 0 = Last Fragment, 1 = More Fragments
    */
    char flags_desc[32]; // Description of the flags
    struct {
        uint8_t reserved: 1;
        uint8_t dont_fragment: 1;
        uint8_t more_fragments: 1;
    } flags;

    uint16_t fragment_offset;
    uint8_t time_to_live;

    uint8_t protocol;
    char protocol_name[16];

    uint16_t checksum;

    char source_ipv4[16];
    char destination_ipv4[16];

} my_ipv4_header_t;

my_ipv4_header_t parse_ipv4(const u_char *packet);

#endif