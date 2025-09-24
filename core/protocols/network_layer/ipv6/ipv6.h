#ifndef IPV6_H
#define IPV6_H

#include <net/ethernet.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <string>

#include "dscp.h"
#include "ipv4.h"

#define IPV6_ADDR_SIZE 128
#define IPV6_INT8_ADDR_SIZE 16
#define MY_IPV6_FLOW_ECN_MASK 0x00300000
#define MY_IPV6_FLOW_ECN_SHIFT 20
#define MY_IPV6_FLOWLABEL_MASK 0x000fffff
#define IPV6_HEADER_SIZE 40

#ifdef __linux__
#define IP6FLOW_DSCP_MASK 0x0fc00000
#define IP6FLOW_DSCP_SHIFT 22
#endif

/* IPv6 Header Format https://datatracker.ietf.org/doc/html/rfc8200#section-3 

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version| Traffic Class |           Flow Label                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Payload Length        |  Next Header  |   Hop Limit   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                         Source Address                        +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                      Destination Address                      +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

+ DSCP and ECN in the Traffic Class field
*/

typedef struct my_ipv6_header {
    // Internet Protocol version number = 6.
    uint8_t version : 4;

    // Traffic class
    uint8_t traffic_class : 8;

    // Flow label
    uint32_t flow_label;

    // DSCP
    uint8_t dscp_value;
    std::string dscp_desc;

    // ECN
    uint8_t ecn_value;
    std::string ecn_desc;

    // Payload length
    uint16_t payload_length;

    /* Next Header - Identifies the type of header
    immediately following the IPv6 header.  
    Uses the same values as the IPv4 Protocol field. */
    uint8_t next_header;
    std::string next_header_name;

    // Hop Limit
    uint8_t hop_limit;

    // Source and destination IP addresses
    uint8_t raw_source_address[IPV6_INT8_ADDR_SIZE];
    uint8_t raw_destination_address[IPV6_INT8_ADDR_SIZE];

    std::string source_address;
    std::string destination_address;
} my_ipv6_header_t;

my_ipv6_header_t parse_ipv6(const u_int8_t *packet, bool verbose);
uint16_t* build_ipv6_pseudo_header_and_packet(uint8_t *packet, int packet_length, uint8_t *src_ip, uint8_t *dst_ip, uint8_t next_header, int *combined_len);

#endif