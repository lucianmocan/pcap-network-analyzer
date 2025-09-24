#include "ipv6.h"

/**
 * @brief Parse the IPv6 header from the packet and
 * return the parsed header
 * 
 * @param packet 
 * @param verbose 
 * @return my_ipv6_header_t 
 */
my_ipv6_header_t 
parse_ipv6(const u_char *packet, bool verbose)
{
    my_ipv6_header_t ipv6_header;

    struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;

    ipv6_header.version = ip6->ip6_ctlun.ip6_un2_vfc >> 4;
    ipv6_header.traffic_class = ip6->ip6_vfc & 0x0F;

    // ip6->ip6_flow is the entire 32 bits row (Version + Traffic Class + Flow Label)
    u_int32_t ntohl_flow = ntohl(ip6->ip6_flow);
    ipv6_header.flow_label = ntohl_flow & MY_IPV6_FLOWLABEL_MASK;
    ipv6_header.dscp_value = (ntohl_flow & IP6FLOW_DSCP_MASK) >> IP6FLOW_DSCP_SHIFT;
    get_dscp_desc(ipv6_header.dscp_value, ipv6_header.dscp_desc, verbose);
    ipv6_header.ecn_value = (ntohl_flow & MY_IPV6_FLOW_ECN_MASK) >> MY_IPV6_FLOW_ECN_SHIFT;
    get_ecn_desc(ipv6_header.ecn_value, ipv6_header.ecn_desc, verbose);

    ipv6_header.payload_length = ntohs(ip6->ip6_plen);

    ipv6_header.next_header = ip6->ip6_nxt;
    // Uses the same values as the IPv4 Protocol field
    ipv4_get_protocol_name(ipv6_header.next_header, ipv6_header.next_header_name, verbose);
    
    ipv6_header.hop_limit = ip6->ip6_hlim;

    // Copy the source and destination addresses
    memcpy(ipv6_header.raw_source_address, ip6->ip6_src.s6_addr, IPV6_INT8_ADDR_SIZE);
    memcpy(ipv6_header.raw_destination_address, ip6->ip6_dst.s6_addr, IPV6_INT8_ADDR_SIZE);

    char source_buffer[IPV6_ADDR_SIZE];
    char destination_buffer[IPV6_ADDR_SIZE];
    inet_ntop(AF_INET6, &ip6->ip6_src, source_buffer, IPV6_ADDR_SIZE);
    inet_ntop(AF_INET6, &ip6->ip6_dst, destination_buffer, IPV6_ADDR_SIZE);
    ipv6_header.source_address = source_buffer;
    ipv6_header.destination_address = destination_buffer;

    return ipv6_header;
}

/**
 * @brief Build the pseudo-header and combine it with the packet
 * "pseudo-header" for IPv6 : https://datatracker.ietf.org/doc/html/rfc2460#section-8.1
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
   |                   Upper-Layer Packet Length                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      zero                     |  Next Header  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * @param packet 
 * @param packet_len 
 * @param src_ip 
 * @param dst_ip 
 * @param next_header 
 * @param combined_len 
 * @return uint16_t* 
 */
uint16_t* build_ipv6_pseudo_header_and_packet(uint8_t *packet, int packet_length, uint8_t *src_ip, uint8_t *dst_ip, uint8_t next_header, int *combined_len)
{   
    // Check sum is different from ICMP because ICMPv6 has to include the pseudo-header of IPv6
    // Create the pseudo-header
    uint8_t pseudo_header[40];
    memcpy(pseudo_header, src_ip, 16);
    memcpy(pseudo_header + 16, dst_ip, 16);
    pseudo_header[32] = (packet_length >> 24) & 0xFF;
    pseudo_header[33] = (packet_length >> 16) & 0xFF;
    pseudo_header[34] = (packet_length >> 8) & 0xFF;
    pseudo_header[35] = packet_length & 0xFF;
    pseudo_header[36] = 0;
    pseudo_header[37] = 0;
    pseudo_header[38] = 0;
    pseudo_header[39] = next_header;

    // Combine the pseudo-header and the packet
    *combined_len = 40 + packet_length;
    uint16_t *combined = (uint16_t*)malloc(*combined_len + (*combined_len % 2));
    memcpy(combined, pseudo_header, 40);
    memcpy((uint8_t*)combined + 40, packet, packet_length);

    // Make sure the combined length is even, add padding if necessary
    if (*combined_len % 2 == 1) {
        ((uint8_t*)combined)[*combined_len] = 0;
        (*combined_len)++;
    }

    return combined;
}