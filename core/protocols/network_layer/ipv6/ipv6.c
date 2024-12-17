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
parse_ipv6(const u_char *packet, bool verbose){

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

    inet_ntop(AF_INET6, &ip6->ip6_src, ipv6_header.source_address, IPV6_ADDR_SIZE);
    inet_ntop(AF_INET6, &ip6->ip6_dst, ipv6_header.destination_address, IPV6_ADDR_SIZE);

    return ipv6_header;
}