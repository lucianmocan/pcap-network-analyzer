#include "udp.h"

my_udp_header_t 
parse_udp(const uint8_t *packet, uint8_t *src_add, uint8_t *dst_add, uint8_t net_protocol, bool verbose)
{   
    my_udp_header_t udp_header;

    struct udphdr *udp = (struct udphdr *)packet;
    udp_header.source_port = ntohs(udp->uh_sport);
    udp_header.destination_port = ntohs(udp->uh_dport);
    udp_header.length = ntohs(udp->uh_ulen);

    // Checksum
    udp_header.checksum = ntohs(udp->uh_sum);
    udp->uh_sum = 0;

    // Build the pseudo-header and packet
    int combined_len;
    uint16_t *combined;
    if (net_protocol == IPPROTO_IPV4){
        combined = build_ipv4_pseudo_header_and_packet((uint8_t*)udp, udp_header.length, src_add, dst_add, IPPROTO_UDP, &combined_len);
    } else if (net_protocol == IPPROTO_IPV6) {
        combined = build_ipv6_pseudo_header_and_packet((uint8_t*)udp, udp_header.length, src_add, dst_add, IPPROTO_UDP, &combined_len);
    }

    // Calculate the checksum
    uint16_t calculated_checksum = ntohs(calculate_checksum(combined, combined_len));
    
    // Check if checksum match
    udp_header.checksum_correct = (calculated_checksum == udp_header.checksum);

    return udp_header;
}