#include "ipv4.h"

/**
 * @brief Parse the ipv4 header off a packet (the packet starts with the ipv4 header,
 * should be updated by the caller to point to the start of the ipv4 header) and return
 * all the information in a my_ipv4_header_t struct
 * 
 * @param packet 
 * @return my_ipv4_header_t 
 */
my_ipv4_header_t 
parse_ipv4(const uint8_t *packet, bool verbose)
{
    struct ip *ip;
    ip = (struct ip*)(packet);

    my_ipv4_header_t ipv4_header;

    ipv4_header.version = ip->ip_v;
    ipv4_header.header_length = ip->ip_hl;

    // DSCP
    ipv4_header.dscp_value = ip->ip_tos >> IPTOS_DSCP_SHIFT;
    get_dscp_desc(ipv4_header.dscp_value, ipv4_header.dscp_desc, verbose);

    // ECN
    ipv4_header.ecn_value = ip->ip_tos & IPTOS_ECN_MASK;
    get_ecn_desc(ipv4_header.ecn_value, ipv4_header.ecn_desc, verbose);

    ipv4_header.total_length = ntohs(ip->ip_len);
    ipv4_header.identification = ntohs(ip->ip_id);

    // Fragment offset
    ipv4_header.fragment_offset = ntohs(ip->ip_off) & IP_OFFMASK;

    // Flags
    ipv4_header.flags.reserved = (ntohs(ip->ip_off) & IP_RF) >> 15;
    ipv4_header.flags.dont_fragment = (ntohs(ip->ip_off) & IP_DF) >> 14;
    ipv4_header.flags.more_fragments = (ntohs(ip->ip_off) & IP_MF) >> 13;
    get_flags_desc(ipv4_header.flags_desc, ntohs(ip->ip_off), verbose);

    // Time to live
    ipv4_header.time_to_live = ip->ip_ttl;

    // Protocol
    ipv4_header.protocol = ip->ip_p;
    ipv4_get_protocol_name(ipv4_header.protocol, ipv4_header.protocol_name, verbose);

    // Checksum
    ipv4_header.checksum = ntohs(ip->ip_sum);
    ip->ip_sum = 0;

    // Calculate the checksum
    uint16_t calculated_checksum = ntohs(calculate_checksum((uint16_t*)ip, ip->ip_hl * 4));
    ipv4_header.checksum_correct = (ipv4_header.checksum == calculated_checksum);
    
    // Raw source and destination addresses
    memcpy(ipv4_header.raw_source_address, &ip->ip_src, 4);
    memcpy(ipv4_header.raw_destination_address, &ip->ip_dst, 4);

    // Source and destination IP
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->ip_src, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip->ip_dst, dst_ip, INET_ADDRSTRLEN);
    ipv4_header.source_ipv4 = src_ip;
    ipv4_header.destination_ipv4 = dst_ip;

    return ipv4_header;
}

/**
 * @brief 
 * 
 * the "pseudo-header" for IPv4 : https://datatracker.ietf.org/doc/html/rfc768
 * 
 *       0      7 8     15 16    23 24    31
 *       +--------+--------+--------+--------+
 *       |          source address           |
 *       +--------+--------+--------+--------+
 *       |        destination address        |
 *       +--------+--------+--------+--------+
 *       |  zero  |protocol| UDP/TCP length  |
 *       +--------+--------+--------+--------+
 * 
 * @param packet 
 * @param packet_len 
 * @param src_ip 
 * @param dst_ip 
 * @param net_protocol 
 * @param combined_len 
 * @return uint16_t* 
 */
uint16_t* 
build_ipv4_pseudo_header_and_packet(uint8_t *packet, int packet_length, uint8_t *src_add, uint8_t *dst_add, uint8_t net_protocol, int *combined_len)
{
    uint8_t pseudo_header[12];
    memcpy(pseudo_header, src_add, 4);
    memcpy(pseudo_header + 4, dst_add, 4);
    pseudo_header[8] = 0;
    pseudo_header[9] = net_protocol;
    pseudo_header[10] = (packet_length >> 8) & 0xFF;
    pseudo_header[11] = packet_length & 0xFF;

    // Combine the pseudo-header and the packet
    *combined_len = 12 + packet_length;
    uint16_t *combined = (uint16_t*)malloc(*combined_len + (*combined_len % 2));
    memcpy(combined, pseudo_header, 12);
    memcpy((uint8_t*)combined + 12, packet, packet_length);

    // Make sure the combined length is even, add padding if necessary
    if (*combined_len % 2 == 1) {
        ((uint8_t*)combined)[*combined_len] = 0;
        (*combined_len)++;
    }

    return combined;
}


/**
 * @brief Get the description string for the flags in the ipv4 header
 * 
 * @param flags_desc 
 * @param ip_off 
 * @param verbose 
 */
void 
get_flags_desc(std::string& flags_desc, uint16_t ip_off, bool verbose)
{
    if (verbose)
    {
        if (ip_off & IP_RF)
        {
            flags_desc += "RF (Reserved)";
        }
        if (ip_off & IP_DF)
        {
            flags_desc += "DF (Don't Fragment)";
        }
        if (ip_off & IP_MF)
        {
            flags_desc += "MF (More Fragments)";
        }
    } else {
        if (ip_off & IP_RF)
        {
            flags_desc = "RF";
        }
        if (ip_off & IP_DF)
        {
            flags_desc = "DF";
        }
        if (ip_off & IP_MF)
        {
            flags_desc = "MF";
        }
    }
}

/**
 * @brief Get the protocol name in a given string depending
 * on the verbose mode
 * 
 * @param protocol 
 * @param protocol_name 
 * @param verbose 
 */
void 
ipv4_get_protocol_name(uint8_t protocol, std::string& protocol_name, bool verbose)
{
    // https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    switch (protocol)
    {
        case IPPROTO_ICMP:
            if (verbose){
                protocol_name = "ICMP (Internet Control Message Protocol)";
            } else {
                protocol_name = "ICMP";
            }
            break;
        case IPPROTO_ICMPV6:
            if (verbose){
                protocol_name = "ICMPv6 (Internet Control Message Protocol version 6)";
            } else {
                protocol_name = "ICMPv6";
            }
            break;
        case IPPROTO_IGMP:
            if (verbose){
                protocol_name = "IGMP (Internet Group Management Protocol)";
            } else {
                protocol_name = "IGMP";
            }
            break;
        case IPPROTO_TCP:
            if (verbose){
                protocol_name = "TCP (Transmission Control Protocol)";
            } else {
                protocol_name = "TCP";
            }
            break;
        case IPPROTO_UDP:
            if (verbose){
                protocol_name = "UDP (User Datagram Protocol)";
            } else {
                protocol_name = "UDP";
            }
            break;
        case IPPROTO_IPV6:
            if (verbose){
                protocol_name = "IPv6 Encapsulated";
            } else {
                protocol_name = "IPv6 Encap";
            }
            break;
    }
}