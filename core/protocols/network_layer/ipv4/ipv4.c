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
parse_ipv4(const u_char *packet, bool verbose)
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

    // Flags
    ipv4_header.flags.reserved = (ip->ip_off & IP_RF) >> 15;
    ipv4_header.flags.dont_fragment = (ip->ip_off & IP_DF) >> 14;
    ipv4_header.flags.more_fragments = (ip->ip_off & IP_MF) >> 13;
    get_flags_desc(ipv4_header.flags_desc, ip->ip_off, verbose);

    // Fragment offset
    ipv4_header.fragment_offset = ntohs(ip->ip_off) & IP_OFFMASK;

    // Time to live
    ipv4_header.time_to_live = ip->ip_ttl;

    // Protocol
    ipv4_header.protocol = ip->ip_p;
    get_protocol_name(ipv4_header.protocol, ipv4_header.protocol_name, verbose);

    // Checksum
    ipv4_header.checksum = ip->ip_sum;
    ip->ip_sum = 0;

    // Calculate the checksum
    uint16_t calculated_checksum = calculate_checksum((uint16_t *)ip, ip->ip_hl * 4);
    ipv4_header.checksum_correct = (ipv4_header.checksum == calculated_checksum);
    
    // Source and destination IP
    snprintf(ipv4_header.source_ipv4, 16, "%s", inet_ntoa(ip->ip_src));
    snprintf(ipv4_header.destination_ipv4, 16, "%s", inet_ntoa(ip->ip_dst));

    return (my_ipv4_header_t){0};
}

/**
 * @brief Calculate the checksum of an IPv4 packet
 * according to RFC1071 (it is done in big-endian)
 * 
 * @param packet 
 * @param length 
 * @return uint16_t 
 */
uint32_t 
calculate_checksum(uint16_t *packet, int count)
{
    // https://www.rfc-editor.org/rfc/rfc1071
    // Algorithm found on [Page 6] 4.1 "C"
    uint32_t sum = 0;
    while (count > 1) {
        sum +=  *(unsigned short*)packet++;
        count -= 2;
    }

    // Add left-over byte, if any
    if (count > 0) {
        sum += *(u_char *)packet;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;
}


/**
 * @brief Get the description string for the flags in the ipv4 header
 * 
 * @param flags_desc 
 * @param ip_off 
 * @param verbose 
 */
void 
get_flags_desc(char flags_desc[32], uint16_t ip_off, bool verbose)
{
    if (verbose)
    {
        if (ip_off & IP_RF)
        {
            snprintf(flags_desc, 32, "RF (Reserved)");
        }
        if (ip_off & IP_DF)
        {
            snprintf(flags_desc, 32, "DF (Don't Fragment)");
        }
        if (ip_off & IP_MF)
        {
            snprintf(flags_desc, 32, "MF (More Fragments)");
        }
    } else {
        if (ip_off & IP_RF)
        {
            snprintf(flags_desc, 32, "RF");
        }
        if (ip_off & IP_DF)
        {
            snprintf(flags_desc, 32, "DF");
        }
        if (ip_off & IP_MF)
        {
            snprintf(flags_desc, 32, "MF");
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
get_protocol_name(uint8_t protocol, char protocol_name[16], bool verbose)
{
    // https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    switch (protocol)
    {
        case IPPROTO_ICMP:
            if (verbose){
                snprintf(protocol_name, 16, "ICMP (Internet Control Message Protocol)");
            } else {
                snprintf(protocol_name, 16, "ICMP");
            }
            break;
        case IPPROTO_IGMP:
            if (verbose){
                snprintf(protocol_name, 16, "IGMP (Internet Group Management Protocol)");
            } else {
                snprintf(protocol_name, 16, "IGMP");
            }
            break;
        case IPPROTO_TCP:
            if (verbose){
                snprintf(protocol_name, 16, "TCP (Transmission Control Protocol)");
            } else {
                snprintf(protocol_name, 16, "TCP");
            }
            break;
        case IPPROTO_UDP:
            if (verbose){
                snprintf(protocol_name, 16, "UDP (User Datagram Protocol)");
            } else {
                snprintf(protocol_name, 16, "UDP");
            }
            break;
        case IPPROTO_IPV6:
            if (verbose){
                snprintf(protocol_name, 16, "IPv6 Encapsulated");
            } else {
                snprintf(protocol_name, 16, "IPv6 Encap");
            }
            break;
    }
}