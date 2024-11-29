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
    const struct ip *ip;
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


    return (my_ipv4_header_t){0};
}