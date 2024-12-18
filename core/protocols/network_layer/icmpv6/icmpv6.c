#include "icmpv6.h"

my_icmpv6_t parse_icmpv6(const uint8_t *packet, size_t packet_length, uint8_t *src_ipv6, uint8_t *dst_ipv6, bool verbose) {
    my_icmpv6_t my_icmpv6;

    struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)packet;

    my_icmpv6.type = icmp6_hdr->icmp6_type;
    get_icmpv6_type_desc(my_icmpv6.type, my_icmpv6.icmpv6_type_desc, verbose);

    my_icmpv6.code = icmp6_hdr->icmp6_code;
    get_icmpv6_code_desc(my_icmpv6.type, my_icmpv6.code, my_icmpv6.icmpv6_code_desc, verbose);

    my_icmpv6.checksum = ntohs(icmp6_hdr->icmp6_cksum);
    icmp6_hdr->icmp6_cksum = 0;
    // "The Next Header field in the pseudo-header for ICMP contains the
    // value 58, which identifies the IPv6 version of ICMP."
    // https://datatracker.ietf.org/doc/html/rfc2460#section-8.1
    uint8_t next_header = 58;

    // Build the pseudo-header and packet
    int combined_len;
    uint16_t *combined = build_icmpv6_pseudo_header_and_packet((uint8_t*)icmp6_hdr, packet_length, src_ipv6, dst_ipv6, next_header, &combined_len);
    uint16_t calculated_checksum = ntohs(calculate_checksum(combined, combined_len));
    my_icmpv6.checksum_valid = (calculated_checksum == my_icmpv6.checksum);

    if (my_icmpv6.type == ICMP6_ECHO_REQUEST || my_icmpv6.type == ICMP6_ECHO_REPLY){
        my_icmpv6.identifier = ntohs(icmp6_hdr->icmp6_id);
        my_icmpv6.sequence_number = ntohs(icmp6_hdr->icmp6_seq);
    } else {
        my_icmpv6.identifier = 0;
        my_icmpv6.sequence_number = 0;
    }

    if (packet_length > MY_ICMPV6_MIN_LEN  && (my_icmpv6.type == ICMP6_ECHO_REQUEST || my_icmpv6.type == ICMP6_ECHO_REPLY)){
        my_icmpv6.payload = malloc(packet_length - MY_ICMPV6_MIN_LEN + 1);
        if (my_icmpv6.payload == NULL){
            perror("malloc");
            exit(EXIT_FAILURE);
        }

        snprintf((char *)my_icmpv6.payload, packet_length - MY_ICMPV6_MIN_LEN + 1, "%s", icmp6_hdr->icmp6_data8);
    } else {
        my_icmpv6.payload = NULL;
    }

    if (my_icmpv6.type == ICMP6_DST_UNREACH){
        // get the original ip header
        my_icmpv6.og_ipv6_header = parse_ipv6((uint8_t*)&icmp6_hdr->icmp6_data32[1], verbose);

        // as much as fits in the minimum IPv6 MTU
        my_icmpv6.payload = malloc(ICMPV6_PLD_MAXLEN * sizeof(uint8_t));
        if (my_icmpv6.payload == NULL){
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        memcpy(my_icmpv6.payload, &icmp6_hdr->icmp6_data32[1], ICMPV6_PLD_MAXLEN);
        if (my_icmpv6.og_ipv6_header.next_header == IPPROTO_TCP){
            // my_tcp_header_t tcp_header = parse_tcp(icmp6_hdr->icmp6_data8 + my_icmpv6.og_ipv6_header.header_length * 4, verbose);
        } else if (my_icmpv6.og_ipv6_header.next_header == IPPROTO_UDP){
            // my_udp_header_t udp_header = parse_udp(icmp6_hdr->icmp6_data8 + my_icmpv6.og_ipv6_header.header_length * 4, verbose);
        }
    }

    if (my_icmpv6.type == ND_NEIGHBOR_SOLICIT){
        // get the target address
        my_icmpv6.payload = malloc(INET6_ADDRSTRLEN * sizeof(uint8_t));
        if (my_icmpv6.payload == NULL){
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        if (inet_ntop(AF_INET6, &icmp6_hdr->icmp6_data32[1], (char*)my_icmpv6.payload, INET6_ADDRSTRLEN) == NULL){
            free(my_icmpv6.payload);
            perror("inet_ntop");
            exit(EXIT_FAILURE);
        }
        // TODO: get the options
    }

    return my_icmpv6;
}

/**
 * @brief Free the payload of the ICMPv6 packet
 * 
 * @param my_icmpv6 
 */
void
free_parse_icmpv6(my_icmpv6_t *my_icmpv6)
{
    if (my_icmpv6->payload != NULL){
        free(my_icmpv6->payload);
    }
}


/**
 * @brief Build the pseudo-header and combine it with the packet
 * https://datatracker.ietf.org/doc/html/rfc2460#section-8.1
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
uint16_t* build_icmpv6_pseudo_header_and_packet(uint8_t *packet, int packet_len, uint8_t *src_ip, uint8_t *dst_ip, uint8_t next_header, int *combined_len)
{   
    // Check sum is different from ICMP because ICMPv6 has to include the pseudo-header of IPv6
    // Create the pseudo-header
    uint8_t pseudo_header[40];
    memcpy(pseudo_header, src_ip, 16);
    memcpy(pseudo_header + 16, dst_ip, 16);
    pseudo_header[32] = (packet_len >> 24) & 0xFF;
    pseudo_header[33] = (packet_len >> 16) & 0xFF;
    pseudo_header[34] = (packet_len >> 8) & 0xFF;
    pseudo_header[35] = packet_len & 0xFF;
    pseudo_header[36] = 0;
    pseudo_header[37] = 0;
    pseudo_header[38] = 0;
    pseudo_header[39] = next_header;

    // Combine the pseudo-header and the packet
    *combined_len = 40 + packet_len;
    uint16_t *combined = (uint16_t*)malloc(*combined_len + (*combined_len % 2));
    memcpy(combined, pseudo_header, 40);
    memcpy((uint8_t*)combined + 40, packet, packet_len);

    // Make sure the combined length is even, add padding if necessary
    if (*combined_len % 2 == 1) {
        ((uint8_t*)combined)[*combined_len] = 0;
        (*combined_len)++;
    }

    return combined;
}

/**
 * @brief Get the icmpv6 code description in a given string
 * 
 * @param type 
 * @param code 
 * @param desc 
 * @param verbose 
 */
void
get_icmpv6_code_desc(uint8_t type, uint8_t code, char *desc, bool verbose) {
    switch(type){
        case ICMP6_DST_UNREACH:
        // https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-codes-2
            switch(code){
                case ICMP6_DST_UNREACH_NOROUTE:
                    if (verbose){
                        snprintf(desc, ICMPV6_CODE_DESC_SIZE, "Code: No Route to Destination (%d)", code);
                    } else {
                        snprintf(desc, ICMPV6_CODE_DESC_SIZE, "no route to dest");
                    }
                    break;
                case ICMP6_DST_UNREACH_ADMIN:
                    if (verbose){
                        snprintf(desc, ICMPV6_CODE_DESC_SIZE, "Code: Communication with Destination Administratively Prohibited (%d)", code);
                    } else {
                        snprintf(desc, ICMPV6_CODE_DESC_SIZE, "admin prohibited");
                    }
                    break;
                case ICMP6_DST_UNREACH_BEYONDSCOPE:
                    if (verbose){
                        snprintf(desc, ICMPV6_CODE_DESC_SIZE, "Code: Beyond Scope of Source Address (%d)", code);
                    } else {
                        snprintf(desc, ICMPV6_CODE_DESC_SIZE, "beyond scope of src addr");
                    }
                    break;
                case ICMP6_DST_UNREACH_ADDR:
                    if (verbose){
                        snprintf(desc, ICMPV6_CODE_DESC_SIZE, "Code: Address Unreachable (%d)", code);
                    } else {
                        snprintf(desc, ICMPV6_CODE_DESC_SIZE, "addr unreachable");
                    }
                    break;
                case ICMP6_DST_UNREACH_NOPORT:
                    if (verbose){
                        snprintf(desc, ICMPV6_CODE_DESC_SIZE, "Code: Port Unreachable (%d)", code);
                    } else {
                        snprintf(desc, ICMPV6_CODE_DESC_SIZE, "port unreachable");
                    }
                    break;
                default:
                    if (verbose){
                        snprintf(desc, ICMPV6_CODE_DESC_SIZE, "Code: Unknown (%d)", code);
                    } else {
                        snprintf(desc, ICMPV6_CODE_DESC_SIZE, "Unknown");
                    }
            }
            break;
        case ICMP6_ECHO_REQUEST:
        case ICMP6_ECHO_REPLY:
        case ND_NEIGHBOR_SOLICIT:
            if (verbose){
                snprintf(desc, ICMPV6_CODE_DESC_SIZE, "Code: (%d)", code);
            } else {
                snprintf(desc, ICMPV6_CODE_DESC_SIZE, "%d", code);
            }
            break;
        default:
            if (verbose){
                snprintf(desc, ICMPV6_CODE_DESC_SIZE, "Code: Unknown (%d)", code);
            } else {
                snprintf(desc, ICMPV6_CODE_DESC_SIZE, "%d", code);
            }
    }
}

/**
 * @brief Get the icmpv6 type description in a given string
 * 
 * @param type 
 * @param desc 
 * @param verbose 
 */
void 
get_icmpv6_type_desc(uint8_t type, char *desc, bool verbose)
{
    switch(type){
        case ICMP6_DST_UNREACH:
            if (verbose){
                snprintf(desc, ICMPV6_TYPE_DESC_SIZE, "Type: Destination Unreachable (%d)", type);
            } else {
                snprintf(desc, ICMPV6_TYPE_DESC_SIZE, "dest unreachable");
            }
            break;
        case ICMP6_ECHO_REQUEST:
            if (verbose){
                snprintf(desc, ICMPV6_TYPE_DESC_SIZE, "Type: Echo Request (%d)", type);
            } else {
                snprintf(desc, ICMPV6_TYPE_DESC_SIZE, "Echo Request");
            }
            break;
        case ICMP6_ECHO_REPLY:
            if (verbose){
                snprintf(desc, ICMPV6_TYPE_DESC_SIZE, "Type: Echo Reply (%d)", type);
            } else {
                snprintf(desc, ICMPV6_TYPE_DESC_SIZE, "Echo Reply");
            }
            break;
        case ND_NEIGHBOR_SOLICIT:
            if (verbose){
                snprintf(desc, ICMPV6_TYPE_DESC_SIZE, "Type: Neighbor Solicitation (%d)", type);
            } else {
                snprintf(desc, ICMPV6_TYPE_DESC_SIZE, "Neighbor Solicitation");
            }
            break;
        default:
            if (verbose){
                snprintf(desc, ICMPV6_TYPE_DESC_SIZE, "Type: Unknown (%d)", type);
            } else {
                snprintf(desc, ICMPV6_TYPE_DESC_SIZE, "Unknown");
            }
            break;
    }
}