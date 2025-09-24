#include "icmp.h"

/**
 * @brief Parse an ICMP packet and return a my_icmp_t struct
 * containing the parsed data.
 * ! needs packet_length to recalculate checksum
 * @param packet 
 * @param verbose 
 * @return my_icmp_t 
 */
my_icmp_t 
parse_icmp(const uint8_t *packet, size_t packet_length, const bool verbose)
{   
    my_icmp_t icmp_p;

    struct icmp *icmp = (struct icmp *)packet;

    // get the type along with the description
    icmp_p.type = icmp->icmp_type;
    get_icmp_type_desc(icmp_p.type, icmp_p.icmp_type_desc, verbose);

    // get the code along with the description
    icmp_p.code = icmp->icmp_code;
    get_icmp_code_desc(icmp_p.type, icmp_p.code, icmp_p.icmp_code_desc, verbose);

    // get the checksum
    icmp_p.checksum = ntohs(icmp->icmp_cksum);
    // set checksum to 0 for recalculation
    icmp->icmp_cksum = 0;

    // recalculate the checksum
    uint16_t calculated_checksum = ntohs(calculate_checksum((uint16_t *)icmp, packet_length));
    icmp_p.calculated_checksum = calculated_checksum;
    icmp_p.checksum_valid = (calculated_checksum == icmp_p.checksum || icmp_p.calculated_checksum == 0x0000 || icmp_p.calculated_checksum == 0xFFFF);

    // destination unreachable doesn't have these fields (unused)
    if (icmp_p.type == ICMP_ECHO || icmp_p.type == ICMP_ECHOREPLY){
        // get the identifier and sequence number
        icmp_p.identifier = ntohs(icmp->icmp_id);
        icmp_p.sequence_number = ntohs(icmp->icmp_seq);
    } else {
        icmp_p.identifier = 0;
        icmp_p.sequence_number = 0;
    }

    // if there's more than the header, then copy the data
    if (packet_length > ICMP_MINLEN && (icmp_p.type == ICMP_ECHO || icmp_p.type == ICMP_ECHOREPLY)){
        icmp_p.payload = (uint8_t *)malloc(packet_length - ICMP_MINLEN + 1);
        if (icmp_p.payload == NULL){
            perror("malloc");
            exit(EXIT_FAILURE);
        }

        memcpy(icmp_p.payload, icmp->icmp_data, packet_length - ICMP_MINLEN);
    } else if (icmp_p.type == ICMP_UNREACH){
        // get the original ip header
        icmp_p.og_ip_header = parse_ipv4(packet + ICMP_MINLEN, verbose);
        // 64 bits
        icmp_p.payload = (uint8_t *)malloc(8 * sizeof(uint8_t));
        if (icmp_p.payload == NULL){
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        memcpy(icmp_p.payload, packet + ICMP_MINLEN + icmp_p.og_ip_header.header_length * 4, 8);
        if (icmp_p.og_ip_header.protocol == IPPROTO_TCP){
            // my_tcp_header_t tcp_header = parse_tcp(packet + ICMP_MINLEN + icmp_p.original_ip_header.header_length * 4, verbose);
        } else if (icmp_p.og_ip_header.protocol == IPPROTO_UDP){
            // my_udp_header_t udp_header = parse_udp(packet + ICMP_MINLEN + icmp_p.original_ip_header.header_length * 4, verbose);
        }
    } else {
        icmp_p.payload = NULL;
    }

    return icmp_p;
}

/**
 * @brief Get the icmp code description based on the type and code
 * and return it in a string
 * 
 * @param type 
 * @param code 
 * @param desc 
 * @param verbose 
 */
void
get_icmp_code_desc(uint8_t type, uint8_t code, std::string& desc, bool verbose)
{
    switch(type){
        case ICMP_ECHO:
        case ICMP_ECHOREPLY:
            // No code for echo request and reply
            if (verbose){
                desc = "No Code (" + std::to_string(code) + ")";
            } else {
                desc = "0";
            }
            break;
        case ICMP_UNREACH:
            switch(code) {
                // https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes-3
                case ICMP_UNREACH_NET:
                    if (verbose){
                        desc = "Code: Network Unreachable (" + std::to_string(code) + ")";
                    } else {
                        desc = "bad net";
                    }
                    break;
                case ICMP_UNREACH_HOST:
                    if (verbose){
                        desc = "Code: Host Unreachable (" + std::to_string(code) + ")";
                    } else {
                        desc = "bad host";
                    }
                    break;
                case ICMP_UNREACH_PROTOCOL:
                    if (verbose){
                        desc = "Code: Protocol Unreachable (" + std::to_string(code) + ")";
                    } else {
                        desc = "bad protocol";
                    }
                    break;
                case ICMP_UNREACH_PORT:
                    if (verbose){
                        desc = "Code: Port Unreachable (" + std::to_string(code) + ")";
                    } else {
                        desc = "bad port";
                    }
                    break;
                case ICMP_UNREACH_NEEDFRAG:
                    if (verbose){
                        desc = "Code: Fragmentation Needed and Don't Fragment was Set (" + std::to_string(code) + ")";
                    } else {
                        desc = "IP_DF caused drop";
                    }
                    break;
                case ICMP_UNREACH_SRCFAIL:
                    if (verbose){
                        desc = "Code: Source Route Failed (" + std::to_string(code) + ")";
                    } else {
                        desc = "src route failed";
                    }
                    break;
                case ICMP_UNREACH_NET_UNKNOWN:
                    if (verbose){
                        desc = "Code: Destination Network Unknown (" + std::to_string(code) + ")";
                    } else {
                        desc = "unknown net";
                    }
                    break;
                case ICMP_UNREACH_HOST_UNKNOWN:
                    if (verbose){
                        desc = "Code: Destination Host Unknown (" + std::to_string(code) + ")";
                    } else {
                        desc = "unknown host";
                    }
                    break;
                case ICMP_UNREACH_ISOLATED:
                    if (verbose){
                        desc = "Code: Source Host Isolated (" + std::to_string(code) + ")";
                    } else {
                        desc = "src host isolated";
                    }
                    break;
                case ICMP_UNREACH_NET_PROHIB:
                    if (verbose){
                        desc = "Code: Communication with Destination Network is Administratively Prohibited (" + std::to_string(code) + ")";
                    } else {
                        desc = "prohibited access";
                    }
                    break;
                case ICMP_UNREACH_HOST_PROHIB:
                    if (verbose){
                        desc = "Code: Communication with Destination Host is Administratively Prohibited (" + std::to_string(code) + ")";
                    } else {
                        desc = "ditto";
                    }
                    break;
                case ICMP_UNREACH_TOSNET:
                    if (verbose){
                        desc = "Code: Network Unreachable for Type of Service (" + std::to_string(code) + ")";
                    } else {
                        desc = "bad ToS for net";
                    }
                    break;
                case ICMP_UNREACH_TOSHOST:
                    if (verbose){
                        desc = "Code: Host Unreachable for Type of Service (" + std::to_string(code) + ")";
                    } else {
                        desc = "bad ToS for host";
                    }
                    break;
                case ICMP_UNREACH_FILTER_PROHIB:
                    if (verbose){
                        desc = "Code: Communication Administratively Prohibited (" + std::to_string(code) + ")";
                    } else {
                        desc = "admin prohib";
                    }
                    break;
                case ICMP_UNREACH_HOST_PRECEDENCE:
                    if (verbose){
                        desc = "Code: Host Precedence Violation (" + std::to_string(code) + ")";
                    } else {
                        desc = "host prec vio.";
                    }
                    break;
                case ICMP_UNREACH_PRECEDENCE_CUTOFF:
                    if (verbose){
                        desc = "Code: Precedence cutoff in effect (" + std::to_string(code) + ")";
                    } else {
                        desc = "prec cutoff";
                    }
                    break;
            }
    }
}


/**
 * @brief Get the icmp type description in a given string
 * 
 * @param type 
 * @param desc 
 * @param verbose 
 */
void
get_icmp_type_desc(uint8_t type, std::string& desc, bool verbose)
{
    switch(type){
        case ICMP_ECHOREPLY:
            if (verbose){
                desc = "Type: Echo Reply (" + std::to_string(type) + ")";
            } else {
                desc = "Echo Reply";
            }
            break;
        case ICMP_UNREACH:
            if (verbose){
                desc = "Type: Destination Unreachable (" + std::to_string(type) + ")";
            } else {
                desc = "Destination Unreachable";
            }
            break;
        case ICMP_ECHO:
            if (verbose){
                desc = "Type: Echo Request (" + std::to_string(type) + ")";
            } else {    
                desc = "Echo Request";
            }
            break;
        default:
            if (verbose){
                desc = "Type: Unknown (" + std::to_string(type) + ")";
            } else {
                desc = "Unknown";
            }
            break;
    }
}

