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
    icmp_p.checksum_valid = (calculated_checksum == icmp_p.checksum);

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
        icmp_p.data = malloc(packet_length - ICMP_MINLEN + 1);
        if (icmp_p.data == NULL){
            perror("malloc");
            exit(EXIT_FAILURE);
        }

        snprintf((char *)icmp_p.data, packet_length - ICMP_MINLEN + 1, "%s", icmp->icmp_data);
    } else {
        icmp_p.data = NULL;
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
get_icmp_code_desc(uint8_t type, uint8_t code, char* desc, bool verbose)
{
    switch(type){
        case ICMP_ECHO:
        case ICMP_ECHOREPLY:
            // No code for echo request and reply
            if (verbose){
                snprintf(desc, ICMP_CODE_DESC_SIZE, "No Code (%d)", code);
            } else {
                snprintf(desc, ICMP_CODE_DESC_SIZE, "0");
            }
            break;
        case ICMP_UNREACH:
            switch(code) {
                // https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes-3
                case ICMP_UNREACH_NET:
                    if (verbose){
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "Code: Network Unreachable (%d)", code);
                    } else {
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "bad net");
                    }
                    break;
                case ICMP_UNREACH_HOST:
                    if (verbose){
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "Code: Host Unreachable (%d)", code);
                    } else {
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "bad host");
                    }
                    break;
                case ICMP_UNREACH_PROTOCOL:
                    if (verbose){
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "Code: Protocol Unreachable (%d)", code);
                    } else {
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "bad protocol");
                    }
                    break;
                case ICMP_UNREACH_PORT:
                    if (verbose){
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "Code: Port Unreachable (%d)", code);
                    } else {
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "bad port");
                    }
                    break;
                case ICMP_UNREACH_NEEDFRAG:
                    if (verbose){
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "Code: Fragmentation Needed and Don't Fragment was Set (%d)", code);
                    } else {
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "IP_DF caused drop");
                    }
                    break;
                case ICMP_UNREACH_SRCFAIL:
                    if (verbose){
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "Code: Source Route Failed (%d)", code);
                    } else {
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "src route failed");
                    }
                    break;
                case ICMP_UNREACH_NET_UNKNOWN:
                    if (verbose){
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "Code: Destination Network Unknown (%d)", code);
                    } else {
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "unknown net");
                    }
                    break;
                case ICMP_UNREACH_HOST_UNKNOWN:
                    if (verbose){
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "Code: Destination Host Unknown (%d)", code);
                    } else {
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "unknown host");
                    }
                    break;
                case ICMP_UNREACH_ISOLATED:
                    if (verbose){
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "Code: Source Host Isolated (%d)", code);
                    } else {
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "src host isolated");
                    }
                    break;
                case ICMP_UNREACH_NET_PROHIB:
                    if (verbose){
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "Code: Communication with Destination Network is Administratively Prohibited (%d)", code);
                    } else {
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "prohibited access");
                    }
                    break;
                case ICMP_UNREACH_HOST_PROHIB:
                    if (verbose){
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "Code: Communication with Destination Host is Administratively Prohibited (%d)", code);
                    } else {
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "ditto");
                    }
                    break;
                case ICMP_UNREACH_TOSNET:
                    if (verbose){
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "Code: Network Unreachable for Type of Service (%d)", code);
                    } else {
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "bad ToS for net");
                    }
                    break;
                case ICMP_UNREACH_TOSHOST:
                    if (verbose){
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "Code: Host Unreachable for Type of Service (%d)", code);
                    } else {
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "bad ToS for host");
                    }
                    break;
                case ICMP_UNREACH_FILTER_PROHIB:
                    if (verbose){
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "Code: Communication Administratively Prohibited (%d)", code);
                    } else {
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "admin prohib");
                    }
                    break;
                case ICMP_UNREACH_HOST_PRECEDENCE:
                    if (verbose){
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "Code: Host Precedence Violation (%d)", code);
                    } else {
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "host prec vio.");
                    }
                    break;
                case ICMP_UNREACH_PRECEDENCE_CUTOFF:
                    if (verbose){
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "Code: Precedence cutoff in effect (%d)", code);
                    } else {
                        snprintf(desc, ICMP_CODE_DESC_SIZE, "prec cutoff");
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
get_icmp_type_desc(uint8_t type, char *desc, bool verbose)
{
    switch(type){
        case ICMP_ECHOREPLY:
            if (verbose){
                snprintf(desc, ICMP_TYPE_DESC_SIZE, "Type: Echo Reply (%d)", type);
            } else {
                snprintf(desc, ICMP_TYPE_DESC_SIZE, "Echo Reply");
            }
            break;
        case ICMP_UNREACH:
            if (verbose){
                snprintf(desc, ICMP_TYPE_DESC_SIZE, "Type: Destination Unreachable (%d)", type);
            } else {
                snprintf(desc, ICMP_TYPE_DESC_SIZE, "Destination Unreachable");
            }
            break;
        case ICMP_ECHO:
            if (verbose){
                snprintf(desc, ICMP_TYPE_DESC_SIZE, "Type: Echo Request (%d)", type);
            } else {
                snprintf(desc, ICMP_TYPE_DESC_SIZE, "Echo Request");
            }
            break;
        default:
            if (verbose){
                snprintf(desc, ICMP_TYPE_DESC_SIZE, "Type: Unknown (%d)", type);
            } else {
                snprintf(desc, ICMP_TYPE_DESC_SIZE, "Unknown");
            }
            break;
    }
}

