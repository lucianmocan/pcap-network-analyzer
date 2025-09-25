#include "tcp.h"

/**
 * @brief Parse TCP header, check if the checksum is correct
 * 
 * @param packet 
 * @param verbose 
 * @return my_tcp_header_t 
 */
my_tcp_header_t 
parse_tcp_header(const uint8_t *packet, uint8_t *src_add, uint8_t *dst_add, uint8_t net_protocol, bool verbose)
{
    my_tcp_header_t tcp_header;

    struct tcphdr *tcp = (struct tcphdr *)packet;
    tcp_header.source_port = ntohs(tcp->th_sport);
    tcp_header.destination_port = ntohs(tcp->th_dport);
    tcp_header.sequence_number = ntohl(tcp->th_seq);
    tcp_header.acknowledgment_number = ntohl(tcp->th_ack);

    tcp_header.data_offset = tcp->th_off;
    tcp_header.reserved = tcp->th_x2;
    tcp_header.flags = tcp->th_flags;
    get_tcp_flags_desc(tcp_header.flags, tcp_header.tcp_flags_desc, verbose);

    tcp_header.window = ntohs(tcp->th_win);

    tcp_header.checksum = ntohs(tcp->th_sum);
    tcp->th_sum = 0;

    // Build the pseudo-header and packet
    int combined_len;
    uint16_t *combined = NULL;
    if (net_protocol == IPPROTO_IPV4){
        combined = build_ipv4_pseudo_header_and_packet((uint8_t*)tcp, tcp_header.data_offset * 4, src_add, dst_add, IPPROTO_TCP, &combined_len);
    } else if (net_protocol == IPPROTO_IPV6) {
        combined = build_ipv6_pseudo_header_and_packet((uint8_t*)tcp, tcp_header.data_offset * 4, src_add, dst_add, IPPROTO_TCP, &combined_len);
    }

    // Calculate the checksum
    uint16_t calculated_checksum = ntohs(calculate_checksum(combined, combined_len));
    tcp_header.calculated_checksum = calculated_checksum;
    free(combined);

    // Check if checksum match
    tcp_header.checksum_correct = (calculated_checksum == tcp_header.checksum || tcp_header.calculated_checksum == 0x0000 || tcp_header.calculated_checksum == 0xFFFF);

    tcp_header.urgent_pointer = ntohs(tcp->th_urp);

    // Options - only 3 options are supported
    // https://datatracker.ietf.org/doc/html/rfc793#section-3.1 :
    // Currently defined options include (kind indicated in octal):
    //   Kind     Length    Meaning
    //   ----     ------    -------
    //    0         -       End of option list.
    //    1         -       No-Operation.
    //    2         4       Maximum Segment Size.
    if (tcp_header.data_offset > 5){
        tcp_header.options = (uint8_t *)malloc((tcp_header.data_offset - 5) * 4);
        if (tcp_header.options == NULL){
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        memcpy(tcp_header.options, packet + 20, (tcp_header.data_offset - 5) * 4);
        get_tcp_options_desc(tcp_header.options, (tcp_header.data_offset - 5) * 4, tcp_header.tcp_options_desc, verbose);
    } else {
        tcp_header.options = NULL;
    }

    // the main parser should deal with the payload
    return tcp_header;
}

/**
 * @brief Get the tcp options description in a string
 * supports only the 3 start options described in https://datatracker.ietf.org/doc/html/rfc793#section-3.1
 * sketchy... because it doesn't support all the options
 * @param options 
 * @param options_length 
 * @param desc 
 * @param verbose 
 */
void
get_tcp_options_desc(uint8_t *options, uint8_t options_length, std::string& desc, bool verbose)
{   
    if (verbose)
    {
        for (int i = 0; i < options_length; i++){
            if (options[i] == TCPOPT_EOL){
                desc += "| End of option list ";
            } else
            if (options[i] == TCPOPT_NOP){
                desc += "| No-Operation ";
            } else
            if (options[i] == TCPOPT_MAXSEG){
                desc += "| Maximum Segment Size ";
                int full_length = (*(uint8_t*)(options + i + 1));
                desc += "(" + std::to_string(ntohs(*(uint16_t*)(options + i + full_length - 2))) + ") ";
                i+= full_length - 1;
            } else 
            if (options[i] != TCPOPT_EOL && options[i] != TCPOPT_NOP && options[i] != TCPOPT_MAXSEG){
                desc += "| Unknown option ";
                int full_length = (*(uint8_t*)(options + i + 1));
                i+= full_length - 1;
            }
        }
    } else {
        for (int i = 0; i < options_length; i++){
            if (options[i] == TCPOPT_EOL){
                desc += "| eopl ";
            } else
            if (options[i] == TCPOPT_NOP){
                desc += "| no-op ";
            } else
            if (options[i] == TCPOPT_MAXSEG){
                desc += "| mss ";
                int full_length = (*(uint8_t*)(options + i + 1));
                desc += "(" + std::to_string(ntohs(*(uint16_t*)(options + i + full_length - 2))) + ") ";
                i+= full_length - 1;
            } else
            if (options[i] != TCPOPT_EOL && options[i] != TCPOPT_NOP && options[i] != TCPOPT_MAXSEG){
                int full_length = (*(uint8_t*)(options + i + 1));
                desc += "| ? op ";
                i+= full_length - 1;
            }
        }
    }
}

/**
 * @brief Get the tcp flags description in a string
 * 
 * @param flags 
 * @param desc 
 * @param verbose 
 */
void 
get_tcp_flags_desc(uint8_t flags, std::string& desc, bool verbose)
{
    if (verbose)
    {   
        desc += "Flags: ";
        if (flags & TH_FIN){
            desc += "FIN ";
        }
        if (flags & TH_SYN){
            desc += "SYN ";
        }
        if (flags & TH_RST){
            desc += "RST ";
        }
        if (flags & TH_PUSH){
            desc += "PSH ";
        }
        if (flags & TH_ACK){
            desc += "ACK ";
        }
        if (flags & TH_URG){
            desc += "URG ";
        }
        if (desc == "Flags: "){
            desc += "None / Unknown ";
        }
        desc += "(0x" + std::to_string(flags) + ")";
    } else {
        if (flags & TH_FIN){
            desc += "FIN ";
        }
        if (flags & TH_SYN){
            desc += "SYN ";
        }
        if (flags & TH_RST){
            desc += "RST ";
        }
        if (flags & TH_PUSH){
            desc += "PSH ";
        }
        if (flags & TH_ACK){
            desc += "ACK ";
        }
        if (flags & TH_URG){
            desc += "URG ";
        }
        if (desc.empty()){
            desc += "none/? ";
        }
        desc += "(0x" + std::to_string(flags) + ")";
    }
}

