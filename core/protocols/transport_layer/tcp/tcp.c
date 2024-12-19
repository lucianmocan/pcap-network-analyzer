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
    uint16_t *combined;
    if (net_protocol == IPPROTO_IPV4){
        combined = build_ipv4_pseudo_header_and_packet((uint8_t*)tcp, tcp_header.data_offset * 4, src_add, dst_add, IPPROTO_TCP, &combined_len);
    } else if (net_protocol == IPPROTO_IPV6) {
        combined = build_ipv6_pseudo_header_and_packet((uint8_t*)tcp, tcp_header.data_offset * 4, src_add, dst_add, IPPROTO_TCP, &combined_len);
    }

    // Calculate the checksum
    uint16_t calculated_checksum = ntohs(calculate_checksum(combined, combined_len));

    // Check if checksum match
    tcp_header.checksum_correct = (calculated_checksum == tcp_header.checksum);

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
        tcp_header.options = malloc((tcp_header.data_offset - 5) * 4);
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
get_tcp_options_desc(uint8_t *options, uint8_t options_length, char *desc, bool verbose)
{
    if (verbose)
    {
        int write_ptr = 0;
        for (int i = 0; i < options_length; i++){
            if (options[i] == TCPOPT_EOL){
                snprintf(desc + write_ptr, MY_TCP_OPTIONS_DESC_SIZE - write_ptr, "End of option list ");
                write_ptr += strlen("End of option list ");
            } 
            if (options[i] == TCPOPT_NOP){
                snprintf(desc + write_ptr, MY_TCP_OPTIONS_DESC_SIZE - write_ptr, "No-Operation ");
                write_ptr += strlen("No-Operation ");
            }
            if (options[i] == TCPOPT_MAXSEG){
                snprintf(desc + write_ptr, MY_TCP_OPTIONS_DESC_SIZE - write_ptr, "Maximum Segment Size ");
                write_ptr += strlen("Maximum Segment Size ");
                i++;
                int length = (*(uint8_t*)(options + i));
                snprintf(desc + write_ptr, MY_TCP_OPTIONS_DESC_SIZE - write_ptr, "(%d) ", ntohs(*(uint16_t*)(options + length / 2)));
                write_ptr += strlen("(65535) ");
                i+= length / 2;
            } else {
                snprintf(desc + write_ptr, MY_TCP_OPTIONS_DESC_SIZE - write_ptr, "Unknown option ");
                write_ptr += strlen("Unknown option ");
                i++;
                int length = (*(uint8_t*)(options + i));
                i+= length / 2;
            }
        }
    } else {
        int write_ptr = 0;
        for (int i = 0; i < options_length; i++){
            if (options[i] == TCPOPT_EOL){
                snprintf(desc + write_ptr, MY_TCP_OPTIONS_DESC_SIZE - write_ptr, "eopl ");
                write_ptr += strlen("eopl ");
            }
            if (options[i] == TCPOPT_NOP){
                snprintf(desc + write_ptr, MY_TCP_OPTIONS_DESC_SIZE - write_ptr, "no-op ");
                write_ptr += strlen("no-op ");
            }
            if (options[i] == TCPOPT_MAXSEG){
                snprintf(desc + write_ptr, MY_TCP_OPTIONS_DESC_SIZE - write_ptr, "mss ");
                write_ptr += strlen("mss ");
                i++;
                int length = (*(uint8_t*)(options + i));
                snprintf(desc + write_ptr, MY_TCP_OPTIONS_DESC_SIZE - write_ptr, "(%d) ", ntohs(*(uint16_t*)(options + length / 2)));
                write_ptr += strlen("(65535) ");
                i+= length / 2;
            } else {
                snprintf(desc + write_ptr, MY_TCP_OPTIONS_DESC_SIZE - write_ptr, "? op ");
                write_ptr += strlen("? op ");
                i++;
                int length = (*(uint8_t*)(options + i));
                i+= length / 2;
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
get_tcp_flags_desc(uint8_t flags, char *desc, bool verbose)
{
    if (verbose)
    {   
        int write_ptr = strlen("Flags: ");
        memcpy(desc, "Flags: ", write_ptr);
        if (flags & TH_FIN){
            snprintf(desc + write_ptr, MY_TCP_FLAGS_DESC_SIZE - write_ptr, "FIN ");
            write_ptr += strlen("FIN ");
        }
        if (flags & TH_SYN){
            snprintf(desc + write_ptr, MY_TCP_FLAGS_DESC_SIZE - write_ptr, "SYN ");
            write_ptr += strlen("SYN ");
        }
        if (flags & TH_RST){
            snprintf(desc + write_ptr, MY_TCP_FLAGS_DESC_SIZE - write_ptr, "RST ");
            write_ptr += strlen("RST ");
        }
        if (flags & TH_PUSH){
            snprintf(desc + write_ptr, MY_TCP_FLAGS_DESC_SIZE - write_ptr, "PSH ");
            write_ptr += strlen("PSH ");
        }
        if (flags & TH_ACK){
            snprintf(desc + write_ptr, MY_TCP_FLAGS_DESC_SIZE - write_ptr, "ACK ");
            write_ptr += strlen("ACK ");
        }
        if (flags & TH_URG){
            snprintf(desc + write_ptr, MY_TCP_FLAGS_DESC_SIZE - write_ptr, "URG ");
            write_ptr += strlen("URG ");
        }
        if (write_ptr == strlen("Flags: ")){
            snprintf(desc + write_ptr, MY_TCP_FLAGS_DESC_SIZE - write_ptr, "None / Unknown ");
            write_ptr += strlen("None / Unknown ");
        }
        snprintf(desc + write_ptr, MY_TCP_FLAGS_DESC_SIZE - write_ptr, "(0x%x)", flags);
    } else {
        int write_ptr = 0;
        if (flags & TH_FIN){
            snprintf(desc + write_ptr, MY_TCP_FLAGS_DESC_SIZE - write_ptr, "FIN ");
            write_ptr += strlen("FIN ");
        }
        if (flags & TH_SYN){
            snprintf(desc + write_ptr, MY_TCP_FLAGS_DESC_SIZE - write_ptr, "SYN ");
            write_ptr += strlen("SYN ");
        }
        if (flags & TH_RST){
            snprintf(desc + write_ptr, MY_TCP_FLAGS_DESC_SIZE - write_ptr, "RST ");
            write_ptr += strlen("RST ");
        }
        if (flags & TH_PUSH){
            snprintf(desc + write_ptr, MY_TCP_FLAGS_DESC_SIZE - write_ptr, "PSH ");
            write_ptr += strlen("PSH ");
        }
        if (flags & TH_ACK){
            snprintf(desc + write_ptr, MY_TCP_FLAGS_DESC_SIZE - write_ptr, "ACK ");
            write_ptr += strlen("ACK ");
        }
        if (flags & TH_URG){
            snprintf(desc + write_ptr, MY_TCP_FLAGS_DESC_SIZE - write_ptr, "URG ");
            write_ptr += strlen("URG ");
        }
        if (write_ptr == 0){
            snprintf(desc + write_ptr, MY_TCP_FLAGS_DESC_SIZE - write_ptr, "none/? ");
            write_ptr += strlen("none/? ");
        }
        snprintf(desc + write_ptr, MY_TCP_FLAGS_DESC_SIZE - write_ptr, "(0x%x)", flags);
    }
}

