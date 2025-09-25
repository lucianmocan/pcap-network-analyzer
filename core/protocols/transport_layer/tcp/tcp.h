#ifndef TCP_H
#define TCP_H

#include <netinet/tcp.h>
#include <string>

#include "ipv4.h"
#include "ipv6.h"

#ifdef __linux
#define IPPROTO_IPV4 IPPROTO_IPIP
#endif

/*
  TCP Header Format : https://datatracker.ietf.org/doc/html/rfc793#section-3.1

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

typedef struct my_tcp_header {
    uint16_t source_port;
    uint16_t destination_port;

    uint32_t sequence_number;
    uint32_t acknowledgment_number;

    uint8_t data_offset : 4;
    uint8_t reserved : 6;
    uint8_t flags: 6;
    std::string tcp_flags_desc;

    uint16_t window;
    uint16_t checksum;
    uint16_t calculated_checksum;
    bool checksum_correct;

    uint16_t urgent_pointer;

    uint8_t *options;
    std::string tcp_options_desc;

} my_tcp_header_t;

my_tcp_header_t parse_tcp_header(const uint8_t *packet, uint8_t *src_add, uint8_t *dst_add, uint8_t net_protocol, bool verbose);


// helpers
void get_tcp_options_desc(uint8_t *options, uint8_t options_length, std::string& desc, bool verbose);
void get_tcp_flags_desc(uint8_t flags, std::string& desc, bool verbose);

#endif