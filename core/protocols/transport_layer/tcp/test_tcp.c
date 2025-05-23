#include "tcp.h"
#include <assert.h>

void test_parse_tcp_ipv4()
{
    uint8_t tcp_packet[] = {
    0x01, 0xbb, 0xe9, 0x2b, 
    0x3b, 0xbc, 0x0c, 0xec,
    0x88, 0xe2, 0xf9, 0xeb, 
    0x80, 0x11, 0x00, 0x65,
    0x93, 0x61, 0x00, 0x00, 
    0x01, 0x01, 0x08, 0x0a,
    0xcb, 0x34, 0x4f, 0x8c, 
    0x61, 0x8c, 0xa2, 0xc4
    };

    uint8_t ipv4_header[] = {
    0x45, 0x00, 0x00, 0x34, 0x5d, 0xe7, 0x40, 0x00,
    0x32, 0x06, 0xdd, 0x56, 0x8c, 0x52, 0x70, 0x15,
    0x0a, 0xc0, 0x06, 0x5f
    };

    my_ipv4_header_t ipv4 = parse_ipv4(ipv4_header, false);
    my_tcp_header_t tcp = parse_tcp_header(tcp_packet, ipv4.raw_source_address, ipv4.raw_destination_address, IPPROTO_IPV4, false);

    assert(tcp.source_port == 443);
    assert(tcp.destination_port == 59691);
    assert(tcp.sequence_number == 1002179820);
    assert(tcp.acknowledgment_number == 2296576491);
    assert(tcp.data_offset == 8);
    assert(tcp.reserved == 0);
    assert(tcp.flags == 0x011);
    assert(strcmp(tcp.tcp_flags_desc, "FIN ACK (0x11)") == 0);
    assert(tcp.window == 101);
    assert(tcp.checksum == 0x9361);
    assert(tcp.checksum_correct == true);
    assert(tcp.urgent_pointer == 0);
}

void test_parse_tcp_ipv6()
{
    uint8_t tcp_packet[] = {
    0xeb, 0x26, 0x27, 0x10, 
    0xa0, 0x22, 0x02, 0x56, 
    0x00, 0x00, 0x00, 0x00, 
    0xb0, 0x02, 0xff, 0xff, 
    0x17, 0xc5, 0x00, 0x00, // checksum 0x0034 but it is partial, the right checksum is 0x17c5 
    0x02, 0x04, 0x3f, 0xc4, // probably cause by TCP checksum offload (Wireshark says so)
    0x01, 0x03, 0x03, 0x06, 
    0x01, 0x01, 0x08, 0x0a, 
    0x60, 0x51, 0xd0, 0x24, 
    0x00, 0x00, 0x00, 0x00,
    0x04, 0x02, 0x00, 0x00
    };

    uint8_t ipv6_header[] = {
    0x60, 0x09, 0x0a, 0x00, 0x00, 
    0x2c, 0x06, 0x40, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x01, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x01
    };

    my_ipv6_header_t ipv6 = parse_ipv6(ipv6_header, false);
    my_tcp_header_t tcp = parse_tcp_header(tcp_packet, ipv6.raw_source_address, ipv6.raw_destination_address, IPPROTO_IPV6, false);
    assert(tcp.source_port == 60198);
    assert(tcp.destination_port == 10000);
    assert(tcp.sequence_number == 2686583382);
    assert(tcp.acknowledgment_number == 0);
    assert(tcp.data_offset == 11);
    assert(tcp.reserved == 0);
    assert(tcp.flags == 0x002);
    assert(strcmp(tcp.tcp_flags_desc, "SYN (0x2)") == 0);
    assert(tcp.window == 65535);
    assert(tcp.checksum == 0x17c5);
    assert(tcp.checksum_correct == true);
    assert(tcp.urgent_pointer == 0);
    assert(strncmp(tcp.tcp_options_desc, "| mss (16324) | no-op | ? op | no-op | no-op | ? op | ? op | eopl | eopl", 72) == 0);
}

int main()
{
    test_parse_tcp_ipv4();
    test_parse_tcp_ipv6();
    return 0;
}