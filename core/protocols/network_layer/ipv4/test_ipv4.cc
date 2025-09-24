#include "ipv4.h"
#include <cassert>
#include <arpa/inet.h>

void test_get_flags_desc(){
    uint16_t ip_off = 0x4000;
    std::string flags_desc;
    get_flags_desc(flags_desc, ip_off, true);
    assert(flags_desc == "DF (Don't Fragment)");

    ip_off = 0x2000;
    get_flags_desc(flags_desc, ip_off, true);
    assert(flags_desc == "MF (More Fragments)");

    ip_off = 0x8000;
    get_flags_desc(flags_desc, ip_off, false);
    assert(flags_desc == "RF");

    ip_off = 0x4000;
    get_flags_desc(flags_desc, ip_off, false);
    assert(flags_desc == "DF");

    ip_off = 0x2000;
    get_flags_desc(flags_desc, ip_off, false);
    assert(flags_desc == "MF");
}

void test_get_protocol_name(){
    uint8_t protocol = 0x06;
    std::string protocol_name;
    ipv4_get_protocol_name(protocol, protocol_name, true);
    assert(protocol_name == "TCP (Transmission Control Protocol)");

    protocol = 0x11;
    ipv4_get_protocol_name(protocol, protocol_name, true);
    assert(protocol_name == "UDP (User Datagram Protocol)");

    protocol = 0x01;
    ipv4_get_protocol_name(protocol, protocol_name, false);
    assert(protocol_name == "ICMP");

    protocol = 0x02;
    ipv4_get_protocol_name(protocol, protocol_name, false);
    assert(protocol_name == "IGMP");
}

void test_parse_ipv4(){
    uint8_t packet[] = {
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61,
        0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7
    };
    
    my_ipv4_header_t ipv4_header = parse_ipv4(packet, true);
    
    // test version & header_length
    assert(ipv4_header.version == 4);
    assert(ipv4_header.header_length == 5);

    // test dscp & ecn
    assert(ipv4_header.dscp_desc == "CS0: Best Effort / Standard");
    assert(ipv4_header.dscp_value == 0);
    assert(ipv4_header.ecn_desc == "Not-ECT: Not ECN-Capable Transport");
    assert(ipv4_header.ecn_value == 0);

    // test total_length, identification, flags, fragment_offset
    assert(ipv4_header.total_length == 115);
    assert(ipv4_header.identification == 0);
    assert(ipv4_header.flags.reserved == 0);
    assert(ipv4_header.flags.dont_fragment == 1);
    assert(ipv4_header.flags.more_fragments == 0);
    assert(ipv4_header.flags_desc == "DF (Don't Fragment)");
    assert(ipv4_header.fragment_offset == 0);

    // test time_to_live, protocol, checksum
    assert(ipv4_header.time_to_live == 64);
    assert(ipv4_header.protocol == 17);
    assert(ipv4_header.protocol_name == "UDP (User Datagram Protocol)");
    assert(ipv4_header.checksum == 0xb861);
    assert(ipv4_header.checksum_correct == true);

    // test source_ipv4, destination_ipv4
    assert(ipv4_header.source_ipv4 == "192.168.0.1");
    assert(ipv4_header.destination_ipv4 == "192.168.0.199");
}

int main(){
    test_get_flags_desc();
    test_get_protocol_name();
    test_parse_ipv4();
    return 0;
}