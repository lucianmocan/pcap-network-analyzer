#include "ipv4.h"
#include <assert.h>
#include <arpa/inet.h>

void test_calculate_checksum(){
    u_int8_t packet[] = {
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61,
        0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7
    };
    
    struct ip *ip = (struct ip*)packet;
    int length = ip->ip_hl * 4;
    uint16_t original_checksum = ip->ip_sum;
    ip->ip_sum = 0;
    
    uint16_t checksum = calculate_checksum((uint16_t*)packet, length);
    
    assert(checksum == original_checksum);
}

void test_get_flags_desc(){
    uint16_t ip_off = 0x4000;
    char flags_desc[FLAGS_DESC_SIZE];
    get_flags_desc(flags_desc, ip_off, true);
    assert(strcmp(flags_desc, "DF (Don't Fragment)") == 0);
    
    ip_off = 0x2000;
    get_flags_desc(flags_desc, ip_off, true);
    assert(strcmp(flags_desc, "MF (More Fragments)") == 0);
    
    ip_off = 0x8000;
    get_flags_desc(flags_desc, ip_off, false);
    assert(strcmp(flags_desc, "RF") == 0);
    
    ip_off = 0x4000;
    get_flags_desc(flags_desc, ip_off, false);
    assert(strcmp(flags_desc, "DF") == 0);
    
    ip_off = 0x2000;
    get_flags_desc(flags_desc, ip_off, false);
    assert(strcmp(flags_desc, "MF") == 0);
}

void test_get_protocol_name(){
    uint8_t protocol = 0x06;
    char protocol_name[PROTOCOL_NAME_SIZE];
    ipv4_get_protocol_name(protocol, protocol_name, true);
    assert(strcmp(protocol_name, "TCP (Transmission Control Protocol)") == 0);
    
    protocol = 0x11;
    ipv4_get_protocol_name(protocol, protocol_name, true);
    assert(strcmp(protocol_name, "UDP (User Datagram Protocol)") == 0);
    
    protocol = 0x01;
    ipv4_get_protocol_name(protocol, protocol_name, false);
    assert(strcmp(protocol_name, "ICMP") == 0);
    
    protocol = 0x02;
    ipv4_get_protocol_name(protocol, protocol_name, false);
    assert(strcmp(protocol_name, "IGMP") == 0);
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
    assert(strcmp(ipv4_header.dscp_desc, "CS0: Best Effort / Standard") == 0);
    assert(ipv4_header.dscp_value == 0);
    assert(strcmp(ipv4_header.ecn_desc, "Not-ECT: Not ECN-Capable Transport") == 0);
    assert(ipv4_header.ecn_value == 0);

    // test total_length, identification, flags, fragment_offset
    assert(ipv4_header.total_length == 115);
    assert(ipv4_header.identification == 0);
    assert(ipv4_header.flags.reserved == 0);
    assert(ipv4_header.flags.dont_fragment == 1);
    assert(ipv4_header.flags.more_fragments == 0);
    assert(strcmp(ipv4_header.flags_desc, "DF (Don't Fragment)") == 0);
    assert(ipv4_header.fragment_offset == 0);

    // test time_to_live, protocol, checksum
    assert(ipv4_header.time_to_live == 64);
    assert(ipv4_header.protocol == 17);
    assert(strcmp(ipv4_header.protocol_name, "UDP (User Datagram Protocol)") == 0);
    assert(ipv4_header.checksum == 0xb861);
    assert(ipv4_header.checksum_correct == true);

    // test source_ipv4, destination_ipv4
    assert(strcmp(ipv4_header.source_ipv4, "192.168.0.1") == 0);
    assert(strcmp(ipv4_header.destination_ipv4, "192.168.0.199") == 0);
}

int main(){
    test_calculate_checksum();
    test_get_flags_desc();
    test_get_protocol_name();
    test_parse_ipv4();
    return 0;
}