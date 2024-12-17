#include "ipv6.h"
#include <assert.h>

void test_parse_ipv6()
{
    uint8_t packet[40] = {
        0x62, 0x10, 0x01, 0x00,  
        0x00, 0x20, 0x06, 0x40,
        0x20, 0x01, 0x0d, 0xb8,  
        0x85, 0xa3, 0x00, 0x00,  
        0x00, 0x00, 0x8a, 0x2e,  
        0x03, 0x70, 0x73, 0x34,  
        0x20, 0x01, 0x0d, 0xb8,  
        0x85, 0xa3, 0x00, 0x00,  
        0x00, 0x00, 0x8a, 0x2e,  
        0x03, 0x70, 0x73, 0x35  
    };

    my_ipv6_header_t ipv6_header = parse_ipv6(packet, false);
    assert(ipv6_header.version == 6);
    assert(ipv6_header.traffic_class == 2);
    assert(ipv6_header.flow_label == 256);
    assert(ipv6_header.dscp_value == 8);
    assert(strcmp(ipv6_header.dscp_desc, "CS1") == 0);
    assert(ipv6_header.ecn_value == 1);
    assert(strcmp(ipv6_header.ecn_desc, "ECT(1)") == 0);
    assert(ipv6_header.payload_length == 32);
    assert(ipv6_header.next_header == 6);
    assert(strcmp(ipv6_header.next_header_name, "TCP") == 0);
    assert(ipv6_header.hop_limit == 64);
    assert(strcmp(ipv6_header.source_address, "2001:db8:85a3::8a2e:370:7334") == 0);
    assert(strcmp(ipv6_header.destination_address, "2001:db8:85a3::8a2e:370:7335") == 0);
}

int main()
{
    test_parse_ipv6();
    return 0;
}