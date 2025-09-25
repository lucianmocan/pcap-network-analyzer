#include "icmp.h"
#include <cassert>


void test_parse_icmp_echo_request()
{
    uint8_t packet[] = {
    0x08, 0x00, 0xC5, 0x30, // Type 8, Code 0, Checksum (0xc530)
    0xBC, 0x24, 0x00, 0x00, 
    0x67, 0x62, 0xA4, 0x7A, // ping adds a timestamp not standard ignore it...
    0x00, 0x0E, 0x7F, 0xBC, // timestamp added by ping
    0x08, 0x09, 0x0A, 0x0B, // payload
    0x0C, 0x0D, 0x0E, 0x0F, 
    0x10, 0x11, 0x12, 0x13, 
    0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 
    0x1C, 0x1D, 0x1E, 0x1F, 
    0x20, 0x21, 0x22, 0x23, 
    0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 
    0x2C, 0x2D, 0x2E, 0x2F, 
    0x30, 0x31, 0x32, 0x33, 
    0x34, 0x35, 0x36, 0x37
};
    my_icmp_t icmp = parse_icmp(packet, sizeof(packet), false);
    assert(icmp.type == ICMP_ECHO);
    assert(icmp.icmp_type_desc == "Echo Request");
    assert(icmp.code == 0);
    assert(icmp.icmp_code_desc == "0");
    assert(icmp.checksum == 0xc530);
    assert(icmp.checksum_valid == true);
    assert(icmp.identifier == 0xbc24);
    assert(icmp.sequence_number == 0x0000);
    assert(std::string((char *)&icmp.payload[33]) == std::string("!\"#$%&'()*+,-./01234567"));
}

void test_parse_icmp_echo_reply()
{
    uint8_t packet[] = {
    0x00, 0x00, 0xcd, 0x30, // Type 0, Code 0, Checksum (0xcd30)
    0xbc, 0x24, 0x00, 0x00, // Identifier, Sequence number
    0x67, 0x62, 0xa4, 0x7a, // timestamp added by ping not standard
    0x00, 0x0e, 0x7f, 0xbc, // timestamp
    0x08, 0x09, 0x0a, 0x0b, // payload
    0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 
    0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 
    0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 
    0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 
    0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 
    0x34, 0x35, 0x36, 0x37
    };

    my_icmp_t icmp = parse_icmp(packet, sizeof(packet), false);
    assert(icmp.type == ICMP_ECHOREPLY);
    assert(icmp.icmp_type_desc == "Echo Reply");
    assert(icmp.code == 0);
    assert(icmp.icmp_code_desc == "0");
    assert(icmp.checksum == 0xcd30);
    assert(icmp.checksum_valid == true);
    assert(icmp.identifier == 0xbc24);
    assert(icmp.sequence_number == 0x0000);
    assert(std::string((char *)&icmp.payload[33]) == std::string("!\"#$%&'()*+,-./01234567"));
}

void test_parse_icmp_destination_unreachable()
{
    uint8_t packet[48] = {
        0x03, 0x01, 0xac, 0x96,  // Type (3), Code (1), Checksum (0x976c)
        0x00, 0x00, 0x00, 0x00,  // Unused field (4 bytes, must be zero)
        0x45, 0x00, 0x00, 0x3c,  // Internet header (IP header)
        0x1c, 0x46, 0x40, 0x00,  
        0x40, 0x06, 0x9c, 0xbc,  
        0xc0, 0xa8, 0x00, 0x68,  // Source IP (192.168.0.104)
        0xc0, 0xa8, 0x00, 0x01,  // Destination IP (192.168.0.1)
        0x00, 0x14, 0x00, 0x50,  // TCP header: Source port (20), Destination port (80)
        0x00, 0x00, 0x00, 0x00,  // TCP sequence number
        0x00, 0x00, 0x00, 0x00,  // TCP acknowledgment number
        0x50, 0x04, 0x00, 0x00,  // TCP header flags and window size
        0x00, 0x00, 0x00, 0x00   // TCP checksum and urgent pointer
    };

    my_icmp_t icmp = parse_icmp(packet, sizeof(packet), false);
    assert(icmp.type == ICMP_UNREACH);
    assert(icmp.icmp_type_desc == "Destination Unreachable");
    assert(icmp.code == ICMP_UNREACH_HOST);
    assert(icmp.icmp_code_desc == "bad host");
    assert(icmp.checksum == 0xac96);
    assert(icmp.checksum_valid == true);
    assert(icmp.identifier == 0);
    assert(icmp.sequence_number == 0);
    assert(icmp.payload != NULL);
    // Test the original IP header (this should work because it is tested in the ipv4 test)
    // but just in case :)
    assert(icmp.og_ip_header.version == 4);
    assert(icmp.og_ip_header.header_length == 5);
    assert(icmp.og_ip_header.dscp_value == 0);
    assert(icmp.og_ip_header.dscp_desc == "CS0");
    assert(icmp.og_ip_header.ecn_value == 0);
    assert(icmp.og_ip_header.ecn_desc == "Not-ECT");
    assert(icmp.og_ip_header.total_length == 60);
    assert(icmp.og_ip_header.identification == 7238);
    assert(icmp.og_ip_header.fragment_offset == 0);
    assert(icmp.og_ip_header.flags.reserved == 0);
    assert(icmp.og_ip_header.flags.dont_fragment == 1);
    assert(icmp.og_ip_header.flags.more_fragments == 0);
    assert(icmp.og_ip_header.flags_desc == "DF");
    assert(icmp.og_ip_header.time_to_live == 64);
    assert(icmp.og_ip_header.protocol == IPPROTO_TCP);
    assert(icmp.og_ip_header.protocol_name == "TCP");
    assert(icmp.og_ip_header.checksum == 0x9cbc);
    assert(icmp.og_ip_header.checksum_correct == true);
}


int main()
{   
    test_parse_icmp_echo_request();
    test_parse_icmp_echo_reply();
    test_parse_icmp_destination_unreachable();
    return 0;
}