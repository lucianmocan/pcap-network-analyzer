#include "arp.h"
#include <cassert>

void test_parse_arp()
{
    uint8_t packet[28] = {
        0x00, 0x01, // Hardware type: Ethernet
        0x08, 0x00, // Protocol type: IPv4
        0x06,       // Hardware address length: 6
        0x04,       // Protocol address length: 4
        0x00, 0x01, // Opcode: Request
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Sender MAC address
        0x01, 0x02, 0x03, 0x04,             // Sender IP address
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // Target MAC address
        0x05, 0x06, 0x07, 0x08              // Target IP address
    };

    my_arp_header_t arp_header = parse_arp(packet, true);
    assert(arp_header.hardware_type == 1);
    assert(arp_header.hardware_type_desc == "Hardware type: Ethernet (1)");
    assert(arp_header.protocol_type == 0x0800);
    assert(arp_header.protocol_type_desc == "Type: IP (0x800)");
    assert(arp_header.hardware_address_length == 6);
    assert(arp_header.protocol_length == 4);
    assert(arp_header.operation == 1);
    assert(arp_header.operation_desc == "Operation: Request to resolve address");
    assert(arp_header.sender_hardware_address == "00:11:22:33:44:55");
    assert(arp_header.sender_protocol_address == "1.2.3.4");
    assert(arp_header.target_hardware_address == "66:77:88:99:aa:bb");
    assert(arp_header.target_protocol_address == "5.6.7.8");
}

int main()
{
    test_parse_arp();
    return 0;
}