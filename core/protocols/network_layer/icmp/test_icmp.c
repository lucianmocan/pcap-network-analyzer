#include "icmp.h"
#include <assert.h>


void test_parse_icmp_echo_request()
{
    uint8_t packet[21] = {
    0x08, 0x00, 0xa4, 0x9e, // Type (8), Code (0), Checksum (0xa49e)
    0x12, 0x34, 0x00, 0x01, // Identifier (0x1234), Sequence Number (0x0001)
    'H',  'e',  'l',  'l',  // Payload
    'o',  ',',  ' ',  'W', 
    'o',  'r',  'l',  'd',  '!'
    };

    my_icmp_t icmp = parse_icmp(packet, sizeof(packet), false);
    assert(icmp.type == ICMP_ECHO);
    assert(strcmp(icmp.icmp_type_desc, "Echo Request") == 0);
    assert(icmp.code == 0);
    assert(strcmp(icmp.icmp_code_desc, "0") == 0);
    assert(icmp.checksum == 0xa49e);
    assert(icmp.checksum_valid == true);
    assert(icmp.identifier == 0x1234);
    assert(icmp.sequence_number == 0x0001);
    assert(strcmp((char *)icmp.data, "Hello, World!") == 0);
}

void test_parse_icmp_echo_reply()
{
    uint8_t packet[12] = {
        0x00, 0x00,       // Type: 0 (Echo Reply), Code: 0 (No error)
        0x29, 0x04,       // Checksum (0x2904)
        0x12, 0x34,       // Identifier
        0x00, 0x01,       // Sequence Number
        'a', 'b', 'c', 'd'  // Payload
    };
    my_icmp_t icmp = parse_icmp(packet, sizeof(packet), false);
    assert(icmp.type == ICMP_ECHOREPLY);
    assert(strcmp(icmp.icmp_type_desc, "Echo Reply") == 0);
    assert(icmp.code == 0);
    assert(strcmp(icmp.icmp_code_desc, "0") == 0);
    assert(icmp.checksum == 0x2904);
    assert(icmp.checksum_valid == true);
    assert(icmp.identifier == 0x1234);
    assert(icmp.sequence_number == 0x0001);
    assert(strcmp((char *)icmp.data, "abcd") == 0);
}

void test_parse_icmp_destination_unreachable()
{
    uint8_t packet[8] = {
        0x03, 0x01, 0xfc, 0xfe,  // Type (3), Code (1), Checksum (0xfcfe)
        0x00, 0x00, 0x00, 0x00,  // Unused field (4 bytes, must be zero)
        // then Internet Header etc... I should implement this later not important now
    };

    my_icmp_t icmp = parse_icmp(packet, sizeof(packet), false);
    assert(icmp.type == ICMP_UNREACH);
    assert(strcmp(icmp.icmp_type_desc, "Destination Unreachable") == 0);
    assert(icmp.code == ICMP_UNREACH_HOST);
    assert(strcmp(icmp.icmp_code_desc, "bad host") == 0);
    assert(icmp.checksum == 0xfcfe);
    assert(icmp.checksum_valid == true);
    assert(icmp.identifier == 0);
    assert(icmp.sequence_number == 0);
    
}


int main()
{   
    test_parse_icmp_echo_request();
    test_parse_icmp_echo_reply();
    test_parse_icmp_destination_unreachable();
    return 0;
}