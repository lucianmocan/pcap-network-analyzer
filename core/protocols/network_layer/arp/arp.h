#ifndef ARP_H
#define ARP_H

#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <string>

#include "ethernet.h"
#include "mac_address.h"

// IPv4 over Ethernet ARP header
// https://en.wikipedia.org/wiki/Address_Resolution_Protocol#cite_note-IANA-2
typedef struct my_arp_header
{
    uint16_t hardware_type;
    std::string hardware_type_desc;

    uint16_t protocol_type;
    std::string protocol_type_desc;

    uint8_t hardware_address_length;
    uint8_t protocol_length;
    uint16_t operation;
    std::string operation_desc;

    std::string sender_hardware_address;
    std::string sender_protocol_address;

    std::string target_hardware_address;
    std::string target_protocol_address;

} my_arp_header_t;

my_arp_header_t parse_arp(const uint8_t *packet, bool verbose);

// helpers
void get_hardware_type_desc(uint16_t hardware_type, std::string& hardware_type_desc, bool verbose);
void get_operation_desc(uint16_t operation, std::string& operation_desc, bool verbose);


#endif