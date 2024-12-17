#ifndef ARP_H
#define ARP_H

#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include "ethernet.h"
#include "mac_address.h"

#define MY_ARP_HARDWARE_TYPE_DESC_SIZE 40
#define MY_ARP_OPERATION_DESC_SIZE 60

// IPv4 over Ethernet ARP header
// https://en.wikipedia.org/wiki/Address_Resolution_Protocol#cite_note-IANA-2
typedef struct my_arp_header
{
    uint16_t hardware_type;
    char hardware_type_desc[MY_ARP_HARDWARE_TYPE_DESC_SIZE];

    uint16_t protocol_type;
    char protocol_type_desc[MY_ETHER_TYPE_DESC_SIZE];

    uint8_t hardware_address_length;
    uint8_t protocol_length;
    uint16_t operation;
    char operation_desc[MY_ARP_OPERATION_DESC_SIZE];

    char sender_hardware_address[MY_ETHER_ADDRESS_SIZE];
    char sender_protocol_address[INET_ADDRSTRLEN];

    char target_hardware_address[MY_ETHER_ADDRESS_SIZE];
    char target_protocol_address[INET_ADDRSTRLEN];

} my_arp_header_t;

my_arp_header_t parse_arp(const uint8_t *packet, bool verbose);

// helpers
void get_hardware_type_desc(uint16_t hardware_type, char *hardware_type_desc, bool verbose);
void get_operation_desc(uint16_t operation, char *operation_desc, bool verbose);


#endif