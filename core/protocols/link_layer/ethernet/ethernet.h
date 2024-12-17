#ifndef ETHERNET_H
#define ETHERNET_H

#include <pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <stdbool.h>

#include "mac_address.h"

#define MY_ETHER_TYPE_DESC_SIZE 32
#define MY_ETHER_ADDRESS_SIZE 18

typedef struct my_ethernet_header {
    char src_mac[MY_ETHER_ADDRESS_SIZE];
    char dst_mac[MY_ETHER_ADDRESS_SIZE]; 

    uint16_t type;
    char type_desc[MY_ETHER_TYPE_DESC_SIZE];
    // VLAN
    bool vlan_tagged;
    uint16_t vlan_id;
    uint16_t pcp;
    uint16_t dei;
    uint16_t type_vlan;
    char type_desc_vlan[MY_ETHER_TYPE_DESC_SIZE];
} my_ethernet_header_t;

my_ethernet_header_t parse_ethernet(const u_char *packet, bool verbose);

// helpers
void get_ethertype_desc(uint16_t type, char *type_desc, bool verbose);

#endif