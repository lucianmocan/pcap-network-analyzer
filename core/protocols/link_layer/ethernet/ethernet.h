#ifndef ETHERNET_H
#define ETHERNET_H

#include <pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <stdbool.h>

#include "mac_address.h"

typedef struct my_ethernet_header {
    char src_mac[18];
    char dst_mac[18]; 
    u_short type;
    // VLAN
    bool vlan_tagged;
    u_short vlan_id;
    u_short pcp;
    u_short dei;
} my_ethernet_header_t;

my_ethernet_header_t parse_ethernet(const u_char *packet);

#endif