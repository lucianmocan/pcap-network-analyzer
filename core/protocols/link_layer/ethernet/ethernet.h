#ifndef ETHERNET_H
#define ETHERNET_H

#include <pcap.h>
#include <net/ethernet.h>
#include <string.h>

#include "mac_address.h"

typedef struct ethernet_frame {
    char src_mac[18];
    char dst_mac[18]; 
    u_short type;
} ethernet_frame_t;

ethernet_frame_t parse_ethernet(const u_char *packet);

#endif