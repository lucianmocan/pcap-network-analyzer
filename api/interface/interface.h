#ifndef INTERFACE_H
#define INTERFACE_H

#include "linked_list.h"
#include "mac_address.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <pcap.h>

#ifdef __APPLE__
#include <net/if_dl.h>
#endif
#ifdef __linux__
#include <linux/if_packet.h>
#endif

typedef struct dev_interface {
    char *name;
    char *description;
    char flags[50];
    node_t *addresses;
} *dev_interface_t;


pcap_if_t* get_interfaces();
pcap_if_t* get_interface(char* interface, pcap_if_t* alldevsp);
void free_interfaces(pcap_if_t *alldevsp);

dev_interface_t get_interface_infos(pcap_if_t* dev);
void free_interface_infos(dev_interface_t dev);


#endif