#ifndef INTERFACE_H
#define INTERFACE_H

#include "linked_list.h"
#include "interface.h"

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
#include "bsd_string.h"
#endif

typedef struct dev_interface {
    char *name;
    char *description;
    char flags[50];
    node_t *addresses;
} *dev_interface_t;


dev_interface_t get_interface_infos(pcap_if_t* dev);
void free_interface_infos(dev_interface_t dev);


#endif