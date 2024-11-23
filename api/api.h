#ifndef API_H
#define API_H

#include <pcap.h>
#include <net/ethernet.h>
#include "interface.h"

pcap_if_t* get_interfaces();
void free_interfaces(pcap_if_t *alldevsp);

#endif