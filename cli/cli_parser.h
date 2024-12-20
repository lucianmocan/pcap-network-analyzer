#ifndef CLI_PARSER_H
#define CLI_PARSER_H

#include <pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include "ethernet.h"
#include "ipv4.h"
#include "arp.h"
#include "ipv6.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"
#include "icmpv6.h"
#include "dhcp_bootp.h"
#include "dns.h"
#include <time.h>

#include <string.h>


// verbosity levels
#define VB_MINIMAL 1
#define VB_MIDDLE 2
#define VB_MAXIMAL 3

void parse_cli(const struct pcap_pkthdr *pcap_header, uint8_t *packet, int verbosity);
void parse_min(uint8_t *packet);
void parse_mid(uint8_t *packet);
void parse_max(uint8_t *packet);

// helpers
void print_timestamp(const struct pcap_pkthdr *pcap_header, int verbosity);
bool is_ipv4_header_empty(const my_ipv4_header_t *header);
bool is_ipv6_header_empty(const my_ipv6_header_t *header);
bool is_tcp_header_empty(const my_tcp_header_t *header);
bool is_udp_header_empty(const my_udp_header_t *header);


void diplay_ethernet_header(my_ethernet_header_t ethernet_header, int verbosity);
void display_ipv4_header(my_ipv4_header_t ipv4_header, int verbosity);
void display_arp_header(my_arp_header_t arp_header, int verbosity);
void display_ipv6_header(my_ipv6_header_t ipv6_header, int verbosity);

void display_dns_header(my_dns_header_t dns_header, int verbosity);

#endif