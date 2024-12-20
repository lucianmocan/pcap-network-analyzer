#ifndef CLI_H
#define CLI_H

#include <signal.h>
#include <stdbool.h>

void start_capture(char* source, char* filter, int verbosity, bool is_live);

void set_filter_if_exists(pcap_t *capture, char* filter);
void signal_handler(int sig);
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void cleanup();

#endif