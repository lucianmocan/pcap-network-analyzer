#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>


/**
 * @brief Get the interfaces object
 * 
 * @return pcap_if_t* 
 */
pcap_if_t* 
get_interfaces()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp = NULL;

    if (pcap_findalldevs(&alldevsp, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return NULL;
    }

    return alldevsp;
}

/**
 * @brief Free the interfaces list object
 * 
 * @param alldevsp 
 */
void
free_interfaces(pcap_if_t *alldevsp)
{
    pcap_freealldevs(alldevsp);
}

