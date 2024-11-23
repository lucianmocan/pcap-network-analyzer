
#include "ethernet.h"

ethernet_frame_t 
parse_ethernet(const u_char *packet)
{
    const struct ether_header *ethernet;
    int size_ethernet = sizeof(struct ether_header);
    ethernet = (struct ether_header*)(packet);
    
    ethernet_frame_t ethernet_frame;
    strcpy(ethernet_frame.src_mac, write_mac_address(ethernet->ether_shost));
    strcpy(ethernet_frame.dst_mac, write_mac_address(ethernet->ether_dhost));
    ethernet_frame.type = ethernet->ether_type;

    return ethernet_frame;
}


