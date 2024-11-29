
#include "ethernet.h"

my_ethernet_header_t 
parse_ethernet(const u_char *packet)
{
    const struct ether_header *ethernet;
    int size_ethernet = sizeof(struct ether_header);
    ethernet = (struct ether_header*)(packet);
    
    my_ethernet_header_t ethernet_frame;
    strcpy(ethernet_frame.src_mac, write_mac_address(ethernet->ether_shost));
    strcpy(ethernet_frame.dst_mac, write_mac_address(ethernet->ether_dhost));
    ethernet_frame.type = ntohs(ethernet->ether_type);

    if (ethernet_frame.type == 0x8100){
        ethernet_frame.vlan_tagged = true;

        // extract VLAN ID and Priority Code Point, Drop Eligible Indicator 
        // source: https://en.wikipedia.org/wiki/IEEE_802.1Q
        u_short vlan_tci = ntohs(*(u_short *)(packet + size_ethernet));
        ethernet_frame.vlan_id = vlan_tci & 0x0FFF;
        ethernet_frame.dei = vlan_tci & 0x1000;
        ethernet_frame.pcp = vlan_tci & 0xE000;

        // get the actual ethernet type + 2 bytes after the VLAN stuff
        ethernet_frame.type = ntohs(*(u_short *)(packet + size_ethernet + 2));
    } else {
        ethernet_frame.vlan_tagged = false;
    }

    return ethernet_frame;
}


