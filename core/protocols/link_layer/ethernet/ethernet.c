
#include "ethernet.h"

/**
 * @brief Parse the ethernet header off a packet and
 * return all the information in a my_ethernet_header_t struct
 * 
 * @param packet 
 * @return my_ethernet_header_t 
 */
my_ethernet_header_t 
parse_ethernet(const u_char *packet, bool verbose)
{
    const struct ether_header *ethernet;
    int size_ethernet = sizeof(struct ether_header);
    ethernet = (struct ether_header*)(packet);
    
    my_ethernet_header_t ethernet_frame;
    strcpy(ethernet_frame.src_mac, write_mac_address(ethernet->ether_shost));
    strcpy(ethernet_frame.dst_mac, write_mac_address(ethernet->ether_dhost));
    ethernet_frame.type = ntohs(ethernet->ether_type);

    get_ethertype_desc(ethernet_frame.type, ethernet_frame.type_desc, verbose);

    // check if the frame is VLAN tagged
    if (ethernet_frame.type == 0x8100){
        ethernet_frame.vlan_tagged = true;

        // extract VLAN ID and Priority Code Point, Drop Eligible Indicator 
        // source: https://en.wikipedia.org/wiki/IEEE_802.1Q
        uint8_t vlan_tci = ntohs(*(uint16_t *)(packet + size_ethernet));
        ethernet_frame.vlan_id = vlan_tci & 0x0FFF;
        ethernet_frame.dei = vlan_tci & 0x1000;
        ethernet_frame.pcp = vlan_tci & 0xE000;

        // get the actual ethernet type + 2 bytes after the VLAN stuff
        ethernet_frame.type_vlan = ntohs(*(uint16_t *)(packet + size_ethernet + 2));
        get_ethertype_desc(ethernet_frame.type_vlan, ethernet_frame.type_desc_vlan, verbose);
    } else {
        ethernet_frame.vlan_tagged = false;
    }

    return ethernet_frame;
}

/**
 * @brief Get the description of the ethernet type
 * 
 * @param type 
 * @param type_desc 
 */
void
get_ethertype_desc(uint16_t type, char *type_desc, bool verbose)
{
    switch(type){
        case ETHERTYPE_PUP:
            if (verbose){
                snprintf(type_desc, MY_ETHER_TYPE_DESC_SIZE, "Type: PUP (0x%x)", ETHERTYPE_PUP);
            } else {
                snprintf(type_desc, MY_ETHER_TYPE_DESC_SIZE, "PUP");
            }
            break;
        case ETHERTYPE_IP:
            if (verbose){
                snprintf(type_desc, MY_ETHER_TYPE_DESC_SIZE, "Type: IP (0x%x)", ETHERTYPE_IP);
            } else {
                snprintf(type_desc, MY_ETHER_TYPE_DESC_SIZE, "IP");
            }
            break;
        case ETHERTYPE_ARP:
            if (verbose){
                snprintf(type_desc, MY_ETHER_TYPE_DESC_SIZE, "Type: ARP (0x%x)", ETHERTYPE_ARP);
            } else {
                snprintf(type_desc, MY_ETHER_TYPE_DESC_SIZE, "ARP");
            }
            break;
        case ETHERTYPE_REVARP:
            if (verbose){
                snprintf(type_desc, MY_ETHER_TYPE_DESC_SIZE, "Type: Reverse ARP (0x%x)", ETHERTYPE_REVARP);
            } else {
                snprintf(type_desc, MY_ETHER_TYPE_DESC_SIZE, "Reverse ARP");
            }
            break;
        case ETHERTYPE_IPV6:
            if (verbose){
                snprintf(type_desc, MY_ETHER_TYPE_DESC_SIZE, "Type: IPv6 (0x%x)", ETHERTYPE_IPV6);
            } else {
                snprintf(type_desc, MY_ETHER_TYPE_DESC_SIZE, "IPv6");
            }
            break;
        case ETHERTYPE_VLAN:
            if (verbose){
                snprintf(type_desc, MY_ETHER_TYPE_DESC_SIZE, "Type: VLAN (0x%x)", ETHERTYPE_VLAN);
            } else {
                snprintf(type_desc, MY_ETHER_TYPE_DESC_SIZE, "VLAN");
            }
            break;
        default:
            if (verbose){
                snprintf(type_desc, MY_ETHER_TYPE_DESC_SIZE, "Type: Unknown (0x%x)", type);
            } else {
                snprintf(type_desc, MY_ETHER_TYPE_DESC_SIZE, "Unknown");
            }
            break;
    }
}


