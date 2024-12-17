#include "arp.h"

/**
 * @brief Parse the ARP header from the packet and
 * return the parsed header
 * 
 * @param packet 
 * @param verbose 
 * @return my_arp_header_t 
 */
my_arp_header_t 
parse_arp(const uint8_t *packet, bool verbose)
{
    my_arp_header_t arp_header;

    struct ether_arp *arp = (struct ether_arp *)packet; 

    arp_header.hardware_type = ntohs(arp->arp_hrd);
    get_hardware_type_desc(arp_header.hardware_type, arp_header.hardware_type_desc, verbose);

    arp_header.protocol_type = ntohs(arp->arp_pro);
    // The permitted PTYPE values share a numbering space with those for EtherType.
    // So we can use the same function to get the description
    get_ethertype_desc(arp_header.protocol_type, arp_header.protocol_type_desc, verbose);

    arp_header.hardware_address_length = arp->arp_hln;
    arp_header.protocol_length = arp->arp_pln;
    
    arp_header.operation = ntohs(arp->arp_op);
    // get the operation description
    get_operation_desc(arp_header.operation, arp_header.operation_desc, verbose);

    // get the sender hardware address
    strcpy(arp_header.sender_hardware_address, write_mac_address(arp->arp_sha));

    // get the sender protocol address
    inet_ntop(AF_INET, arp->arp_spa, arp_header.sender_protocol_address, INET_ADDRSTRLEN);

    // get the target hardware address
    strcpy(arp_header.target_hardware_address, write_mac_address(arp->arp_tha));

    // get the target protocol address
    inet_ntop(AF_INET, arp->arp_tpa, arp_header.target_protocol_address, INET_ADDRSTRLEN);

    return arp_header;
}

/**
 * @brief Get the ARP operation description in a given string
 * 
 * @param operation 
 * @param operation_desc 
 */
void
get_operation_desc(uint16_t operation, char *operation_desc, bool verbose)
{
    switch(operation){
        case ARPOP_REQUEST:
            if (verbose){
                snprintf(operation_desc, MY_ARP_OPERATION_DESC_SIZE, "Operation: Request to resolve address");
            } else {
                snprintf(operation_desc, MY_ARP_OPERATION_DESC_SIZE, "Request");
            }
            break; 
        case ARPOP_REPLY:
            if (verbose){
                snprintf(operation_desc, MY_ARP_OPERATION_DESC_SIZE, "Operation: Response to previous request");
            } else {
                snprintf(operation_desc, MY_ARP_OPERATION_DESC_SIZE, "Reply");
            }
            break;
        #ifdef __APPLE__
        case ARPOP_REVREQUEST:
        #endif
        #ifdef __linux__
        case ARPOP_RREQUEST:
        #endif
            if (verbose){
                snprintf(operation_desc, MY_ARP_OPERATION_DESC_SIZE, "Operation: Request protocol address given hardware");
            } else {
                snprintf(operation_desc, MY_ARP_OPERATION_DESC_SIZE, "Reverse Request");
            }
            break;
        #ifdef __APPLE__
        case ARPOP_REVREPLY:
        #endif
        #ifdef __linux__
        case ARPOP_RREPLY:
        #endif
            if (verbose){
                snprintf(operation_desc, MY_ARP_OPERATION_DESC_SIZE, "Operation: Response giving protocol address");
            } else {
                snprintf(operation_desc, MY_ARP_OPERATION_DESC_SIZE, "Reverse Reply");
            }
            break;
        #ifdef __APPLE__
        case ARPOP_INVREQUEST:
        #endif
        #ifdef __linux__
        case ARPOP_InREQUEST:
        #endif
            if (verbose){
                snprintf(operation_desc, MY_ARP_OPERATION_DESC_SIZE, "Operation: Request to identify peer");
            } else {
                snprintf(operation_desc, MY_ARP_OPERATION_DESC_SIZE, "Inverse Request");
            }
            break;
        #ifdef __APPLE__
        case ARPOP_INVREPLY:
        #endif
        #ifdef __linux__
        case ARPOP_InREPLY:
        #endif
            if (verbose){
                snprintf(operation_desc, MY_ARP_OPERATION_DESC_SIZE, "Operation: Response identifying peer");
            } else {
                snprintf(operation_desc, MY_ARP_OPERATION_DESC_SIZE, "Inverse Reply");
            }
            break;
    }
}

/**
 * @brief Get the ARP hardware type description in a given string
 * 
 * @param hardware_type 
 * @param hardware_type_desc 
 * @param verbose 
 */
void
get_hardware_type_desc(uint16_t hardware_type, char *hardware_type_desc, bool verbose)
{
    switch(hardware_type){
        case ARPHRD_ETHER:
            if (verbose){
                snprintf(hardware_type_desc, MY_ARP_HARDWARE_TYPE_DESC_SIZE, "Hardware type: Ethernet (%d)", hardware_type);
            } else {
                snprintf(hardware_type_desc, MY_ARP_HARDWARE_TYPE_DESC_SIZE, "Ethernet");
            }
            break;
        case ARPHRD_IEEE802:
            if (verbose){
                snprintf(hardware_type_desc, MY_ARP_HARDWARE_TYPE_DESC_SIZE, "Hardware type: IEEE802 (%d)", hardware_type);
            } else {
                snprintf(hardware_type_desc, MY_ARP_HARDWARE_TYPE_DESC_SIZE, "IEEE802");
            }
            break;
        #ifdef __APPLE__
        case ARPHRD_FRELAY:
        #endif
        #ifdef __linux__
        case ARPHRD_DLCI:
        #endif
            if (verbose){
                snprintf(hardware_type_desc, MY_ARP_HARDWARE_TYPE_DESC_SIZE, "Hardware type: Frame Relay (%d)", hardware_type);
            } else {
                snprintf(hardware_type_desc, MY_ARP_HARDWARE_TYPE_DESC_SIZE, "Frame Relay");
            }
            break;
        case ARPHRD_IEEE1394:
            if (verbose){
                snprintf(hardware_type_desc, MY_ARP_HARDWARE_TYPE_DESC_SIZE, "Hardware type: IEEE1394 (%d)", hardware_type);
            } else {
                snprintf(hardware_type_desc, MY_ARP_HARDWARE_TYPE_DESC_SIZE, "IEEE1394");
            }
            break;
        #ifdef __APPLE__
        case ARPHRD_IEEE1394_EUI64:
        #endif
        #ifdef __linux__
        case ARPHRD_EUI64:
        #endif
            if (verbose){
                snprintf(hardware_type_desc, MY_ARP_HARDWARE_TYPE_DESC_SIZE, "Hardware type: IEEE1394 EUI-64 (%d)", hardware_type);
            } else {
                snprintf(hardware_type_desc, MY_ARP_HARDWARE_TYPE_DESC_SIZE, "IEEE1394 EUI-64");
            }
            break;
    }
}