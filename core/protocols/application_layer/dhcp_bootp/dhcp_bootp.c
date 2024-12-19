#include "dhcp_bootp.h"

/**
 * @brief Parse the BOOTP header from the packet and return the parsed header
 * 
 * @param packet 
 * @param verbose 
 * @return my_bootp_header_t 
 */
my_dhcp_bootp_header_t 
parse_bootp(uint8_t *packet, bool verbose)
{
    my_dhcp_bootp_header_t bootp_header;

    struct bootp *bootp = (struct bootp *)packet;

    bootp_header.bp_op = bootp->bp_op;
    get_bp_op_desc(bootp_header.bp_op, bootp_header.bp_op_desc, verbose);

    bootp_header.bp_htype = bootp->bp_htype;
    get_hardware_type_desc(bootp_header.bp_htype, bootp_header.bp_htype_desc, verbose);

    bootp_header.bp_hlen = bootp->bp_hlen;

    bootp_header.bp_xid = ntohl(bootp->bp_xid);

    bootp_header.bp_secs = ntohs(bootp->bp_secs);

    bootp_header.dhcp_flags_bp_unused = ntohs(bootp->bp_unused);

    // BOOTREQUEST, if known
    if (bootp_header.bp_op == BOOTREQUEST){
        inet_ntop(AF_INET, &bootp->bp_ciaddr, bootp_header.client_ip_address, INET_ADDRSTRLEN);
    } else {
        bootp_header.client_ip_address[0] = '\0';
    }
    
    inet_ntop(AF_INET, &bootp->bp_yiaddr, bootp_header.your_ip_address, INET_ADDRSTRLEN);
    
    // returned in BOOTREPLY by server
    if (bootp_header.bp_op == BOOTREPLY){
        inet_ntop(AF_INET, &bootp->bp_siaddr, bootp_header.server_ip_address, INET_ADDRSTRLEN);
    } else {
        bootp_header.server_ip_address[0] = '\0';
    }

    // optional cross-gateway booting
    if (bootp->bp_giaddr.s_addr != 0){
        inet_ntop(AF_INET, &bootp->bp_giaddr, bootp_header.gateway_ip_address, INET_ADDRSTRLEN);
    } else {
        bootp_header.gateway_ip_address[0] = '\0';
    }

    strcpy(bootp_header.client_hardware_address, write_mac_address(bootp->bp_chaddr));    
    strcpy((char*)bootp_header.server_host_name, (char*)bootp->bp_sname);
    strcpy((char*)bootp_header.boot_file_name, (char*)bootp->bp_file);

    bootp_header.magic_cookie = ntohl(*(uint32_t*)bootp->bp_vend);
    
    memcpy(bootp_header.vendor_specific_area, bootp->bp_vend, sizeof(bootp->bp_vend));

    // get the DHCP options
    uint8_t *options_start = packet + sizeof(struct bootp) - 60; // 60 = the size of the vendor specific area (64) - 4 bytes for the magic cookie
    bootp_header.dhcp_options = NULL;

    // get the DHCP options
    get_dhcp_options_desc(options_start, &bootp_header, verbose);

    return bootp_header;
}

/**
 * @brief Get the dhcp message type description in a given string
 * 
 * @param message_type 
 * @param desc 
 * @param verbose 
 */
void 
get_dhcp_message_type_desc(uint8_t message_type, char *desc, bool verbose)
{
    switch(message_type){
        case DHCPDISCOVER:
            if (verbose){
                snprintf(desc, MY_DHCP_OPTION_DESC_SIZE, "Discover (%d)", message_type);
            } else {
                snprintf(desc, MY_DHCP_OPTION_DESC_SIZE, "Discover");
            }
            break;
        case DHCPOFFER:
            if (verbose){
                snprintf(desc, MY_DHCP_OPTION_DESC_SIZE, "Offer (%d)", message_type);
            } else {
                snprintf(desc, MY_DHCP_OPTION_DESC_SIZE, "Offer");
            }
            break;
        case DHCPREQUEST:
            if (verbose){
                snprintf(desc, MY_DHCP_OPTION_DESC_SIZE, "Request (%d)", message_type);
            } else {
                snprintf(desc, MY_DHCP_OPTION_DESC_SIZE, "Request");
            }
            break;
        case DHCPDECLINE:
            if (verbose){
                snprintf(desc, MY_DHCP_OPTION_DESC_SIZE, "Decline (%d)", message_type);
            } else {
                snprintf(desc, MY_DHCP_OPTION_DESC_SIZE, "Decline");
            }
            break;
        case DHCPACK:
            if (verbose){
                snprintf(desc, MY_DHCP_OPTION_DESC_SIZE, "ACK (%d)", message_type);
            } else {
                snprintf(desc, MY_DHCP_OPTION_DESC_SIZE, "ACK");
            }
            break;
        case DHCPNAK:
            if (verbose){
                snprintf(desc, MY_DHCP_OPTION_DESC_SIZE, "NAK (%d)", message_type);
            } else {
                snprintf(desc, MY_DHCP_OPTION_DESC_SIZE, "NAK");
            }
            break;
        case DHCPRELEASE:
            if (verbose){
                snprintf(desc, MY_DHCP_OPTION_DESC_SIZE, "Release (%d)", message_type);
            } else {
                snprintf(desc, MY_DHCP_OPTION_DESC_SIZE, "Release");
            }
            break;
    }
}

/**
 * @brief Get the dhcp options descriptions
 * 
 * @param options 
 * @param bootp_header 
 * @param verbose 
 */
void 
get_dhcp_options_desc(uint8_t *options, my_dhcp_bootp_header_t* bootp_header, bool verbose)
{
    int write_ptr = 0;
    // stop if we reach the end of the options 0xFF or 0 (for BOOTP!!)
    while (options[write_ptr] != 0xFF && options[write_ptr] != 0){
        // create a new option to be stored in the linked list
        my_dhcp_option_t *dhcp_option = malloc(sizeof(my_dhcp_option_t));
        dhcp_option->option_code = options[write_ptr];
        dhcp_option->option_length = options[write_ptr + 1];
        switch(options[write_ptr]){
            case DHCP_MESSAGE_TYPE:
                snprintf(dhcp_option->option_code_desc, MY_DHCP_OPTION_DESC_SIZE, "DHCP Message Type (%d)", options[write_ptr]);
                dhcp_option->option_value = options[write_ptr + 2];
                get_dhcp_message_type_desc(dhcp_option->option_value, dhcp_option->option_value_desc, verbose);
                break;
            case DHCP_SUBNET_MASK:
                snprintf(dhcp_option->option_code_desc, MY_DHCP_OPTION_DESC_SIZE, "Subnet Mask (%d)", options[write_ptr]);
                inet_ntop(AF_INET, options + write_ptr + 2, dhcp_option->option_value_desc, INET_ADDRSTRLEN);
                break;
            case DHCP_TIME_OFFSET:
                snprintf(dhcp_option->option_code_desc, MY_DHCP_OPTION_DESC_SIZE, "Time Offset (%d)", options[write_ptr]);
                dhcp_option->option_value = ntohl(*(uint32_t*)(options + write_ptr + 2));
                break;
            case DHCP_ROUTER:
                snprintf(dhcp_option->option_code_desc, MY_DHCP_OPTION_DESC_SIZE, "Router (%d)", options[write_ptr]);
                inet_ntop(AF_INET, options + write_ptr + 2, dhcp_option->option_value_desc, INET_ADDRSTRLEN); // I only do the first IP address
                break;
            case DHCP_DNS:
                snprintf(dhcp_option->option_code_desc, MY_DHCP_OPTION_DESC_SIZE, "DNS (%d)", options[write_ptr]);
                inet_ntop(AF_INET, options + write_ptr + 2, dhcp_option->option_value_desc, INET_ADDRSTRLEN); // I only do the first IP address
                break;
            case DHCP_HOST_NAME:
                snprintf(dhcp_option->option_code_desc, MY_DHCP_OPTION_DESC_SIZE, "Host Name (%d)", options[write_ptr]);
                strncpy(dhcp_option->option_value_desc, (char*)(options + write_ptr + 2), dhcp_option->option_length);
                break;
            case DHCP_DOMAIN_NAME:
                snprintf(dhcp_option->option_code_desc, MY_DHCP_OPTION_DESC_SIZE, "Domain Name (%d)", options[write_ptr]);
                strncpy(dhcp_option->option_value_desc, (char*)(options + write_ptr + 2), dhcp_option->option_length);
                break;
            case DHCP_BROADCAST_ADDRESS:
                snprintf(dhcp_option->option_code_desc, MY_DHCP_OPTION_DESC_SIZE, "Broadcast Address (%d)", options[write_ptr]);
                inet_ntop(AF_INET, options + write_ptr + 2, dhcp_option->option_value_desc, INET_ADDRSTRLEN);
                break;
            case DHCP_NETBIOS_NAME_SERVER:
                snprintf(dhcp_option->option_code_desc, MY_DHCP_OPTION_DESC_SIZE, "NetBIOS Name Server (%d)", options[write_ptr]);
                inet_ntop(AF_INET, options + write_ptr + 2, dhcp_option->option_value_desc, INET_ADDRSTRLEN); // I only do the first IP address
                break;
            case DHCP_NETBIOS_SCOPE:
                snprintf(dhcp_option->option_code_desc, MY_DHCP_OPTION_DESC_SIZE, "NetBIOS Scope (%d)", options[write_ptr]);
                strncpy(dhcp_option->option_value_desc, (char*)(options + write_ptr + 2), dhcp_option->option_length);
                break;
            case DHCP_REQUESTED_IP_ADDRESS:
                snprintf(dhcp_option->option_code_desc, MY_DHCP_OPTION_DESC_SIZE, "Requested IP Address (%d)", options[write_ptr]);
                inet_ntop(AF_INET, options + write_ptr + 2, dhcp_option->option_value_desc, INET_ADDRSTRLEN);
                break;
            case DHCP_IP_ADDRESS_LEASE_TIME:
                snprintf(dhcp_option->option_code_desc, MY_DHCP_OPTION_DESC_SIZE, "IP Address Lease Time (%d)", options[write_ptr]);
                dhcp_option->option_value = ntohl(*(uint32_t*)(options + write_ptr + 2));
                break;
            case DHCP_SERVER_IDENTIFIER:
                snprintf(dhcp_option->option_code_desc, MY_DHCP_OPTION_DESC_SIZE, "Server Identifier (%d)", options[write_ptr]);
                inet_ntop(AF_INET, options + write_ptr + 2, dhcp_option->option_value_desc, INET_ADDRSTRLEN);
                break;
            case DHCP_PARAMETER_REQUEST_LIST:
                snprintf(dhcp_option->option_code_desc, MY_DHCP_OPTION_DESC_SIZE, "Parameter Request List (%d)", options[write_ptr]);
                for (int i = 0; i < dhcp_option->option_length; i++){
                    snprintf(dhcp_option->option_value_desc + i * 3, dhcp_option->option_length * 2, "%d,", options[write_ptr + 2 + i]);
                }
                break;
            case DHCP_CLIENT_IDENTIFIER:
                snprintf(dhcp_option->option_code_desc, MY_DHCP_OPTION_DESC_SIZE, "Client Identifier (%d)", options[write_ptr]);
                strncpy(dhcp_option->option_value_desc, (char*)(options + write_ptr + 2), dhcp_option->option_length);
                break;
            default:
                snprintf(dhcp_option->option_code_desc, MY_DHCP_OPTION_DESC_SIZE, "Unknown (%d)", options[write_ptr]);
                dhcp_option->option_value = 0;
                dhcp_option->option_value_desc[0] = '\0';
                break;
        }
        // add the option to the linked list
        bootp_header->dhcp_options = add_node(bootp_header->dhcp_options, (void*)dhcp_option);
        // save a pointer to the message type
        if (dhcp_option->option_code == DHCP_MESSAGE_TYPE){
            bootp_header->dhcp_message_type = bootp_header->dhcp_options;
        }
        write_ptr += options[write_ptr + 1] + 2;
    }
}

/**
 * @brief Get the bootp operation description in a given string
 * 
 * @param bp_op 
 * @param desc 
 * @param verbose 
 */
void
get_bp_op_desc(uint8_t bp_op, char *desc, bool verbose)
{
    switch(bp_op){
        case BOOTREQUEST:
            if (verbose){
                snprintf(desc, BP_OP_DESC_SIZE, "Operation: BOOTREQUEST (%d)", bp_op);
            } else {
                snprintf(desc, BP_OP_DESC_SIZE, "BOOTREQUEST");
            }
            break;
        case BOOTREPLY:
            if (verbose){
                snprintf(desc, BP_OP_DESC_SIZE, "Operation: BOOTREPLY (%d)", bp_op);
            } else {
                snprintf(desc, BP_OP_DESC_SIZE, "BOOTREPLY");
            }
            break;
        default:
            if (verbose){
                snprintf(desc, BP_OP_DESC_SIZE, "Operation: Unknown (%d)", bp_op);
            } else {
                snprintf(desc, BP_OP_DESC_SIZE, "Unknown (%d)", bp_op);
            }
            break;
    }
}