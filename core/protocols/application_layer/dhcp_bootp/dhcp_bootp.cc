#include "dhcp_bootp.h"

/**
 * @brief Convert IPv4 address to string
 * 
 * @param addr Pointer to IPv4 address (in_addr or uint32_t)
 * @return std::string IP address as string
 */
std::string ipv4_to_string(const void* addr) {
    char addr_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, addr, addr_str, INET_ADDRSTRLEN) == nullptr) {
        return "0.0.0.0";  // fallback for invalid address
    }
    return std::string(addr_str);
}

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
        bootp_header.client_ip_address = ipv4_to_string(&bootp->bp_ciaddr);
    } else {
        bootp_header.client_ip_address[0] = '\0';
    }

    bootp_header.your_ip_address = ipv4_to_string(&bootp->bp_yiaddr);

    // returned in BOOTREPLY by server
    if (bootp_header.bp_op == BOOTREPLY){
        bootp_header.server_ip_address = ipv4_to_string(&bootp->bp_siaddr);
    } else {
        bootp_header.server_ip_address[0] = '\0';
    }

    // optional cross-gateway booting
    if (bootp->bp_giaddr.s_addr != 0){
        bootp_header.gateway_ip_address = ipv4_to_string(&bootp->bp_giaddr);
    } else {
        bootp_header.gateway_ip_address[0] = '\0';
    }

    bootp_header.client_hardware_address = write_mac_address(bootp->bp_chaddr);
    bootp_header.server_host_name = std::string((char*)bootp->bp_sname);
    bootp_header.boot_file_name = std::string((char*)bootp->bp_file);

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
 * @brief Free the DHCP allocated linked list
 * 
 * @param bootp_header 
 */
void 
free_dhcp_bootp_header(my_dhcp_bootp_header_t *bootp_header)
{
    free_list(bootp_header->dhcp_options);
}

/**
 * @brief Get the dhcp message type description in a given string
 * 
 * @param message_type 
 * @param desc 
 * @param verbose 
 */
void 
get_dhcp_message_type_desc(uint8_t message_type, std::string& desc, bool verbose)
{
    switch(message_type){
        case DHCPDISCOVER:
            if (verbose){
                desc = "Discover (" + std::to_string(message_type) + ")";
            } else {
                desc = "Discover";
            }
            break;
        case DHCPOFFER:
            if (verbose){
                desc = "Offer (" + std::to_string(message_type) + ")";
            } else {
                desc = "Offer";
            }
            break;
        case DHCPREQUEST:
            if (verbose){
                desc = "Request (" + std::to_string(message_type) + ")";
            } else {
                desc = "Request";
            }
            break;
        case DHCPDECLINE:
            if (verbose){
                desc = "Decline (" + std::to_string(message_type) + ")";
            } else {
                desc = "Decline";
            }
            break;
        case DHCPACK:
            if (verbose){
                desc = "ACK (" + std::to_string(message_type) + ")";
            } else {
                desc = "ACK";
            }
            break;
        case DHCPNAK:
            if (verbose){
                desc = "NAK (" + std::to_string(message_type) + ")";
            } else {
                desc = "NAK";
            }
            break;
        case DHCPRELEASE:
            if (verbose){
                desc = "Release (" + std::to_string(message_type) + ")";
            } else {
                desc = "Release";
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
        my_dhcp_option_t *dhcp_option = (my_dhcp_option_t *)malloc(sizeof(my_dhcp_option_t));
        dhcp_option->option_code = options[write_ptr];
        dhcp_option->option_length = options[write_ptr + 1];
        switch(options[write_ptr]){
            case DHCP_MESSAGE_TYPE:
                dhcp_option->option_code_desc = "DHCP Message Type (" + std::to_string(options[write_ptr]) + ")";
                dhcp_option->option_value = options[write_ptr + 2];
                get_dhcp_message_type_desc(dhcp_option->option_value, dhcp_option->option_value_desc, verbose);
                break;
            case DHCP_SUBNET_MASK:
                dhcp_option->option_code_desc = "Subnet Mask (" + std::to_string(options[write_ptr]) + ")";
                {   
                    dhcp_option->option_value_desc = ipv4_to_string(options + write_ptr + 2);
                }
                break;
            case DHCP_TIME_OFFSET:
                dhcp_option->option_code_desc = "Time Offset (" + std::to_string(options[write_ptr]) + ")";
                dhcp_option->option_value = ntohl(*(uint32_t*)(options + write_ptr + 2));
                break;
            case DHCP_ROUTER:
                dhcp_option->option_code_desc = "Router (" + std::to_string(options[write_ptr]) + ")";
                {   
                    dhcp_option->option_value_desc = ipv4_to_string(options + write_ptr + 2);
                }
                break;
            case DHCP_DNS:
                dhcp_option->option_code_desc = "DNS (" + std::to_string(options[write_ptr]) + ")";
                {
                    dhcp_option->option_value_desc = ipv4_to_string(options + write_ptr + 2);
                }
                break;
            case DHCP_HOST_NAME:
                dhcp_option->option_code_desc = "Host Name (" + std::to_string(options[write_ptr]) + ")";
                dhcp_option->option_value_desc = std::string((char*)(options + write_ptr + 2), dhcp_option->option_length);
                break;
            case DHCP_DOMAIN_NAME:
                dhcp_option->option_code_desc = "Domain Name (" + std::to_string(options[write_ptr]) + ")";
                dhcp_option->option_value_desc = std::string((char*)(options + write_ptr + 2), dhcp_option->option_length);
                break;
            case DHCP_BROADCAST_ADDRESS:
                dhcp_option->option_code_desc = "Broadcast Address (" + std::to_string(options[write_ptr]) + ")";
                {
                    dhcp_option->option_value_desc = ipv4_to_string(options + write_ptr + 2);
                }
                break;
            case DHCP_NETBIOS_NAME_SERVER:
                dhcp_option->option_code_desc = "NetBIOS Name Server (" + std::to_string(options[write_ptr]) + ")";
                {
                    dhcp_option->option_value_desc = ipv4_to_string(options + write_ptr + 2); // only the first one
                }
                break;
            case DHCP_NETBIOS_SCOPE:
                dhcp_option->option_code_desc = "NetBIOS Scope (" + std::to_string(options[write_ptr]) + ")";
                dhcp_option->option_value_desc = std::string((char*)(options + write_ptr + 2), dhcp_option->option_length);
                break;
            case DHCP_REQUESTED_IP_ADDRESS:
                dhcp_option->option_code_desc = "Requested IP Address (" + std::to_string(options[write_ptr]) + ")";
                {
                    dhcp_option->option_value_desc = ipv4_to_string(options + write_ptr + 2);
                }
                break;
            case DHCP_IP_ADDRESS_LEASE_TIME:
                dhcp_option->option_code_desc = "IP Address Lease Time (" + std::to_string(options[write_ptr]) + ")";
                dhcp_option->option_value = ntohl(*(uint32_t*)(options + write_ptr + 2));
                break;
            case DHCP_SERVER_IDENTIFIER:
                dhcp_option->option_code_desc = "Server Identifier (" + std::to_string(options[write_ptr]) + ")";
                {   
                    dhcp_option->option_value_desc = ipv4_to_string(options + write_ptr + 2);
                }
                break;
            case DHCP_PARAMETER_REQUEST_LIST:
                dhcp_option->option_code_desc = "Parameter Request List (" + std::to_string(options[write_ptr]) + ")";
                {
                    std::ostringstream oss;
                    for (int i = 0; i < dhcp_option->option_length; i++){
                        if (i > 0) oss << ",";
                        oss << static_cast<int>(options[write_ptr + 2 + i]);
                    }
                    dhcp_option->option_value_desc = oss.str();
                }
                break;
            case DHCP_CLIENT_IDENTIFIER:
                dhcp_option->option_code_desc = "Client Identifier (" + std::to_string(options[write_ptr]) + ")";
                dhcp_option->option_value_desc = std::string((char*)(options + write_ptr + 2), dhcp_option->option_length);
                break;
            default:
                dhcp_option->option_code_desc = "Unknown (" + std::to_string(options[write_ptr]) + ")";
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
get_bp_op_desc(uint8_t bp_op, std::string& desc, bool verbose)
{
    switch(bp_op){
        case BOOTREQUEST:
            if (verbose){
                desc = "Operation: BOOTREQUEST (" + std::to_string(bp_op) + ")";
            } else {
                desc = "BOOTREQUEST";
            }
            break;
        case BOOTREPLY:
            if (verbose){
                desc = "Operation: BOOTREPLY (" + std::to_string(bp_op) + ")";
            } else {
                desc = "BOOTREPLY";
            }
            break;
        default:
            if (verbose){
                desc = "Operation: Unknown (" + std::to_string(bp_op) + ")";
            } else {
                desc = "Unknown (" + std::to_string(bp_op) + ")";
            }
            break;
    }
}