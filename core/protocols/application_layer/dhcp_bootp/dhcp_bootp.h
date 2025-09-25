#ifndef DHCP_BOOTP_H
#define DHCP_BOOTP_H

#ifdef __APPLE__
#include <netinet/bootp.h>
#endif

#ifdef __linux__
#include "lib_bootp.h"
#endif

#include <string>
#include <sstream>


#include "arp.h"
#include "ethernet.h"
#include "mac_address.h"
#include "linked_list.h"

#define PORT_BOOTPS 67
#define PORT_BOOTPC 68

// DHCP options DHCP
#define DHCP_SUBNET_MASK 1
#define DHCP_TIME_OFFSET 2
#define DHCP_ROUTER 3
#define DHCP_DNS 6
#define DHCP_HOST_NAME 12
#define DHCP_DOMAIN_NAME 15
#define DHCP_BROADCAST_ADDRESS 28
#define DHCP_NETBIOS_NAME_SERVER 44
#define DHCP_NETBIOS_SCOPE 47
#define DHCP_REQUESTED_IP_ADDRESS 50
#define DHCP_IP_ADDRESS_LEASE_TIME 51
#define DHCP_MESSAGE_TYPE 53
#define DHCP_SERVER_IDENTIFIER 54
#define DHCP_PARAMETER_REQUEST_LIST 55
#define DHCP_CLIENT_IDENTIFIER 61

// DHCP message types
#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK 5
#define DHCPNAK 6
#define DHCPRELEASE 7

typedef struct my_dhcp_option {
    uint8_t option_code;
    std::string option_code_desc;
    uint8_t option_length;
    uint8_t option_value; // if I have an interesting value to store, like the dhcp message type
    std::string option_value_desc;
} my_dhcp_option_t;

typedef struct my_dhcp_bootp_header {
    uint8_t bp_op;
    std::string bp_op_desc;

    uint8_t bp_htype; // hardware type same as ARP
    std::string bp_htype_desc;
    uint8_t bp_hlen;

    uint32_t bp_xid; // transaction ID

    uint16_t bp_secs; // seconds since boot began
    uint16_t dhcp_flags_bp_unused;

    std::string client_ip_address; // BOOTREQUEST, if known
    std::string your_ip_address;   // filled by server if client doesn't know its own address (ciaddr was 0)
    std::string server_ip_address; // returned in BOOTREPLY by server
    std::string gateway_ip_address; // optional cross-gateway booting

    std::string client_hardware_address; // client hardware address
    std::string server_host_name; // server host name (optional)

    std::string boot_file_name;  // 'generic' name or null in bootrequest,
                                   // fully qualified directory-path
                                   // name in bootreply.
    uint8_t vendor_specific_area[64]; // vendor-specific area (could be readable or not) if BOOTP
                                   // TODO: what happens if not readable ?
    uint32_t magic_cookie; // always 0x63825363
    
    // DHCP specific
    node_t *dhcp_message_type;
    
    node_t *dhcp_options;

} my_dhcp_bootp_header_t;

my_dhcp_bootp_header_t parse_bootp(uint8_t *packet, bool verbose);
void free_dhcp_bootp_header(my_dhcp_bootp_header_t *bootp_header);

// helpers
void get_dhcp_message_type_desc(uint8_t message_type, std::string& desc, bool verbose);
void get_dhcp_options_desc(uint8_t *options, my_dhcp_bootp_header_t* bootp_header, bool verbose);
void get_bp_op_desc(uint8_t bp_op, std::string& desc, bool verbose);

#endif