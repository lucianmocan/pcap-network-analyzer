#ifndef IPV4_H
#define IPV4_H

#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "mac_address.h"
#include "dscp.h"
#include "check_sum.h"

typedef struct my_ipv4_header {
    uint8_t version : 4;
    uint8_t header_length : 4;

    /*  
    ToS no longer used, DSCP and ECN instead
    DSCP: https://datatracker.ietf.org/doc/html/rfc2474#section-3
    DSCP: first 6 bits of ToS 
    */
    std::string dscp_desc;    // DSCP [0-63]
    uint8_t dscp_value;    // Description of the DSCP value

    /*
    ECN: https://datatracker.ietf.org/doc/html/rfc3168#section-5 [Page 8]
    ECN: last 2 bits of ToS
    */
    std::string ecn_desc;     // ECN [0-3]
    uint8_t ecn_value;     // Description of the ECN value

    uint16_t total_length;  
    uint16_t identification;

    /*
    flags: https://datatracker.ietf.org/doc/html/rfc791#section-3.1 [Page 13]
    flags R: 1 bit reserved, should be 0
    flags DF: 0 = May Fragment, 1 = Don't Fragment
    flags MF: 0 = Last Fragment, 1 = More Fragments
    */
    std::string flags_desc; // Description of the flags
    struct {
        uint8_t reserved: 1;
        uint8_t dont_fragment: 1;
        uint8_t more_fragments: 1;
    } flags;

    uint16_t fragment_offset;
    uint8_t time_to_live;

    uint8_t protocol;
    std::string protocol_name;

    uint16_t checksum;
    bool checksum_correct;

    uint8_t raw_source_address[4];
    uint8_t raw_destination_address[4];

    std::string source_ipv4;
    std::string destination_ipv4;

} my_ipv4_header_t;

my_ipv4_header_t parse_ipv4(const uint8_t *packet, bool verbose);

// helpers
void get_flags_desc(std::string& flags_desc, uint16_t ip_off, bool verbose);
void ipv4_get_protocol_name(uint8_t protocol, std::string& protocol_name, bool verbose);
uint16_t* build_ipv4_pseudo_header_and_packet(uint8_t *packet, int packet_len, uint8_t *src_ip, uint8_t *dst_ip, uint8_t net_protocol, int *combined_len);


#endif