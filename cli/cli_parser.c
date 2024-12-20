#include "cli_parser.h"

void
parse_cli(const struct pcap_pkthdr *pcap_header, uint8_t *packet, int verbosity){
    static int count_packets = 0;
    printf("------------------------------------------------------------------\n");
    if (verbosity == VB_MAXIMAL){
        printf("Packet %d\n", count_packets);
    }
    print_timestamp(pcap_header, verbosity);
    switch(verbosity){
        case VB_MINIMAL:
            parse_min(packet);
            break;
        case VB_MIDDLE:
            parse_mid(packet);
            break;
        case VB_MAXIMAL:
            parse_max(packet);
            break;
        default:
            break;
    }
    count_packets++;
    printf("\n");
}

void
parse_min(uint8_t *packet)
{   
    my_ethernet_header_t ethernet_header = parse_ethernet(packet, false);
    diplay_ethernet_header(ethernet_header, VB_MINIMAL);
    packet = packet + sizeof(struct ether_header);

    my_ipv4_header_t ipv4_header = {0};
    my_ipv6_header_t ipv6_header = {0};

    if (ethernet_header.type == ETHERTYPE_IP){
        ipv4_header = parse_ipv4(packet, false);
        display_ipv4_header(ipv4_header, VB_MINIMAL);
        packet = packet + ipv4_header.header_length * 4;
    } else if (ethernet_header.type == ETHERTYPE_ARP){
        my_arp_header_t arp_header = parse_arp(packet, false);
        display_arp_header(arp_header, VB_MINIMAL);
    } else if (ethernet_header.type == ETHERTYPE_IPV6){
        ipv6_header = parse_ipv6(packet, false);
        display_ipv6_header(ipv6_header, VB_MINIMAL);
        packet = packet + IPV6_HEADER_SIZE;
    } else {
        printf("\n");
    }

    my_tcp_header_t tcp_header = {0};
    my_udp_header_t udp_header = {0};

    if (!is_ipv4_header_empty(&ipv4_header)){
        printf("%s ", ipv4_header.protocol_name);
        switch (ipv4_header.protocol){
            case IPPROTO_TCP: {
                tcp_header = parse_tcp_header(packet, ipv4_header.raw_source_address, ipv4_header.raw_destination_address, ipv4_header.protocol, false);
                printf("%d > %d ", tcp_header.source_port, tcp_header.destination_port);
                packet += tcp_header.data_offset * 4;
                break;
            }
            case IPPROTO_UDP: {
                udp_header = parse_udp(packet, ipv4_header.raw_source_address, ipv4_header.raw_destination_address, ipv4_header.protocol, false);
                printf("%d > %d ", udp_header.source_port, udp_header.destination_port);
                packet += sizeof(struct udphdr);
                break;
            }
            case IPPROTO_ICMP: {
                my_icmp_t icmp_header = parse_icmp(packet, ipv4_header.total_length - ipv4_header.header_length, false);
                printf("%s ", icmp_header.icmp_type_desc);
                printf("%s ", icmp_header.icmp_code_desc);
                break;
            }
            default:
                break;
        }
    } else
    if(!is_ipv6_header_empty(&ipv6_header)){
        printf("%s ", ipv6_header.next_header_name);
        switch(ipv6_header.next_header){
            case IPPROTO_TCP: {
                tcp_header = parse_tcp_header(packet, ipv6_header.raw_source_address, ipv6_header.raw_destination_address, ipv6_header.next_header, false);
                printf("%d > %d ", tcp_header.source_port, tcp_header.destination_port);
                packet += tcp_header.data_offset * 4;
                break;
            }
            case IPPROTO_UDP: {
                udp_header = parse_udp(packet, ipv6_header.raw_source_address, ipv6_header.raw_destination_address, ipv6_header.next_header, false);
                printf("%d > %d ", udp_header.source_port, udp_header.destination_port);
                packet += sizeof(struct udphdr);
                break;
            }
            case IPPROTO_ICMPV6: {
                my_icmpv6_t icmpv6_header = parse_icmpv6(packet, ipv6_header.payload_length, ipv6_header.raw_source_address, ipv6_header.raw_destination_address, false);
                printf("%s ", icmpv6_header.icmpv6_type_desc);
                if (icmpv6_header.type == ND_NEIGHBOR_SOLICIT){
                    printf("%s ", icmpv6_header.payload);
                }
                free_parse_icmpv6(&icmpv6_header);
                break;
            }
            default:
                break;
        }
    }
    if (!is_tcp_header_empty(&tcp_header)){
        printf("%s ", tcp_header.tcp_flags_desc);
        switch(tcp_header.destination_port){
            case PORT_DNS: {
                my_dns_header_t dns_header = parse_dns(packet, false);
                display_dns_header(dns_header, VB_MINIMAL);
                free_dns_header(&dns_header);
                break;
            }
            default:
                break;
        }
    } else
    if (!is_udp_header_empty(&udp_header)){
        switch(udp_header.destination_port){
            case PORT_BOOTPC:
            case PORT_BOOTPS: {
                printf("BOOTP/DHCP ");
                my_dhcp_bootp_header_t dhcp_header = parse_bootp(packet, false);
                printf("%s ", dhcp_header.bp_op_desc);
                (dhcp_header.bp_op == BOOTREQUEST) ? printf("from %s ", dhcp_header.client_ip_address) : printf("to %s ", dhcp_header.your_ip_address);
                free_dhcp_bootp_header(&dhcp_header);
                break;
            }
            case PORT_DNS: {
                my_dns_header_t dns_header = parse_dns(packet, false);
                display_dns_header(dns_header, VB_MINIMAL);
                free_dns_header(&dns_header);
                break;
            }
            default:
                break;
        }

    }


}

void
parse_mid(uint8_t *packet)
{   
    my_ethernet_header_t ethernet_header = parse_ethernet(packet, false);
    diplay_ethernet_header(ethernet_header, VB_MIDDLE);

    my_ipv4_header_t ipv4_header = {0};
    my_ipv6_header_t ipv6_header = {0};

    packet = packet + sizeof(struct ether_header);
    if (ethernet_header.type == ETHERTYPE_IP){
        ipv4_header = parse_ipv4(packet, false);
        display_ipv4_header(ipv4_header, VB_MIDDLE);
        packet = packet + ipv4_header.header_length * 4;
    } else if (ethernet_header.type == ETHERTYPE_ARP){
        my_arp_header_t arp_header = parse_arp(packet, false);
        display_arp_header(arp_header, VB_MIDDLE);
    } else if (ethernet_header.type == ETHERTYPE_IPV6){
        ipv6_header = parse_ipv6(packet, false);
        display_ipv6_header(ipv6_header, VB_MIDDLE);
        packet = packet + IPV6_HEADER_SIZE;
    } else {
        printf("\n");
    }

    my_tcp_header_t tcp_header = {0};
    my_udp_header_t udp_header = {0};

    if (!is_ipv4_header_empty(&ipv4_header)){
        printf("%s ", ipv4_header.protocol_name);
        switch (ipv4_header.protocol){
            case IPPROTO_TCP: {
                tcp_header = parse_tcp_header(packet, ipv4_header.raw_source_address, ipv4_header.raw_destination_address, ipv4_header.protocol, false);
                printf("%d > %d | ", tcp_header.source_port, tcp_header.destination_port);
                printf("%s | ", tcp_header.tcp_flags_desc);
                printf("Window: %d | ", tcp_header.window);
                printf("Checksum: %x ", tcp_header.checksum);
                (tcp_header.checksum_correct) ? printf("(correct) \n") : printf("(incorrect) calculated: %x\n", tcp_header.calculated_checksum);
                packet += tcp_header.data_offset * 4;
                break;
            }
            case IPPROTO_UDP: {
                udp_header = parse_udp(packet, ipv4_header.raw_source_address, ipv4_header.raw_destination_address, ipv4_header.protocol, false);
                printf("%d > %d ", udp_header.source_port, udp_header.destination_port);
                printf("Length: %d | ", udp_header.length);
                printf("Checksum: %x  ", udp_header.checksum);
                (udp_header.checksum_correct) ? printf("(correct) \n") : printf("(incorrect) calculated: %x\n", udp_header.calculated_checksum);
                packet += sizeof(struct udphdr);
                break;
            }
            case IPPROTO_ICMP: {
                my_icmp_t icmp_header = parse_icmp(packet, ipv4_header.total_length - ipv4_header.header_length, false);
                printf("Type: %s |", icmp_header.icmp_type_desc);
                printf("Code: %s |", icmp_header.icmp_code_desc);
                printf("Identifier: %d | ", icmp_header.identifier);
                printf("Checksum: %x ", icmp_header.checksum);
                (icmp_header.checksum_valid) ? printf("(correct) \n") : printf("(incorrect) calculated: %x\n", icmp_header.calculated_checksum);
                break;
            }
            default:
                break;
        }
    } else
    if(!is_ipv6_header_empty(&ipv6_header)){
        printf("%s ", ipv6_header.next_header_name);
        switch(ipv6_header.next_header){
            case IPPROTO_TCP: {
                tcp_header = parse_tcp_header(packet, ipv6_header.raw_source_address, ipv6_header.raw_destination_address, ipv6_header.next_header, false);
                printf("%s | ", tcp_header.tcp_flags_desc);
                printf("Window: %d | ", tcp_header.window);
                printf("Checksum: %x ", tcp_header.checksum);
                (tcp_header.checksum_correct) ? printf("(correct) \n") : printf("(incorrect) calculated: %x\n", tcp_header.calculated_checksum);
                packet += tcp_header.data_offset * 4;
                break;
            }
            case IPPROTO_UDP: {
                udp_header = parse_udp(packet, ipv6_header.raw_source_address, ipv6_header.raw_destination_address, ipv6_header.next_header, false);
                printf("%d > %d ", udp_header.source_port, udp_header.destination_port);
                printf("Length: %d | ", udp_header.length);
                printf("Checksum: %x  ", udp_header.checksum);
                (udp_header.checksum_correct) ? printf("(correct) \n") : printf("(incorrect) calculated: %x\n", udp_header.calculated_checksum);
                packet += sizeof(struct udphdr);
                break;
            }
            case IPPROTO_ICMPV6: {
                my_icmpv6_t icmpv6_header = parse_icmpv6(packet, ipv6_header.payload_length, ipv6_header.raw_source_address, ipv6_header.raw_destination_address, false);
                printf("Type: %s | ", icmpv6_header.icmpv6_type_desc);
                printf("Code: %s | ", icmpv6_header.icmpv6_code_desc);
                printf("Identifier: %d | ", icmpv6_header.identifier);
                if (icmpv6_header.type == ND_NEIGHBOR_SOLICIT){
                    printf("Target address: %s | ", icmpv6_header.payload);
                }
                printf("Checksum: %x ", icmpv6_header.checksum);
                (icmpv6_header.checksum_valid) ? printf("(correct) \n") : printf("(incorrect) calculated: %x\n", icmpv6_header.calculated_checksum);
                free_parse_icmpv6(&icmpv6_header);
                break;
            }
            default:
                break;
        }
    }
    if (!is_tcp_header_empty(&tcp_header)){
        switch(tcp_header.destination_port){
            case PORT_DNS: {
                my_dns_header_t dns_header = parse_dns(packet, false);
                printf("xid: %d | ", dns_header.transaction_id);
                printf("op: %s | ", dns_header.opcode_desc);
                printf("questions count: %d | ", dns_header.qdcount);
                printf("answers count: %d | ", dns_header.ancount);
                printf("authority count: %d | ", dns_header.nscount);
                printf("additional count: %d \n", dns_header.arcount);
                free_dns_header(&dns_header);
                break;
            }
            default:
                break;
        }
    } else
    if (!is_udp_header_empty(&udp_header)){
        switch(udp_header.destination_port){
            case PORT_BOOTPC:
            case PORT_BOOTPS: {
                printf("BOOTP/DHCP ");
                my_dhcp_bootp_header_t dhcp_header = parse_bootp(packet, false);
                printf("%s | ", dhcp_header.bp_op_desc);
                (dhcp_header.bp_op == BOOTREQUEST) ? printf("from %s | ", dhcp_header.client_ip_address) : printf("to %s | ", dhcp_header.your_ip_address);
                printf("xid: %d | ", dhcp_header.bp_xid);
                printf("Client HADDR: %s | ", dhcp_header.client_hardware_address);
                printf("Server host name: %s \n", dhcp_header.server_host_name);
                free_dhcp_bootp_header(&dhcp_header);
                break;
            }
            case PORT_DNS: {
                printf("DNS ");
                my_dns_header_t dns_header = parse_dns(packet, false);
                printf("xid: %d | ", dns_header.transaction_id);
                printf("op: %s | ", dns_header.opcode_desc);
                printf("questions count: %d | ", dns_header.qdcount);
                printf("answers count: %d | ", dns_header.ancount);
                printf("authority count: %d | ", dns_header.nscount);
                printf("additional count: %d \n", dns_header.arcount);
                free_dns_header(&dns_header);
                break;
            }
            default:
                break;
        }

    }
}


/**
 * @brief Display the ethernet header
 * 
 * @param ethernet_header 
 * @param verbosity 
 * @return * void 
 */
void
diplay_ethernet_header(my_ethernet_header_t ethernet_header, int verbosity)
{
    switch(verbosity){
        case VB_MINIMAL: {
            printf("%s > %s ", ethernet_header.src_mac, ethernet_header.dst_mac);
            printf("%s ", ethernet_header.type_desc);
            break;
        }
        case VB_MIDDLE: {
            printf("Ethernet: src: %s > dst: %s %s\n", ethernet_header.src_mac, ethernet_header.dst_mac, ethernet_header.type_desc);
            break;
        }
        case VB_MAXIMAL: {
            printf("Ethernet ---------------------------------------------------------\n");
            printf("|   Source MAC: %s\n", ethernet_header.src_mac);
            printf("|   Destination MAC: %s\n", ethernet_header.dst_mac);
            printf("|   Type: %s (%d)\n", ethernet_header.type_desc, ethernet_header.type);
            printf("|   is vlan_tagged: %s\n", (ethernet_header.vlan_tagged) ? "yes" : "no");
            if (ethernet_header.vlan_tagged){
                printf("|       VLAN ID: %d\n", ethernet_header.vlan_id);
                printf("|       PCP: %d\n", ethernet_header.pcp);
                printf("|       DEI: %d\n", ethernet_header.dei);
                printf("|       Type VLAN: %d\n", ethernet_header.type_vlan);
                printf("|       Type VLAN Description: %s\n", ethernet_header.type_desc_vlan);
            }
            break;
        }
    }
}

void
display_ipv4_header(my_ipv4_header_t ipv4_header, int verbosity)
{
    switch(verbosity){
        case VB_MINIMAL:{
            printf(" %s > %s ", ipv4_header.source_ipv4, ipv4_header.destination_ipv4);
            break;
        }
        case VB_MIDDLE:{
            printf("IPv4: %s > %s | ", ipv4_header.source_ipv4, ipv4_header.destination_ipv4);
            printf("Checksum: %x ", ipv4_header.checksum);
            (ipv4_header.checksum_correct) ? printf("(correct) | ") : printf("(incorrect) | ");
            printf("TTL: %d | ", ipv4_header.time_to_live);
            printf("ID: %d\n", ipv4_header.identification);
            break;
        }
        case VB_MAXIMAL:{
            printf("|\n|   IPv4 ---------------------------------------------------------\n");
            printf("|   |   Source IP: %s\n", ipv4_header.source_ipv4);
            printf("|   |   Destination IP: %s\n", ipv4_header.destination_ipv4);
            printf("|   |   Version: %d\n", ipv4_header.version);
            printf("|   |   Header Length: %d\n", ipv4_header.header_length);
            printf("|   |   DSCP: %s (%d)\n", ipv4_header.dscp_desc, ipv4_header.dscp_value);
            printf("|   |   ECN: %s (%d)\n", ipv4_header.ecn_desc, ipv4_header.ecn_value);
            printf("|   |   Total Length: %d\n", ipv4_header.total_length);
            printf("|   |   Identification: %d\n", ipv4_header.identification);
            printf("|   |   Flags: %s \n", ipv4_header.flags_desc);
            printf("|   |   Fragment Offset: %d\n", ipv4_header.fragment_offset);
            printf("|   |   TTL: %d\n", ipv4_header.time_to_live);
            printf("|   |   Protocol: %d (%s)\n", ipv4_header.protocol, ipv4_header.protocol_name);
            printf("|   |   Checksum: 0x%x\n", ipv4_header.checksum);
            printf("|   |   is Checksum correct: %s\n", (ipv4_header.checksum_correct) ? "yes" : "no");
            printf("|   |   Source IP (raw): %d.%d.%d.%d\n", ipv4_header.raw_source_address[0], ipv4_header.raw_source_address[1], ipv4_header.raw_source_address[2], ipv4_header.raw_source_address[3]);
            printf("|   |   Destination IP (raw): %d.%d.%d.%d\n", ipv4_header.raw_destination_address[0], ipv4_header.raw_destination_address[1], ipv4_header.raw_destination_address[2], ipv4_header.raw_destination_address[3]);
            break;
        }
    }
}


void
display_arp_header(my_arp_header_t arp_header, int verbosity)
{
    switch(verbosity){
        case VB_MINIMAL:{
            printf("%s ", arp_header.operation_desc);
            if (arp_header.operation == ARPOP_REQUEST){
                printf("Who has %s ? Tell %s ", arp_header.target_protocol_address, arp_header.sender_protocol_address);
            } else if (arp_header.operation == ARPOP_REPLY){
                printf("%s is at %s ", arp_header.sender_protocol_address, arp_header.sender_hardware_address);
            }
            break;
        }
        case VB_MIDDLE:{
            printf("ARP: %s | ", arp_header.operation_desc);
            if (arp_header.operation == ARPOP_REQUEST){
                printf("Who has %s ? Tell %s \n", arp_header.target_protocol_address, arp_header.sender_protocol_address);
            } else if (arp_header.operation == ARPOP_REPLY){
                printf("%s is at %s \n", arp_header.sender_protocol_address, arp_header.sender_hardware_address);
            }
        }
        case VB_MAXIMAL:{
            printf("|\n|   ARP ----------------------------------------------------------\n");
            printf("|   |   Operation: %s (%d)\n", arp_header.operation_desc, arp_header.operation);
            printf("|   |   Hardware Type: %s (%d)\n", arp_header.hardware_type_desc, arp_header.hardware_type);
            printf("|   |   Protocol Type: %s (%d)\n", arp_header.protocol_type_desc, arp_header.protocol_type);
            printf("|   |   Hardware Address Length: %d\n", arp_header.hardware_address_length);
            printf("|   |   Protocol Length: %d\n", arp_header.protocol_length);
            printf("|   |   Sender Hardware Address: %s\n", arp_header.sender_hardware_address);
            printf("|   |   Sender Protocol Address: %s\n", arp_header.sender_protocol_address);
            printf("|   |   Target Hardware Address: %s\n", arp_header.target_hardware_address);
            printf("|   |   Target Protocol Address: %s\n", arp_header.target_protocol_address);
            if (arp_header.operation == ARPOP_REQUEST){
                printf("|   |   Who has %s ? Tell %s \n", arp_header.target_protocol_address, arp_header.sender_protocol_address);
            } else if (arp_header.operation == ARPOP_REPLY){
                printf("|   |   %s is at %s \n", arp_header.sender_protocol_address, arp_header.sender_hardware_address);
            }
        }
    }
}


void
display_ipv6_header(my_ipv6_header_t ipv6_header, int verbosity)
{
    switch(verbosity){
        case VB_MINIMAL:{
            printf(" %s > %s ", ipv6_header.source_address, ipv6_header.destination_address);
            break;
        }
        case VB_MIDDLE:{
            printf("IPv6: %s > %s | ", ipv6_header.source_address, ipv6_header.destination_address);
            printf("Hop Limit: %d | ", ipv6_header.hop_limit);
            printf("Flow Label: %d | ", ipv6_header.flow_label);
            printf("Payload Length: %d\n", ipv6_header.payload_length);
            break;
        }
        case VB_MAXIMAL:{
            printf("|\n|   IPv6 ---------------------------------------------------------\n");
            printf("|   |   Source IP: %s\n", ipv6_header.source_address);
            printf("|   |   Destination IP: %s\n", ipv6_header.destination_address);
            printf("|   |   Version: %d\n", ipv6_header.version);
            printf("|   |   Traffic Class: %d\n", ipv6_header.traffic_class);
            printf("|   |   Flow Label: %d\n", ipv6_header.flow_label);
            printf("|   |   Payload Length: %d\n", ipv6_header.payload_length);
            printf("|   |   Next Header: %d (%s)\n", ipv6_header.next_header, ipv6_header.next_header_name);
            printf("|   |   Hop Limit: %d\n", ipv6_header.hop_limit);
            printf("|   |   Source IP (raw): ");
            for (int i = 0; i < IPV6_INT8_ADDR_SIZE; i++){
                printf(" %02x", ipv6_header.raw_source_address[i]);
            }
            printf("\n");
            printf("|   |   Destination IP (raw): ");
            for (int i = 0; i < IPV6_INT8_ADDR_SIZE; i++){
                printf(" %02x", ipv6_header.raw_destination_address[i]);
            }
            printf("\n");
            break;
        }
    }
}


void
display_dns_header(my_dns_header_t dns_header, int verbosity)
{
    switch(verbosity){
        case VB_MINIMAL:{
            printf("%d ", dns_header.transaction_id);
            printf("%s ", dns_header.opcode_desc);
            printf("qd: %d ", dns_header.qdcount);
            break;
        }
    }
}

void
parse_max(uint8_t *packet)
{
    my_ethernet_header_t ethernet_header = parse_ethernet(packet, true);
    diplay_ethernet_header(ethernet_header, VB_MAXIMAL);

    my_ipv4_header_t ipv4_header = {0};
    my_ipv6_header_t ipv6_header = {0};

    packet = packet + sizeof(struct ether_header);
    if (ethernet_header.type == ETHERTYPE_IP){
        ipv4_header = parse_ipv4(packet, true);
        display_ipv4_header(ipv4_header, VB_MAXIMAL);
        packet = packet + ipv4_header.header_length * 4;
    } else if (ethernet_header.type == ETHERTYPE_ARP){
        my_arp_header_t arp_header = parse_arp(packet, true);
        display_arp_header(arp_header, VB_MAXIMAL);
    } else if (ethernet_header.type == ETHERTYPE_IPV6){
        ipv6_header = parse_ipv6(packet, true);
        display_ipv6_header(ipv6_header, VB_MAXIMAL);
        packet = packet + IPV6_HEADER_SIZE;
    } else {
        printf("\n");
    }

    my_tcp_header_t tcp_header = {0};
    my_udp_header_t udp_header = {0};
    printf("|   |\n");
    if (!is_ipv4_header_empty(&ipv4_header)){
        switch (ipv4_header.protocol){
            case IPPROTO_TCP: {
                printf("|   |   %s ----------------------\n", ipv4_header.protocol_name);
                tcp_header = parse_tcp_header(packet, ipv4_header.raw_source_address, ipv4_header.raw_destination_address, ipv4_header.protocol, true);
                printf("|   |   |   Source Port: %d (0x%x)\n", tcp_header.source_port, tcp_header.source_port);
                printf("|   |   |   Destination Port: %d (0x%x)\n", tcp_header.destination_port, tcp_header.destination_port);
                printf("|   |   |   Sequence Number: %u\n", tcp_header.sequence_number);
                printf("|   |   |   Acknowledgment Number: %u\n", tcp_header.acknowledgment_number);
                printf("|   |   |   Data Offset: %d\n", tcp_header.data_offset);
                printf("|   |   |   Flags: %s (%d)\n", tcp_header.tcp_flags_desc, tcp_header.flags);
                printf("|   |   |   Window: %d\n", tcp_header.window);
                printf("|   |   |   Checksum: 0x%x %s\n", tcp_header.checksum, (tcp_header.checksum_correct) ? "(correct)" : "(incorrect)");
                printf("|   |   |   Urgent Pointer: %d\n", tcp_header.urgent_pointer);
                printf("|   |   |   Options: %s\n", tcp_header.tcp_options_desc);
                packet += tcp_header.data_offset * 4;
                break;
            }
            case IPPROTO_UDP: {
                printf("|   |   %s ----------------------------\n", ipv4_header.protocol_name);
                udp_header = parse_udp(packet, ipv4_header.raw_source_address, ipv4_header.raw_destination_address, ipv4_header.protocol, true);
                printf("|   |   |   Source Port: %d (0x%x)\n", udp_header.source_port, udp_header.source_port);
                printf("|   |   |   Destination Port: %d (0x%x)\n", udp_header.destination_port, udp_header.destination_port);
                printf("|   |   |   Length: %d\n", udp_header.length);
                printf("|   |   |   Checksum: 0x%x %s\n", udp_header.checksum, (udp_header.checksum_correct) ? "(correct)" : "(incorrect)");
                packet += sizeof(struct udphdr);
                break;
            }
            case IPPROTO_ICMP: {
                printf("|   |   %s  ------------------\n", ipv4_header.protocol_name);
                int packet_length = ipv4_header.total_length - ipv4_header.header_length;
                my_icmp_t icmp_header = parse_icmp(packet, packet_length, true);
                printf("|   |   |   Type: %s (%d)\n", icmp_header.icmp_type_desc, icmp_header.type);
                printf("|   |   |   Code: %s (%d)\n", icmp_header.icmp_code_desc, icmp_header.code);
                printf("|   |   |   Checksum: 0x%x %s\n", icmp_header.checksum, (icmp_header.checksum_valid) ? "(correct)" : "(incorrect)");
                if (icmp_header.type == ICMP_ECHO || icmp_header.type == ICMP_ECHOREPLY){
                    printf("|   |   |   Identifier: %d\n", icmp_header.identifier);
                    printf("|   |   |   Sequence Number: %d\n", icmp_header.sequence_number);
                    printf("|   |   |   Data: %s\n", (char*)&icmp_header.payload[33]);
                }
                if (icmp_header.type == ICMP_UNREACH){
                    printf("|   |   |   Original IP Header: \n");
                    printf("|   |   |   |   Version: %d\n", icmp_header.og_ip_header.version);
                    printf("|   |   |   |   Header Length: %d\n", icmp_header.og_ip_header.header_length);
                    printf("|   |   |   |   DSCP: %s (%d)\n", icmp_header.og_ip_header.dscp_desc, icmp_header.og_ip_header.dscp_value);
                    printf("|   |   |   |   ECN: %s (%d)\n", icmp_header.og_ip_header.ecn_desc, icmp_header.og_ip_header.ecn_value);
                    printf("|   |   |   |   Total Length: %d\n", icmp_header.og_ip_header.total_length);
                    printf("|   |   |   |   Identification: %d\n", icmp_header.og_ip_header.identification);
                    printf("|   |   |   |   Flags: %s \n", icmp_header.og_ip_header.flags_desc);
                    printf("|   |   |   |   Fragment Offset: %d\n", icmp_header.og_ip_header.fragment_offset);
                    printf("|   |   |   |   TTL: %d\n", icmp_header.og_ip_header.time_to_live);
                    printf("|   |   |   |   Protocol: %d (%s)\n", icmp_header.og_ip_header.protocol, icmp_header.og_ip_header.protocol_name);
                    printf("|   |   |   |   Checksum: 0x%x %s\n", icmp_header.og_ip_header.checksum, (icmp_header.og_ip_header.checksum_correct) ? "(correct)" : "(incorrect)");
                    printf("|   |   |   |   Source IP: %s\n", icmp_header.og_ip_header.source_ipv4);
                    printf("|   |   |   |   Destination IP: %s\n", icmp_header.og_ip_header.destination_ipv4);
                }
                break;
            }
            default:
                break;
        }
    } else
    if(!is_ipv6_header_empty(&ipv6_header)){
        switch(ipv6_header.next_header){
            case IPPROTO_TCP: {
                printf("|   |   %s ----------------------\n", ipv6_header.next_header_name);
                tcp_header = parse_tcp_header(packet, ipv6_header.raw_source_address, ipv6_header.raw_destination_address, ipv6_header.next_header, true);
                printf("|   |   |   Source Port: %d (0x%x)\n", tcp_header.source_port, tcp_header.source_port);
                printf("|   |   |   Destination Port: %d (0x%x)\n", tcp_header.destination_port, tcp_header.destination_port);
                printf("|   |   |   Sequence Number: %u\n", tcp_header.sequence_number);
                printf("|   |   |   Acknowledgment Number: %u\n", tcp_header.acknowledgment_number);
                printf("|   |   |   Data Offset: %d\n", tcp_header.data_offset);
                printf("|   |   |   Flags: %s (%d)\n", tcp_header.tcp_flags_desc, tcp_header.flags);
                printf("|   |   |   Window: %d\n", tcp_header.window);
                printf("|   |   |   Checksum: 0x%x %s\n", tcp_header.checksum, (tcp_header.checksum_correct) ? "(correct)" : "(incorrect)");
                printf("|   |   |   Urgent Pointer: %d\n", tcp_header.urgent_pointer);
                printf("|   |   |   Options: %s\n", tcp_header.tcp_options_desc);
                packet += tcp_header.data_offset * 4;
                break;
            }
            case IPPROTO_UDP: {
                printf("|   |   %s ----------------------------\n", ipv6_header.next_header_name);
                udp_header = parse_udp(packet, ipv6_header.raw_source_address, ipv6_header.raw_destination_address, ipv6_header.next_header, true);
                printf("|   |   |   Source Port: %d (0x%x)\n", udp_header.source_port, udp_header.source_port);
                printf("|   |   |   Destination Port: %d (0x%x)\n", udp_header.destination_port, udp_header.destination_port);
                printf("|   |   |   Length: %d\n", udp_header.length);
                printf("|   |   |   Checksum: 0x%x %s\n", udp_header.checksum, (udp_header.checksum_correct) ? "(correct)" : "(incorrect)");
                packet += sizeof(struct udphdr);
                break;
            }
            case IPPROTO_ICMPV6: {
                printf("|   |   %s ----------------\n", ipv6_header.next_header_name);
                my_icmpv6_t icmpv6_header = parse_icmpv6(packet, ipv6_header.payload_length, ipv6_header.raw_source_address, ipv6_header.raw_destination_address, true);
                printf("|   |   |   Type: %s (%d)\n", icmpv6_header.icmpv6_type_desc, icmpv6_header.type);
                printf("|   |   |   Code: %s (%d)\n", icmpv6_header.icmpv6_code_desc, icmpv6_header.code);
                printf("|   |   |   Checksum: 0x%x %s\n", icmpv6_header.checksum, (icmpv6_header.checksum_valid) ? "(correct)" : "(incorrect)");
                if (icmpv6_header.type == ICMP_ECHO || icmpv6_header.type == ICMP_ECHOREPLY){
                    printf("|   |   |   Identifier: %d\n", icmpv6_header.identifier);
                    printf("|   |   |   Sequence Number: %d\n", icmpv6_header.sequence_number);
                    printf("|   |   |   Data: %s\n", (char*)&icmpv6_header.payload[33]);
                }
                if (icmpv6_header.type == ICMP_UNREACH){
                    printf("|   |   |   Original IP Header: \n");
                    printf("|   |   |   |   Version: %d\n", icmpv6_header.og_ipv6_header.version);
                    printf("|   |   |   |   Traffic Class: %d\n", icmpv6_header.og_ipv6_header.traffic_class);
                    printf("|   |   |   |   Flow Label: %d\n", icmpv6_header.og_ipv6_header.flow_label);
                    printf("|   |   |   |   Payload Length: %d\n", icmpv6_header.og_ipv6_header.payload_length);
                    printf("|   |   |   |   Next Header: %d (%s)\n", icmpv6_header.og_ipv6_header.next_header, icmpv6_header.og_ipv6_header.next_header_name);
                    printf("|   |   |   |   Hop Limit: %d\n", icmpv6_header.og_ipv6_header.hop_limit);
                    printf("|   |   |   |   Source IP: %s\n", icmpv6_header.og_ipv6_header.source_address);
                    printf("|   |   |   |   Destination IP: %s\n", icmpv6_header.og_ipv6_header.destination_address);
                }
                if (icmpv6_header.type == ND_NEIGHBOR_SOLICIT){
                    printf("|   |   |   Target address: %s\n", icmpv6_header.payload);
                }
                free_parse_icmpv6(&icmpv6_header);
                break;
            }
            default:
                break;
        }
    }
    printf("|   |   |\n");
    if (!is_tcp_header_empty(&tcp_header)){
        switch(tcp_header.destination_port){
            case PORT_DNS: {
                my_dns_header_t dns_header = parse_dns(packet, true);
                printf("|   |   |  DNS ---------------------------------------------------------\n");
                printf("|   |   |   |   Transaction-ID: %d (0x%x)\n", dns_header.transaction_id, dns_header.transaction_id);
                printf("|   |   |   |   Opcode: %s (%d)\n", dns_header.opcode_desc, dns_header.opcode);
                if (dns_header.aa) printf("|   |   |   |   %s: %s\n", dns_header.aa_desc, (dns_header.aa) ? "yes" : "no");
                if (dns_header.tc) printf("|   |   |   |   %s: %s\n", dns_header.tc_desc, (dns_header.tc) ? "yes" : "no");
                if (dns_header.rd) printf("|   |   |   |   %s: %s\n", dns_header.rd_desc, (dns_header.rd) ? "yes" : "no");
                if (dns_header.ra) printf("|   |   |   |   %s: %s\n", dns_header.ra_desc, (dns_header.ra) ? "yes" : "no");
                printf("|   |   |   |   Error code: %s: %d\n", dns_header.rcode_desc, dns_header.rcode);
                printf("|   |   |   |   Questions count: %d \n", dns_header.qdcount);
                printf("|   |   |   |   Answers count: %d \n", dns_header.ancount);
                printf("|   |   |   |   Authority count: %d \n", dns_header.nscount);
                printf("|   |   |   |   Additional count: %d \n", dns_header.arcount);

                node_t *tmp = dns_header.question_section;
                int question_count = 0;
                while (tmp != NULL){
                    question_section_t *question = (question_section_t*)tmp->data;
                    printf("|   |   |   |   Question (%d): \n", question_count);
                    printf("|   |   |   |   |   Name: %s\n", question->qname);
                    printf("|   |   |   |   |   Type: %s (%d)\n", question->qtype_desc, question->qtype);
                    printf("|   |   |   |   |   Class: %s (%d)\n", question->qclass_desc, question->qclass);
                    question_count++;
                    tmp = tmp->next;
                }

                tmp = dns_header.answer_section;
                int answer_count = 0;
                while (tmp != NULL){
                    resource_record_t *answer = (resource_record_t*)tmp->data;
                    printf("|   |   |   |   Answer (%d): \n", answer_count);
                    printf("|   |   |   |   |   Name: %s\n", answer->name);
                    printf("|   |   |   |   |   Type: %s (%d)\n", answer->type_desc, answer->type);
                    printf("|   |   |   |   |   Class: %s (%d)\n", answer->class_desc, answer->class);
                    printf("|   |   |   |   |   TTL: %d\n", answer->ttl);
                    printf("|   |   |   |   |   Data length: %d\n", answer->rdlength);
                    printf("|   |   |   |   |   Data: %s\n", answer->rdata_desc);
                    answer_count++;
                    tmp = tmp->next;
                }

                tmp = dns_header.authority_section;
                int authority_count = 0;
                while (tmp != NULL){
                    resource_record_t *authority = (resource_record_t*)tmp->data;
                    printf("|   |   |   |   Authority (%d): \n", authority_count);
                    printf("|   |   |   |   |   Name: %s\n", authority->name);
                    printf("|   |   |   |   |   Type: %s (%d)\n", authority->type_desc, authority->type);
                    printf("|   |   |   |   |   Class: %s (%d)\n", authority->class_desc, authority->class);
                    printf("|   |   |   |   |   TTL: %d\n", authority->ttl);
                    printf("|   |   |   |   |   Data length: %d\n", authority->rdlength);
                    printf("|   |   |   |   |   Data: %s\n", authority->rdata_desc);
                    authority_count++;
                    tmp = tmp->next;
                }

                tmp = dns_header.additional_section;
                int additional_count = 0;
                while (tmp != NULL){
                    resource_record_t *additional = (resource_record_t*)tmp->data;
                    printf("|   |   |   |   Additional (%d): \n", additional_count);
                    printf("|   |   |   |   |   Name: %s\n", additional->name);
                    printf("|   |   |   |   |   Type: %s (%d)\n", additional->type_desc, additional->type);
                    printf("|   |   |   |   |   Class: %s (%d)\n", additional->class_desc, additional->class);
                    printf("|   |   |   |   |   TTL: %d\n", additional->ttl);
                    printf("|   |   |   |   |   Data length: %d\n", additional->rdlength);
                    printf("|   |   |   |   |   Data: %s\n", additional->rdata_desc);
                    additional_count++;
                    tmp = tmp->next;
                }
                free_dns_header(&dns_header);
                break;
            }
            default:
                break;
        }
    } else
    if (!is_udp_header_empty(&udp_header)){
        switch(udp_header.destination_port){
            case PORT_BOOTPC:
            case PORT_BOOTPS: {
                printf("|   |   |  BOOTP/DHCP --------------------------------------------------\n");
                my_dhcp_bootp_header_t dhcp_header = parse_bootp(packet, true);
                printf("|   |   |   |   Option: %s (%d) \n", dhcp_header.bp_op_desc, dhcp_header.bp_op);
                printf("|   |   |   |   Hardware type: %s (%d) \n", dhcp_header.bp_htype_desc, dhcp_header.bp_htype);
                printf("|   |   |   |   Hardware address length: %d \n", dhcp_header.bp_hlen);
                printf("|   |   |   |   Transaction-ID: %d \n", dhcp_header.bp_xid);
                printf("|   |   |   |   Seconds elapsed: %d \n", dhcp_header.bp_secs);
                (dhcp_header.dhcp_flags_bp_unused & 0x8000) ? printf("|   |   |   |   Broadcast flag: set \n") : printf("|   |   |   |   Broadcast flag: not set \n");
                
                (dhcp_header.bp_op == BOOTREQUEST) ? printf("|   |   |   |   Client IP address: %s \n", dhcp_header.client_ip_address) : printf("|   |   |   |   Your IP address: %s \n", dhcp_header.your_ip_address);
                (dhcp_header.bp_op == BOOTREPLY) ? printf("|   |   |   |   Server IP address: %s \n", dhcp_header.server_ip_address) : printf("|   |   |   |   Gateway IP address: %s \n", dhcp_header.gateway_ip_address);
                printf("|   |   |   |   Client hardware address: %s \n", dhcp_header.client_hardware_address);
                printf("|   |   |   |   Server host name: %s \n", dhcp_header.server_host_name);
                printf("|   |   |   |   Boot file name: %s \n", dhcp_header.boot_file_name);

                node_t *tmp = dhcp_header.dhcp_options;
                while (tmp != NULL){
                    my_dhcp_option_t *option = (my_dhcp_option_t*)tmp->data;
                    printf("|   |   |   |   Option: %d (%s) \n", option->option_code, option->option_code_desc);
                    printf("|   |   |   |   |   Length: %d \n", option->option_length);
                    if (option->option_code == DHCP_MESSAGE_TYPE){
                        printf("|   |   |   |   |   Message type: %s (%d) \n", option->option_value_desc, option->option_value);
                    } else {
                        printf("|   |   |   |   |   Description: %s \n", option->option_value_desc);
                    }
                    tmp = tmp->next;
                }

                free_dhcp_bootp_header(&dhcp_header);
                break;
            }
            case PORT_DNS: {
                my_dns_header_t dns_header = parse_dns(packet, true);
                printf("|   |   |  DNS ---------------------------------------------------------\n");
                printf("|   |   |   |   Transaction-ID: %d (0x%x)\n", dns_header.transaction_id, dns_header.transaction_id);
                printf("|   |   |   |   Opcode: %s (%d)\n", dns_header.opcode_desc, dns_header.opcode);
                if (dns_header.aa) printf("|   |   |   |   %s: %s\n", dns_header.aa_desc, (dns_header.aa) ? "yes" : "no");
                if (dns_header.tc) printf("|   |   |   |   %s: %s\n", dns_header.tc_desc, (dns_header.tc) ? "yes" : "no");
                if (dns_header.rd) printf("|   |   |   |   %s: %s\n", dns_header.rd_desc, (dns_header.rd) ? "yes" : "no");
                if (dns_header.ra) printf("|   |   |   |   %s: %s\n", dns_header.ra_desc, (dns_header.ra) ? "yes" : "no");
                printf("|   |   |   |   Error code: %s: %d\n", dns_header.rcode_desc, dns_header.rcode);
                printf("|   |   |   |   Questions count: %d \n", dns_header.qdcount);
                printf("|   |   |   |   Answers count: %d \n", dns_header.ancount);
                printf("|   |   |   |   Authority count: %d \n", dns_header.nscount);
                printf("|   |   |   |   Additional count: %d \n", dns_header.arcount);

                node_t *tmp = dns_header.question_section;
                int question_count = 0;
                while (tmp != NULL){
                    question_section_t *question = (question_section_t*)tmp->data;
                    printf("|   |   |   |   Question (%d): \n", question_count);
                    printf("|   |   |   |   |   Name: %s\n", question->qname);
                    printf("|   |   |   |   |   Type: %s (%d)\n", question->qtype_desc, question->qtype);
                    printf("|   |   |   |   |   Class: %s (%d)\n", question->qclass_desc, question->qclass);
                    question_count++;
                    tmp = tmp->next;
                }

                tmp = dns_header.answer_section;
                int answer_count = 0;
                while (tmp != NULL){
                    resource_record_t *answer = (resource_record_t*)tmp->data;
                    printf("|   |   |   |   Answer (%d): \n", answer_count);
                    printf("|   |   |   |   |   Name: %s\n", answer->name);
                    printf("|   |   |   |   |   Type: %s (%d)\n", answer->type_desc, answer->type);
                    printf("|   |   |   |   |   Class: %s (%d)\n", answer->class_desc, answer->class);
                    printf("|   |   |   |   |   TTL: %d\n", answer->ttl);
                    printf("|   |   |   |   |   Data length: %d\n", answer->rdlength);
                    printf("|   |   |   |   |   Data: %s\n", answer->rdata_desc);
                    answer_count++;
                    tmp = tmp->next;
                }

                tmp = dns_header.authority_section;
                int authority_count = 0;
                while (tmp != NULL){
                    resource_record_t *authority = (resource_record_t*)tmp->data;
                    printf("|   |   |   |   Authority (%d): \n", authority_count);
                    printf("|   |   |   |   |   Name: %s\n", authority->name);
                    printf("|   |   |   |   |   Type: %s (%d)\n", authority->type_desc, authority->type);
                    printf("|   |   |   |   |   Class: %s (%d)\n", authority->class_desc, authority->class);
                    printf("|   |   |   |   |   TTL: %d\n", authority->ttl);
                    printf("|   |   |   |   |   Data length: %d\n", authority->rdlength);
                    printf("|   |   |   |   |   Data: %s\n", authority->rdata_desc);
                    authority_count++;
                    tmp = tmp->next;
                }

                tmp = dns_header.additional_section;
                int additional_count = 0;
                while (tmp != NULL){
                    resource_record_t *additional = (resource_record_t*)tmp->data;
                    printf("|   |   |   |   Additional (%d): \n", additional_count);
                    printf("|   |   |   |   |   Name: %s\n", additional->name);
                    printf("|   |   |   |   |   Type: %s (%d)\n", additional->type_desc, additional->type);
                    printf("|   |   |   |   |   Class: %s (%d)\n", additional->class_desc, additional->class);
                    printf("|   |   |   |   |   TTL: %d\n", additional->ttl);
                    printf("|   |   |   |   |   Data length: %d\n", additional->rdlength);
                    printf("|   |   |   |   |   Data: %s\n", additional->rdata_desc);
                    additional_count++;
                    tmp = tmp->next;
                }

                free_dns_header(&dns_header);
                break;
            }
            default:
                break;
        }

    }
}

/**
 * @brief Print the timestamp of the packet based on the verbosity level
 * 
 * @param pcap_header 
 * @param verbosity 
 */
void
print_timestamp(const struct pcap_pkthdr *pcap_header, int verbosity)
{   
    char buffer[64];
    struct tm *localtm;
    time_t local_tv_sec;

    local_tv_sec = pcap_header->ts.tv_sec;
    localtm = localtime(&local_tv_sec);

    switch(verbosity){
        case VB_MINIMAL:
            strftime(buffer, sizeof(buffer), "%H:%M:%S", localtm);
            printf("%s ", buffer);
            break;
        case VB_MIDDLE:
            strftime(buffer, sizeof(buffer), "%H:%M:%S", localtm);
            printf("Timestamp: %s\n", buffer);
            break;
        case VB_MAXIMAL:
            strftime(buffer, sizeof(buffer), "%H:%M:%S", localtm);
            printf("Timestamp: %s\n", buffer);
            break;
        default:
            break;
    }
}

/**
 * @brief Check if the given IPv4 header is empty
 * 
 * @param header 
 * @return true 
 * @return false 
 */
bool 
is_ipv4_header_empty(const my_ipv4_header_t *header) {
    my_ipv4_header_t empty_header = {0};
    return memcmp(header, &empty_header, sizeof(my_ipv4_header_t)) == 0;
}

/**
 * @brief Check if the given IPv6 header is empty
 * 
 * @param header 
 * @return true 
 * @return false 
 */
bool
is_ipv6_header_empty(const my_ipv6_header_t *header) {
    my_ipv6_header_t empty_header = {0};
    return memcmp(header, &empty_header, sizeof(my_ipv6_header_t)) == 0;
}

/**
 * @brief Check if the given TCP header is empty
 * 
 * @param header 
 * @return true 
 * @return false 
 */
bool
is_tcp_header_empty(const my_tcp_header_t *header) {
    my_tcp_header_t empty_header = {0};
    return memcmp(header, &empty_header, sizeof(my_tcp_header_t)) == 0;
}

/**
 * @brief Check if the given UDP header is empty
 * 
 * @param header 
 * @return true 
 * @return false 
 */
bool
is_udp_header_empty(const my_udp_header_t *header) {
    my_udp_header_t empty_header = {0};
    return memcmp(header, &empty_header, sizeof(my_udp_header_t)) == 0;
}