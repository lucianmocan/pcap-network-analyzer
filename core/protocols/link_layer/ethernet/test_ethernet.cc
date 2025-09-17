#include <cassert>
#include "ethernet.h"

void
test_parse_ethernet()
{
    u_char packet[14] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst mac
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src mac
        0x08, 0x00 // type
    };
    my_ethernet_header_t ethernet_frame = parse_ethernet(packet, true);
    assert(ethernet_frame.src_mac == "66:77:88:99:aa:bb");
    assert(ethernet_frame.dst_mac == "00:11:22:33:44:55");
    assert(ethernet_frame.type == 0x0800);
    assert(ethernet_frame.type_desc == "Type: IP (0x800)");
}

void
test_parse_ethernet_vlan()
{
    u_char packet[18] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst mac
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src mac
        0x81, 0x00,                         // VLAN EtherType
        0x00, 0x64,                         // VLAN TCI: PCP=0, DEI=0, VLAN ID=100
        0x08, 0x00                          // Payload EtherType (IPv4)
    };

    my_ethernet_header_t ethernet_frame = parse_ethernet(packet, true);

    assert(ethernet_frame.src_mac == "66:77:88:99:aa:bb");
    assert(ethernet_frame.dst_mac == "00:11:22:33:44:55");

    assert(ethernet_frame.vlan_tagged == true);
    assert(ethernet_frame.vlan_id == 100); // VLAN ID
    assert(ethernet_frame.pcp == 0);       // PCP
    assert(ethernet_frame.dei == 0);       // DEI

    assert(ethernet_frame.type == 0x8100); // VLAN
    assert(ethernet_frame.type_desc == "Type: VLAN (0x8100)");
    assert(ethernet_frame.type_vlan == 0x0800); // IPv4
    assert(ethernet_frame.type_desc_vlan == "Type: IP (0x800)");
}

int 
main()
{
    test_parse_ethernet();
    test_parse_ethernet_vlan();
    return 0;
}