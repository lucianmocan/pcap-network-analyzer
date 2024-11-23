#include <assert.h>
#include "ethernet.h"

void
test_parse_ethernet()
{
    u_char packet[14] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst mac
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src mac
        0x08, 0x00 // type
    };
    ethernet_frame_t ethernet_frame = parse_ethernet(packet);
    assert(strcmp(ethernet_frame.src_mac, "66:77:88:99:aa:bb") == 0);
    assert(strcmp(ethernet_frame.dst_mac, "00:11:22:33:44:55") == 0);
    assert(ethernet_frame.type == 8);
}

int 
main()
{
    test_parse_ethernet();
    return 0;
}