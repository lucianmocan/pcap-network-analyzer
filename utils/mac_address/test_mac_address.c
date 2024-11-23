#include <assert.h>
#include <string.h>
#include "mac_address.h"

void
test_write_mac_address()
{
    u_char mac_address[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    char* mac = write_mac_address(mac_address);
    assert(strcmp(mac, "00:11:22:33:44:55") == 0);
    free(mac);
}


int 
main()
{
    test_write_mac_address();
    return 0;
}