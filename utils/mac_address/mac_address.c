#include "mac_address.h"

char* 
write_mac_address(const u_char *mac_address)
{
    char *mac = (char *)malloc(18);
    if (mac == NULL){
        fprintf(stderr, "Failed to allocate memory for mac\n");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < 6; i++){
        sprintf(mac + i * 3, "%02x", mac_address[i]);
        if (i != 5)
            sprintf(mac + i * 3 + 2, ":");
    }
    return mac;
}