#include "check_sum.h"
#include <assert.h>

void test_calculate_checksum(){
    u_int8_t packet[] = {
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61,
        0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7
    };
    
    struct ip *ip = (struct ip*)packet;
    int length = ip->ip_hl * 4;
    uint16_t original_checksum = ip->ip_sum;
    ip->ip_sum = 0;
    
    uint16_t checksum = calculate_checksum((uint16_t*)packet, length);
    
    assert(checksum == original_checksum);
}


int main()
{
    test_calculate_checksum();
    return 0;
}