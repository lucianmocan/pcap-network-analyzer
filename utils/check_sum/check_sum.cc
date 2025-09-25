#include "check_sum.h"

/**
 * @brief Calculate the checksum of an IPv4 packet
 * according to RFC1071 (it is done in big-endian)
 * 
 * @param packet 
 * @param length 
 * @return uint16_t 
 */
uint32_t 
calculate_checksum(uint16_t *packet, int count)
{
    // https://www.rfc-editor.org/rfc/rfc1071
    // Algorithm found on [Page 6] 4.1 "C"
    uint32_t sum = 0;
    while (count > 1) {
        sum +=  *(uint16_t*)packet++;
        count -= 2;
    }

    // Add left-over byte, if any
    if (count > 0) {
        sum += *(uint8_t *)packet;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;
}
