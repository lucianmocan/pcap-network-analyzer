#ifndef __CHECK_SUM_H__
#define __CHECK_SUM_H__


#include <netinet/ip.h>

uint32_t calculate_checksum(uint16_t *packet, int count);

#endif