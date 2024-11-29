#include "ipv4.h"

/**
 * @brief Parse the ipv4 header off a packet (the packet starts with the ipv4 header,
 * should be updated by the caller to point to the start of the ipv4 header) and return
 * all the information in a my_ipv4_header_t struct
 * 
 * @param packet 
 * @return my_ipv4_header_t 
 */
my_ipv4_header_t parse_ipv4(const u_char *packet){

    const struct ip *ip;
    ip = (struct ip*)(packet);


    return (my_ipv4_header_t){0};
}