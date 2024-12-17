#ifndef ICMP_H
#define ICMP_H

#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include "ipv4.h"

/* https://datatracker.ietf.org/doc/html/rfc792 
Echo or Echo Reply Message [Page 14]

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Data ...
   +-+-+-+-+-

Destination Unreachable Message

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             unused                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Internet Header + 64 bits of Original Data Datagram      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define ICMP_TYPE_DESC_SIZE 40
#define ICMP_CODE_DESC_SIZE 90

typedef struct my_icmp {
    uint8_t type;
    char icmp_type_desc[ICMP_TYPE_DESC_SIZE];

    uint8_t code;
    char icmp_code_desc[ICMP_CODE_DESC_SIZE];

    uint16_t checksum;
    bool checksum_valid;

    uint16_t identifier;
    uint16_t sequence_number;
    uint8_t *data; // this is reserved for the ICMP payload

    // Internet Header + 64 bits of Original Data Datagram
    // TODO: I need to implement this later
} my_icmp_t;

my_icmp_t parse_icmp(const uint8_t *packet, size_t packet_length, bool verbose);

// helpers
void get_icmp_type_desc(uint8_t type, char *desc, bool verbose);
void get_icmp_code_desc(uint8_t type, uint8_t code, char* desc, bool verbose);

#endif