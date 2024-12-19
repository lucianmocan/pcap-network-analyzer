#ifndef DNS_H
#define DNS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "linked_list.h"

#define DNS_NAME_MAX_SIZE 255
#define DNS_LABEL_MAX_SIZE 63

/* 
Size limits in DNS: https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.4
    labels          63 octets or less
    names           255 octets or less
    TTL             positive values of a signed 32 bit number.
    UDP messages    512 octets or less


RR header format: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

Question section format: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
    
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

The header contains the following fields:
https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

*/

#define QR_DESC_SIZE 42
#define OPCODE_DESC_SIZE 40
#define RCODE_DESC_SIZE 40

// QR values
#define QR_QUERY 0
#define QR_RESPONSE 1

// OPCODE values
#define OP_QUERY 0
#define OP_IQUERY 1
#define OP_STATUS 2

// RCODE values
#define RCODE_NO_ERROR 0
#define RCODE_FORMAT_ERROR 1
#define RCODE_SERVER_FAILURE 2
#define RCODE_NAME_ERROR 3
#define RCODE_NOT_IMPLEMENTED 4
#define RCODE_REFUSED 5


typedef struct dns_label {
    uint8_t length;
    uint8_t value[DNS_LABEL_MAX_SIZE];
    char value_desc[DNS_LABEL_MAX_SIZE + 1];
} dns_label_t;

typedef struct question_section {
    node_t* qname;   // a domain name represented as a sequence of labels, where each label consists of a length octet followed by that number of octets.
    uint16_t qtype;  // a two octet code which specifies the type of the query.
    uint16_t qclass; // a two octet code that specifies the class of the query.
} question_section_t;

typedef struct resource_record {
    node_t* name;    // a domain name to which this resource record pertains.
    uint16_t type;   // two octets containing one of the RR type codes.
    uint16_t class;  // two octets which specify the class of the data in the RDATA field.
    uint32_t ttl;    
    uint16_t rdlength; // the length in octets of the RDATA field.
    uint16_t* rdata;  
} resource_record_t;

typedef struct my_dns_header {
    uint16_t transaction_id;

    // A one bit field that specifies whether this message is a
    // query (0), or a response (1).
    uint8_t qr:1;
    char qr_desc[QR_DESC_SIZE];

    // A four bit field that specifies kind of query in this
    // message.  This value is set by the originator of a query
    // and copied into the response.  The values are:
    // 0 a standard query (QUERY)
    // 1 an inverse query (IQUERY)
    // 2 a server status request (STATUS)
    // 3-15 reserved for future use
    uint8_t opcode;
    char opcode_desc[OPCODE_DESC_SIZE];

    uint8_t aa:1; // Authoritative Answer, valid in responses
    char aa_desc[OPCODE_DESC_SIZE];

    uint8_t tc:1; // TrunCation, set if message was truncated
    char tc_desc[OPCODE_DESC_SIZE];
    uint8_t rd:1; // Recursion Desired (set in a query and copied into the response)
                  // In a response, it specifies that the server can do recursive queries
    char rd_desc[OPCODE_DESC_SIZE];
    uint8_t ra:1; // Recursion Available, (set or cleared in a response)
    char ra_desc[OPCODE_DESC_SIZE];

    uint8_t z:3;  // Reserved for future use
    
    uint8_t rcode:4; // Response code
    char rcode_desc[RCODE_DESC_SIZE];

    uint16_t qdcount; // the number of entries in the question section.
    uint16_t ancount; // the number of resource records in the answer section.
    uint16_t nscount; // the number of name server resource records in the authority records section.
    uint16_t arcount; // the number of resource records in the additional records section.

    question_section_t* question_section;
    resource_record_t* answer_section;
    resource_record_t* authority_section;
    resource_record_t* additional_section;

} my_dns_header_t;

my_dns_header_t parse_dns(const uint8_t *packet, bool verbose);
void free_dns_header(my_dns_header_t *dns_header);
// helpers
// void get_dns_name(const uint8_t *packet, my_dns_header_t *dns_header);

void get_ra_desc(uint8_t ra, char *desc, bool verbose);
void get_rd_desc(uint8_t rd, char *desc, bool verbose);
void get_tc_desc(uint8_t tc, char *desc, bool verbose);
void get_aa_desc(uint8_t aa, char *desc, bool verbose);
void get_rcode_desc(uint8_t rcode, char *desc, bool verbose);
void get_opcode_desc(uint8_t opcode, char *desc, bool verbose);
void get_qr_desc(uint8_t qr, char *desc, bool verbose);



#endif