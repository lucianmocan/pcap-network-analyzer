#ifndef DNS_H
#define DNS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "linked_list.h"

#define DNS_NAME_MAX_SIZE 1024
#define DNS_LABEL_MAX_SIZE 63
#define DNS_DESC_SIZE 64

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
#define RDATA_MAX_SIZE 512

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

// TYPE/QTYPE values
#define TYPE_A 1       // a host address
#define TYPE_NS 2      // an authoritative name server
#define TYPE_CNAME 5   // the canonical name for an alias
#define TYPE_SOA 6     // marks the start of a zone of authority
#define TYPE_WKS 11          // a well known service description
#define TYPE_PTR 12          // a domain name pointer
#define TYPE_HINFO 13        // host information
#define TYPE_MINFO 14        // mailbox or mail list information
#define TYPE_MX 15           // mail exchange
#define TYPE_TXT 16          // text strings
#define TYPE_HTTPS 65       // HTTPS

// CLASS/QCLASS values
#define CLASS_IN 1     // the Internet
#define CLASS_CH 3     // the Chaos class
#define CLASS_HS 4     // Hesiod [Dyer 87]

// 
#define IS_ANSWER 0
#define IS_AUTHORITY 1
#define IS_ADDITIONAL 2

typedef struct question_section {
    char qname[DNS_NAME_MAX_SIZE];   // a domain name represented as a sequence of labels, where each label consists of a length octet followed by that number of octets.
    uint16_t qtype;  // a two octet code which specifies the type of the query.
    char qtype_desc[DNS_DESC_SIZE];
    uint16_t qclass; // a two octet code that specifies the class of the query.
    char qclass_desc[DNS_DESC_SIZE];
} question_section_t;

typedef struct resource_record {
    char name[DNS_NAME_MAX_SIZE];    // a domain name to which this resource record pertains.
    uint16_t type;   // two octets containing one of the RR type codes.
    char type_desc[DNS_DESC_SIZE];
    uint16_t class;  // two octets which specify the class of the data in the RDATA field.
    char class_desc[DNS_DESC_SIZE];
    uint32_t ttl;    
    uint16_t rdlength; // the length in octets of the RDATA field.
    uint8_t* rdata; 
    char rdata_desc[RDATA_MAX_SIZE]; 
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

    node_t* question_section;
    node_t* answer_section;
    node_t* authority_section;
    node_t* additional_section;

} my_dns_header_t;

my_dns_header_t parse_dns(uint8_t *packet, bool verbose);
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
void get_class_desc(uint16_t class, char *desc, bool verbose);
void get_type_desc(uint16_t type, char *desc, bool verbose);
void process_rdata(uint8_t *rdata, char* desc, size_t rdata_length);

int get_dns_name(uint8_t *packet, resource_record_t *resource_record);
int get_dns_qname(uint8_t *packet, question_section_t *question_section);
int get_dns_question(uint8_t *packet, my_dns_header_t *dns_header, bool verbose);
int get_dns_resource_record(uint8_t *packet, uint8_t *packet_init, my_dns_header_t *dns_header, int count, int dest, int advance, bool verbose);
int get_dns_answer(uint8_t *packet, uint8_t *packet_init, my_dns_header_t *dns_header, int advance, bool verbose);
int get_dns_authority(uint8_t *packet, uint8_t *packet_init, my_dns_header_t *dns_header, int advance, bool verbose);
int get_dns_additional(uint8_t *packet, uint8_t *packet_init, my_dns_header_t *dns_header, int advance, bool verbose);
#endif