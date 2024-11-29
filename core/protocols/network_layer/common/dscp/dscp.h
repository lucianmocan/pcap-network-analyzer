#ifndef DSCP_H
#define DSCP_H

#include <stdbool.h>
#include <sys/types.h>
#include <stdio.h>
#include <netinet/ip.h>

/*
DSCP values: https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml
*/

#ifdef __linux__
#define IPTOS_DSCP_SHIFT 2
#endif

// DSCP Pool 1 Codepoints
// Class Selector
#define CS0 0           
#define CS1 8
#define CS2 16
#define CS3 24
#define CS4 32
#define CS5 40
#define CS6 48
#define CS7 56

// Assured Forwarding
#define AF11 10         
#define AF12 12
#define AF13 14

#define AF21 18
#define AF22 20
#define AF23 22

#define AF31 26
#define AF32 28
#define AF33 30

#define AF41 34
#define AF42 36
#define AF43 38

// Expedited Forwarding
#define EF 46           

#define VOICE_ADMIT 44  // Voice Admit https://datatracker.ietf.org/doc/html/rfc5865#section-4 [Page 12]

// DSCP Pool 3 Codepoints
#define LE 1            // Low Effort https://datatracker.ietf.org/doc/html/rfc3662

#define DSCP_DEFAULT 0

#define IS_VALID_DSCP(x) ((x) <= 63 && (x) >= 0)    // DSCP is in [0-63]
#define IS_VALID_ECN(x) ((x) <= 3 && (x) >= 0)      // ECN is in [0-3]

#define ECN_DESC_SIZE 40
#define DSCP_DESC_SIZE 40

void get_dscp_desc(uint8_t dscp, char *dscp_desc, bool verbose);
void get_ecn_desc(uint8_t ecn, char *ecn_desc, bool verbose);

#endif