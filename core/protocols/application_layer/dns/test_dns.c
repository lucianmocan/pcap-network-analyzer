#include "dns.h"
#include <assert.h>

void test_parse_dns()
{
    uint8_t dns_packet[] = {
    0x01, 0x9f, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x39, 0x35, 0x01,
    0x36, 0x03, 0x31, 0x39, 0x32, 0x02, 0x31, 0x30,
    0x07, 0x69, 0x6e, 0x2d, 0x61, 0x64, 0x64, 0x72,
    0x04, 0x61, 0x72, 0x70, 0x61, 0x00, 0x00, 0x0c,
    0x00, 0x01
    };

    my_dns_header_t dns_header = parse_dns(dns_packet, false);
    assert(dns_header.transaction_id == 0x019f);
    assert(dns_header.qr == 0);
    assert(strcmp(dns_header.qr_desc, "QUERY") == 0);
    assert(dns_header.opcode == 0);
    assert(strcmp(dns_header.opcode_desc, "op: QUERY") == 0);
    assert(dns_header.aa == 0);
    assert(dns_header.tc == 0);
    assert(dns_header.rd == 1);
    assert(strcmp(dns_header.rd_desc, "Recursion") == 0);
    assert(dns_header.ra == 0);
    assert(dns_header.z == 0);
    assert(dns_header.rcode == 0);
    assert(dns_header.qdcount == 1);
    assert(dns_header.ancount == 0);
    assert(dns_header.nscount == 0);
    assert(dns_header.arcount == 0);
}

int main()
{
    test_parse_dns();
    return 0;
}