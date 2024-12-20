#include "dns.h"
#include <assert.h>

void test_parse_dns_simple()
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

    node_t *tmp = dns_header.question_section;
    for (; tmp != NULL; tmp = tmp->next){
        question_section_t *question_section = (question_section_t*)tmp->data;
        assert(strcmp(question_section->qname, "95.6.192.10.in-addr.arpa") == 0);
        assert(question_section->qtype == 12);
        assert(strcmp(question_section->qtype_desc, "PTR") == 0);
        assert(question_section->qclass == 1);
        assert(strcmp(question_section->qclass_desc, "IN") == 0);
    }
}

void test_parse_dns_complex()
{
    uint8_t dns_packet[] = {
        0x4e, 0xf,  0x81, 0x80, 0x0,  0x1,  0x0,  0x2, 
        0x0,  0x1,  0x0,  0x0,  0x5,  0x76, 0x61, 0x6c, 
        0x69, 0x64, 0x5,  0x61, 0x70, 0x70, 0x6c, 0x65, 
        0x3,  0x63, 0x6f, 0x6d, 0x0,  0x0,  0x41, 0x0, 
        0x1,  0xc0, 0xc,  0x0,  0x5,  0x0,  0x1,  0x0,
        0x0,  0x17, 0x54, 0x0,  0x23, 0x5,  0x76, 0x61, 
        0x6c, 0x69, 0x64, 0xc,  0x6f, 0x72, 0x69, 0x67, 
        0x69, 0x6e, 0x2d, 0x61, 0x70, 0x70, 0x6c, 0x65, 
        0x3,  0x63, 0x6f, 0x6d, 0x6,  0x61, 0x6b, 0x61, 
        0x64, 0x6e, 0x73, 0x3,  0x6e, 0x65, 0x74, 0x0, 
        0xc0, 0x2d, 0x0,  0x5,  0x0,  0x1,  0x0,  0x0, 
        0x0,  0x0,  0x0,  0x1b, 0xb,  0x76, 0x61, 0x6c, 
        0x69, 0x64, 0x2d, 0x61, 0x70, 0x70, 0x6c, 0x65, 
        0x1,  0x67, 0x7,  0x61, 0x61, 0x70, 0x6c, 0x69, 
        0x6d, 0x67, 0x3,  0x63, 0x6f, 0x6d, 0x0,  0x1, 
        0x67, 0x7,  0x61, 0x61, 0x70, 0x6c, 0x69, 0x6d, 
        0x67, 0x3,  0x63, 0x6f, 0x6d, 0x0,  0x0,  0x6, 
        0x0,  0x1,  0x0,  0x0,  0x1,  0x21, 0x0,  0x3e, 
        0x1,  0x61, 0x4,  0x67, 0x73, 0x6c, 0x62, 0x7, 
        0x61, 0x61, 0x70, 0x6c, 0x69, 0x6d, 0x67, 0x3, 
        0x63, 0x6f, 0x6d, 0x0,  0xa,  0x68, 0x6f, 0x73, 
        0x74, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x5, 
        0x61, 0x70, 0x70, 0x6c, 0x65, 0x3,  0x63, 0x6f, 
        0x6d, 0x0,  0x66, 0x88, 0xe1, 0x1f, 0x0,  0x0, 
        0x7,  0x8,  0x0,  0x0,  0x1,  0x2c, 0x0,  0x0, 
        0xec, 0x40, 0x0,  0x0,  0x1,  0x2c};

    my_dns_header_t dns_header = parse_dns(dns_packet, false);
    assert(dns_header.transaction_id == 0x4e0f);
    assert(dns_header.qr == 1);
    assert(strcmp(dns_header.qr_desc, "RESPONSE") == 0);
    assert(dns_header.opcode == 0);
    assert(strcmp(dns_header.opcode_desc, "op: QUERY") == 0);
    assert(dns_header.aa == 0);
    assert(dns_header.tc == 0);
    assert(dns_header.rd == 1);
    assert(strcmp(dns_header.rd_desc, "Recursion") == 0);
    assert(dns_header.ra == 1);
    assert(dns_header.z == 0);
    assert(dns_header.rcode == 0);
    assert(dns_header.qdcount == 1);
    assert(dns_header.ancount == 2);
    assert(dns_header.nscount == 1);
    assert(dns_header.arcount == 0);

    // test the question
    node_t *tmp = dns_header.question_section;
    question_section_t *question_section = (question_section_t*)tmp->data;
    assert(strcmp(question_section->qname, "valid.apple.com") == 0);
    assert(question_section->qtype == 65);
    assert(strcmp(question_section->qtype_desc, "HTTPS") == 0);
    assert(question_section->qclass == 1);
    assert(strcmp(question_section->qclass_desc, "IN") == 0);

    // test the answers (2)
    tmp = dns_header.answer_section;
    resource_record_t *answer_section = (resource_record_t*)tmp->data;
    assert(answer_section->type == 5);
    assert(strcmp(answer_section->type_desc, "CNAME") == 0);
    assert(answer_section->class == 1);
    assert(strcmp(answer_section->class_desc, "IN") == 0);
    assert(answer_section->ttl == 5972);
    assert(answer_section->rdlength == 35);
    assert(strcmp(answer_section->rdata_desc, ".valid.origin-apple.com.akadns.net.") == 0);

    tmp = dns_header.answer_section->next;
    answer_section = (resource_record_t*)tmp->data;
    assert(answer_section->type == 5);
    assert(strcmp(answer_section->type_desc, "CNAME") == 0);
    assert(answer_section->class == 1);
    assert(strcmp(answer_section->class_desc, "IN") == 0);
    assert(answer_section->ttl == 0);
    assert(answer_section->rdlength == 27);
    assert(strcmp(answer_section->rdata_desc, ".valid-apple.g.aaplimg.com.") == 0);


    // test the authority (1)
    tmp = dns_header.authority_section;
    resource_record_t *authority_section = (resource_record_t*)tmp->data;
    assert(authority_section->type == 6);
    assert(strcmp(authority_section->type_desc, "SOA") == 0);
    assert(authority_section->class == 1);
    assert(strcmp(authority_section->class_desc, "IN") == 0);
    assert(authority_section->ttl == 289);
    assert(authority_section->rdlength == 62);
    printf("%s\n", authority_section->rdata_desc);
    assert(strcmp(authority_section->rdata_desc, ".a.gslb.aaplimg.com..hostmaster.apple.com.f..........,...@...,") == 0);

    free_dns_header(&dns_header);
}

int main()
{
    // test_parse_dns_simple();
    test_parse_dns_complex();
    return 0;
}