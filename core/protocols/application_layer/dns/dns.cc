#include "dns.h"



my_dns_header_t 
parse_dns(uint8_t *packet, bool verbose)
{
    my_dns_header_t dns_header;
    uint8_t *packet_init = (uint8_t*)packet;
    dns_header.transaction_id = ntohs(*(uint16_t*)packet);
    packet += 2;
    dns_header.qr = (*packet & 0x80) >> 7;
    get_qr_desc(dns_header.qr, dns_header.qr_desc, verbose);

    dns_header.opcode = (*packet & 0x78) >> 3;
    get_opcode_desc(dns_header.opcode, dns_header.opcode_desc, verbose);

    dns_header.aa = (*packet & 0x04) >> 2;
    get_aa_desc(dns_header.aa, dns_header.aa_desc, verbose);
    dns_header.tc = (*packet & 0x02) >> 1;
    get_tc_desc(dns_header.tc, dns_header.tc_desc, verbose);
    dns_header.rd = (*packet & 0x01);
    get_rd_desc(dns_header.rd, dns_header.rd_desc, verbose);
    packet += 1;
    dns_header.ra = (*packet & 0x80) >> 7;
    get_ra_desc(dns_header.ra, dns_header.ra_desc, verbose);
    dns_header.z = (*packet & 0x70) >> 4;

    dns_header.rcode = (*packet & 0x0F);
    get_rcode_desc(dns_header.rcode, dns_header.rcode_desc, verbose);

    packet += 1;
    dns_header.qdcount = ntohs(*(uint16_t*)packet);
    packet += 2;
    dns_header.ancount = ntohs(*(uint16_t*)packet);
    packet += 2;
    dns_header.nscount = ntohs(*(uint16_t*)packet);
    packet += 2;
    dns_header.arcount = ntohs(*(uint16_t*)packet);
    packet += 2;

    dns_header.question_section = NULL;
    dns_header.answer_section = NULL;
    dns_header.authority_section = NULL;
    dns_header.additional_section = NULL;

    int advance = 0;
    if (dns_header.qdcount > 0){
        int step = get_dns_question(packet, &dns_header, verbose);
        advance += step;
    }

    if (dns_header.ancount > 0){
        int step = get_dns_answer(packet, packet_init, &dns_header, advance, verbose);
        advance += step;
    }

    if (dns_header.nscount > 0){
        int step = get_dns_authority(packet, packet_init, &dns_header, advance, verbose);
        advance += step;
    }

    if (dns_header.arcount > 0){
        int step = get_dns_additional(packet, packet_init, &dns_header, advance, verbose);
        advance += step;
    }

    return dns_header;
}

void
free_dns_header(my_dns_header_t *dns_header)
{
    free_list(dns_header->question_section);
    free_list(dns_header->answer_section);
    free_list(dns_header->authority_section);
    free_list(dns_header->additional_section);
}

/**
 * @brief Get the dns answer stuff
 * 
 * @param packet 
 * @param packet_init 
 * @param dns_header 
 * @param advance 
 * @param verbose 
 * @return int 
 */
int get_dns_answer(uint8_t *packet, uint8_t *packet_init, my_dns_header_t *dns_header, int advance, bool verbose){
    return get_dns_resource_record(packet, packet_init, dns_header, dns_header->ancount, IS_ANSWER, advance, verbose);
}

/**
 * @brief Get the dns authority stuff
 * 
 * @param packet 
 * @param packet_init 
 * @param dns_header 
 * @param advance 
 * @param verbose 
 * @return int 
 */
int get_dns_authority(uint8_t *packet, uint8_t *packet_init, my_dns_header_t *dns_header, int advance, bool verbose){
    return get_dns_resource_record(packet, packet_init, dns_header, dns_header->nscount, IS_AUTHORITY, advance, verbose);
}

/**
 * @brief Get the dns additional stuff
 * 
 * @param packet 
 * @param packet_init 
 * @param dns_header 
 * @param advance 
 * @param verbose 
 * @return int 
 */
int get_dns_additional(uint8_t *packet, uint8_t *packet_init, my_dns_header_t *dns_header, int advance, bool verbose){
    return get_dns_resource_record(packet, packet_init, dns_header, dns_header->arcount, IS_ADDITIONAL, advance, verbose);
}

/**
 * @brief Get the dns resource record object
 * 
 * @param packet 
 * @param packet_init 
 * @param dns_header 
 * @param count 
 * @param what 
 * @param advance 
 * @param verbose 
 * @return int 
 */
int
get_dns_resource_record(uint8_t *packet, uint8_t* packet_init, my_dns_header_t *dns_header, int count, int what, int advance, bool verbose)
{   
    node_t **dest;
    switch(what){
        case IS_ANSWER:
            dest = &dns_header->answer_section;
            break;
        case IS_AUTHORITY:
            dest = &dns_header->authority_section;
            break;
        case IS_ADDITIONAL:
            dest = &dns_header->additional_section;
            break;
        default:
            fprintf(stderr, "Invalid resource record type\n");
            exit(EXIT_FAILURE);
    }
    int next = 0;
    uint8_t *packet_current = packet + advance;
    while(count > 0){
        resource_record_t *resource_record = (resource_record_t *)malloc(sizeof(resource_record_t));
        if (resource_record == NULL){
            fprintf(stderr, "Failed to allocate memory for resource record\n");
            exit(EXIT_FAILURE);
        }
        if ((packet_current[0] & 0xC0) == 0xC0){
            size_t offset = ((packet_current[0] & 0x3F) << 8) | packet_current[1];
            int qname_size = get_dns_name(packet_init + offset, resource_record);
            // skip pointer
            packet_current += 2;
            next += 2;
        } else {
            int qname_size = get_dns_name(packet_current, resource_record);
            packet_current += qname_size;
            next += qname_size;
        }
        resource_record->type = ntohs(*(uint16_t*)packet_current);
        get_type_desc(resource_record->type, resource_record->type_desc, verbose);
        packet_current += 2;
        next += 2;

        resource_record->data_class = ntohs(*(uint16_t*)packet_current);
        get_class_desc(resource_record->data_class, resource_record->class_desc, verbose);
        packet_current += 2;
        next += 2;

        resource_record->ttl = ntohl(*(uint32_t*)packet_current);
        packet_current += 4;
        next += 4;

        resource_record->rdlength = ntohs(*(uint16_t*)packet_current);
        packet_current += 2;
        next += 2;

        resource_record->rdata = (uint8_t*)malloc(resource_record->rdlength);
        if (resource_record->rdata == NULL){
            fprintf(stderr, "Failed to allocate memory for rdata\n");
            exit(EXIT_FAILURE);
        }
        memcpy(resource_record->rdata, packet_current, resource_record->rdlength);
        process_rdata((uint8_t*)resource_record->rdata, resource_record->rdata_desc, resource_record->rdlength);
        packet_current += resource_record->rdlength;
        next += resource_record->rdlength;

        *dest = add_node_end(*dest, (void*)resource_record);
        count--;
    }
    return next;
}

/**
 * @brief Get rdata into string representation
 * 
 * @param rdata 
 * @param desc 
 * @param rdata_length 
 */
void
process_rdata(uint8_t *rdata, char* desc, size_t rdata_length)
{
    desc[rdata_length] = '\0';
    for (int i = 0; i < rdata_length; i++){
        if (isprint(rdata[i])){
            desc[i] = rdata[i];
        } else {
            desc[i] = '.';
        }
    }
}

int 
get_dns_question(uint8_t *packet, my_dns_header_t *dns_header, bool verbose)
{
    int count = dns_header->qdcount;
    // keep the counter in the packet for the others
    int next = 0;
    while(count > 0){
        question_section_t *question_section = (question_section_t *)malloc(sizeof(question_section_t));
        if (question_section == NULL){
            fprintf(stderr, "Failed to allocate memory for question section\n");
            exit(EXIT_FAILURE);
        }
        int qname_size = get_dns_qname(packet, question_section);
        next += qname_size;
        packet += qname_size;
        question_section->qtype = ntohs(*(uint16_t*)packet);
        get_type_desc(question_section->qtype, question_section->qtype_desc, verbose);
        packet += 2;
        next += 2;
        question_section->qclass = ntohs(*(uint16_t*)packet);
        get_class_desc(question_section->qclass, question_section->qclass_desc, verbose);
        packet += 2;
        next += 2;
        dns_header->question_section = add_node_end(dns_header->question_section, (void*)question_section);
        count--;
    }
    return next;
}

/**
 * @brief Get the class/qclass description in a given string
 * 
 * @param desc 
 * @param verbose 
 */
void
get_class_desc(uint16_t data_class, std::string& desc, bool verbose){
    // https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
    switch(data_class){
        case CLASS_IN:
            if (verbose){
                desc = "IN (" + std::to_string(data_class) + ") the Internet";
            } else {
                desc = "IN";
            }
            break;
        case CLASS_CH:
            if (verbose){
                desc = "CH (" + std::to_string(data_class) + ") the CHAOS class";
            } else {
                desc = "CH";
            }
            break;
        case CLASS_HS:
            if (verbose){
                desc = "HS (" + std::to_string(data_class) + ") Hesiod";
            } else {
                desc = "HS";
            }
            break;
        default:
            if (verbose){
                desc = "class: Unknown (" + std::to_string(data_class) + ")";
            } else {
                desc = "class: ?";
            }
            break;
    }
}

/**
 * @brief Get the type/qtype description in a given string
 * 
 * @param type 
 * @param desc 
 * @param verbose 
 */
void 
get_type_desc(uint16_t type, std::string& desc, bool verbose)
{
    // https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
    switch(type){
        case TYPE_A:
            if (verbose){
                desc = "A (" + std::to_string(type) + ") host address";
            } else {
                desc = "A";
            }
            break;
        case TYPE_NS:
            if (verbose){
                desc = "NS (" + std::to_string(type) + ") authoritative name server";
            } else {
                desc = "NS";
            }
            break;
        case TYPE_CNAME:
            if (verbose){
                desc = "CNAME (" + std::to_string(type) + ") canonical name";
            } else {
                desc = "CNAME";
            }
            break;
        case TYPE_SOA:
            if (verbose){
                desc = "SOA (" + std::to_string(type) + ") zone of authority";
            } else {
                desc = "SOA";
            }
            break;
        case TYPE_PTR:
            if (verbose){
                desc = "PTR (" + std::to_string(type) + ") domain name pointer";
            } else {
                desc = "PTR";
            }
            break;
        case TYPE_HINFO:
            if (verbose){
                desc = "HINFO (" + std::to_string(type) + ") host information";
            } else {
                desc = "HINFO";
            }
            break;
        case TYPE_MINFO:
            if (verbose){
                desc = "MINFO (" + std::to_string(type) + ") mailbox or mail list information";
            } else {
                desc = "MINFO";
            }
            break;
        case TYPE_MX:
            if (verbose){
                desc = "MX (" + std::to_string(type) + ") mail exchange";
            } else {
                desc = "MX";
            }
            break;
        case TYPE_TXT:
            if (verbose){
                desc = "TXT (" + std::to_string(type) + ") text strings";
            } else {
                desc = "TXT";
            }
            break;
        case TYPE_HTTPS:
            if (verbose){
                desc = "HTTPS (" + std::to_string(type) + ") Specific Service Endpoints";
            } else {
                desc = "HTTPS";
            }
            break;
        default:
            if (verbose){
                desc = "qtype: Unknown (" + std::to_string(type) + ")";
            } else {
                desc = "qtype: ?";
            }
            break;
    }
}

/**
 * @brief Get the dns qnames in a string and return the number of bytes read
 * 
 * @param packet 
 * @param question_section 
 * @return int 
 */
int
get_dns_qname(uint8_t *packet, question_section_t *question_section)
{
    int i = 0;
    std::string qname;
    while (packet[i] != 0) {
        int label_length = packet[i];
        if (label_length == 0 || label_length > DNS_NAME_MAX_SIZE) {
            throw std::runtime_error("Invalid label length in DNS qname");
        }
        if (i + label_length + 1 > DNS_NAME_MAX_SIZE) {
            throw std::runtime_error("QName exceeds maximum allowed size");
        }
        if (!qname.empty()) {
            qname += '.';
        }
        qname.append(reinterpret_cast<char*>(packet + i + 1), label_length);
        i += label_length + 1;
    }
    question_section->qname = qname;
    return i + 1;
}

/**
 * @brief Get the dns qnames in a string and return the number of bytes read
 * 
 * @param packet 
 * @param question_section 
 * @return int 
 */
int
get_dns_name(uint8_t *packet, resource_record_t *resource_record)
{
    int i = 0;
    std::string name;
    while (packet[i] != 0) {
        int label_length = packet[i];
        if (label_length == 0 || label_length > DNS_LABEL_MAX_SIZE) {
            throw std::runtime_error("Invalid label length in DNS name");
        }
        if (i + label_length + 1 > DNS_NAME_MAX_SIZE) {
            throw std::runtime_error("Name exceeds maximum allowed size");
        }
        if (!name.empty()) {
            name += '.';
        }
        name.append(reinterpret_cast<char*>(packet + i + 1), label_length);
        i += label_length + 1;
    }
    resource_record->name = name;
    return i + 1;
}

/**
 * @brief Get the ra description in a given string
 * 
 * @param ra 
 * @param desc 
 * @param verbose 
 */
void
get_ra_desc(uint8_t ra, std::string& desc, bool verbose)
{
    switch(ra){
        case 1:
            if (verbose){
                desc = "Recursion available (" + std::to_string(ra) + ")";
            } else {
                desc = "Rec";
            }
            break;
    }
}

/**
 * @brief Get the rd description in a given string
 * 
 * @param rd 
 * @param desc 
 * @param verbose 
 */
void
get_rd_desc(uint8_t rd, std::string& desc, bool verbose)
{
    switch(rd){
        case 1:
            if (verbose){
                desc = "Recursion desired (" + std::to_string(rd) + ")";
            } else {
                desc = "Recursion";
            }
            break;
    }
}


/**
 * @brief Get the tc description in a given string
 * 
 * @param tc 
 * @param desc 
 * @param verbose 
 */
void
get_tc_desc(uint8_t tc, std::string& desc, bool verbose)
{
    switch(tc){
        case 1:
            if (verbose){
                desc = "Truncated (" + std::to_string(tc) + ")";
            } else {
                desc = "Trunc";
            }
            break;
    }
}


/**
 * @brief Get the aa description in a given string
 * 
 * @param aa 
 * @param desc 
 * @param verbose 
 */
void
get_aa_desc(uint8_t aa, std::string& desc, bool verbose)
{
    switch(aa){
        case 1:
            if (verbose){
                desc = "Authoritative (" + std::to_string(aa) + ")";
            } else {
                desc = "Auth";
            }
            break;
    }
}

/**
 * @brief Get the rcode description in a given string
 * 
 * @param rcode 
 * @param desc 
 * @param verbose 
 */
void
get_rcode_desc(uint8_t rcode, std::string& desc, bool verbose)
{   
    // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    switch(rcode){
        case RCODE_NO_ERROR:
            if (verbose){
                desc = "No error (" + std::to_string(rcode) + ")";
            } else {
                desc = "res: 0 !";
            }
            break;
        case RCODE_FORMAT_ERROR:
            if (verbose){
                desc = "Format error (" + std::to_string(rcode) + ")";
            } else {
                desc = "res: format !";
            }
            break;
        case RCODE_SERVER_FAILURE:
            if (verbose){
                desc = "Server failure (" + std::to_string(rcode) + ")";
            } else {
                desc = "res: server !";
            }
            break;
        case RCODE_NAME_ERROR:
            if (verbose){
                desc = "Name error (" + std::to_string(rcode) + ")";
            } else {
                desc = "res: name !";
            }
            break;
        case RCODE_NOT_IMPLEMENTED:
            if (verbose){
                desc = "Not implemented (" + std::to_string(rcode) + ")";
            } else {
                desc = "res: !impl";
            }
            break;
        case RCODE_REFUSED:
            if (verbose){
                desc = "Refused (" + std::to_string(rcode) + ")";
            } else {
                desc = "res: X";
            }
            break;
        default:
            if (verbose){
                desc = "Unknown (" + std::to_string(rcode) + ")";
            } else {
                desc = "res: ?";
            }
            break;
    }
}

/**
 * @brief Get the qr description in a given string
 * 
 * @param qr 
 * @param desc 
 * @param verbose 
 */
void
get_qr_desc(uint8_t qr, std::string& desc, bool verbose)
{
    switch(qr){
        case QR_QUERY:
            if (verbose){
                desc = "Query (" + std::to_string(qr) + ")";
            } else {
                desc = "QUERY";
            }
            break;
        case QR_RESPONSE:
            if (verbose){
                desc = "Response (" + std::to_string(qr) + ")";
            } else {
                desc = "RESPONSE";
            }
            break;
    }
}


/**
 * @brief Get the opcode description in a given string
 * 
 * @param opcode
 * @param desc 
 * @param verbose 
 */
void
get_opcode_desc(uint8_t opcode, std::string& desc, bool verbose)
{
    switch(opcode){
        case OP_QUERY:
            if (verbose){
                desc = "Message has: Standard query (" + std::to_string(opcode) + ")";
            } else {
                desc = "op: QUERY";
            }
            break;
        case OP_IQUERY:
            if (verbose){
                desc = "Message has: Inverse query (" + std::to_string(opcode) + ")";
            } else {
                desc = "op: IQUERY";
            }
            break;
        case OP_STATUS:
            if (verbose){
                desc = "Message has: Server status request (" + std::to_string(opcode) + ")";
            } else {
                desc = "op: STATUS";
            }
            break;
        default:
            if (verbose){
                desc = "Message has: Unknown (" + std::to_string(opcode) + ")";
            } else {
                desc = "op: ?";
            }
            break;
    }
}

