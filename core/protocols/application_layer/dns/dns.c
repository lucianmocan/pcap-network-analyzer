#include "dns.h"



my_dns_header_t 
parse_dns(const uint8_t *packet, bool verbose)
{
    my_dns_header_t dns_header;
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

    return dns_header;
}

void
free_dns_header(my_dns_header_t *dns_header)
{
    // free_list(dns_header->name);
}

// void
// get_dns_name(const uint8_t *packet, my_dns_header_t *dns_header)
// {
//     int i = 0;
//     while (packet[i] != 0){
//         dns_label_t *label = malloc(sizeof(dns_label_t));
//         printf("Label length: %d\n", packet[i]);
//         label->length = packet[i];
//         strncpy((char*)label->value, (char*)packet + i + 1, label->length);
//         label->value[label->length] = '\0';
//         snprintf(label->value_desc, DNS_LABEL_MAX_SIZE + 1, "%s", label->value);
//         printf("Label: %s\n", label->value_desc);
//         dns_header->name = add_node(dns_header->name, (void*)label);
//         i += label->length + 1;
//     }
// }

/**
 * @brief Get the ra description in a given string
 * 
 * @param ra 
 * @param desc 
 * @param verbose 
 */
void 
get_ra_desc(uint8_t ra, char *desc, bool verbose)
{
    switch(ra){
        case 1:
            if (verbose){
                snprintf(desc, OPCODE_DESC_SIZE, "Recursion available (%d)", ra);
            } else {
                snprintf(desc, OPCODE_DESC_SIZE, "Rec");
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
get_rd_desc(uint8_t rd, char *desc, bool verbose)
{
    switch(rd){
        case 1:
            if (verbose){
                snprintf(desc, OPCODE_DESC_SIZE, "Recursion desired (%d)", rd);
            } else {
                snprintf(desc, OPCODE_DESC_SIZE, "Recursion");
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
get_tc_desc(uint8_t tc, char *desc, bool verbose)
{
    switch(tc){
        case 1:
            if (verbose){
                snprintf(desc, OPCODE_DESC_SIZE, "Truncated (%d)", tc);
            } else {
                snprintf(desc, OPCODE_DESC_SIZE, "Trunc");
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
get_aa_desc(uint8_t aa, char *desc, bool verbose)
{
    switch(aa){
        case 1:
            if (verbose){
                snprintf(desc, OPCODE_DESC_SIZE, "Authoritative (%d)", aa);
            } else {
                snprintf(desc, OPCODE_DESC_SIZE, "Auth");
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
get_rcode_desc(uint8_t rcode, char *desc, bool verbose)
{   
    // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    switch(rcode){
        case RCODE_NO_ERROR:
            if (verbose){
                snprintf(desc, RCODE_DESC_SIZE, "No error (%d)", rcode);
            } else {
                snprintf(desc, RCODE_DESC_SIZE, "res: 0 !");
            }
            break;
        case RCODE_FORMAT_ERROR:
            if (verbose){
                snprintf(desc, RCODE_DESC_SIZE, "Format error (%d)", rcode);
            } else {
                snprintf(desc, RCODE_DESC_SIZE, "res: format !");
            }
            break;
        case RCODE_SERVER_FAILURE:
            if (verbose){
                snprintf(desc, RCODE_DESC_SIZE, "Server failure (%d)", rcode);
            } else {
                snprintf(desc, RCODE_DESC_SIZE, "res: server !");
            }
            break;
        case RCODE_NAME_ERROR:
            if (verbose){
                snprintf(desc, RCODE_DESC_SIZE, "Name error (%d)", rcode);
            } else {
                snprintf(desc, RCODE_DESC_SIZE, "res: name !");
            }
            break;
        case RCODE_NOT_IMPLEMENTED:
            if (verbose){
                snprintf(desc, RCODE_DESC_SIZE, "Not implemented (%d)", rcode);
            } else {
                snprintf(desc, RCODE_DESC_SIZE, "res: !impl");
            }
            break;
        case RCODE_REFUSED:
            if (verbose){
                snprintf(desc, RCODE_DESC_SIZE, "Refused (%d)", rcode);
            } else {
                snprintf(desc, RCODE_DESC_SIZE, "res: X");
            }
            break;
        default:
            if (verbose){
                snprintf(desc, RCODE_DESC_SIZE, "Unknown (%d)", rcode);
            } else {
                snprintf(desc, RCODE_DESC_SIZE, "res: ?");
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
get_qr_desc(uint8_t qr, char *desc, bool verbose)
{
    switch(qr){
        case QR_QUERY:
            if (verbose){
                snprintf(desc, QR_DESC_SIZE, "Query (%d)", qr);
            } else {
                snprintf(desc, QR_DESC_SIZE, "QUERY");
            }
            break;
        case QR_RESPONSE:
            if (verbose){
                snprintf(desc, QR_DESC_SIZE, "Response (%d)", qr);
            } else {
                snprintf(desc, QR_DESC_SIZE, "RESPONSE");
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
get_opcode_desc(uint8_t opcode, char *desc, bool verbose)
{
    switch(opcode){
        case OP_QUERY:
            if (verbose){
                snprintf(desc, QR_DESC_SIZE, "Message has: Standard query (%d)", opcode);
            } else {
                snprintf(desc, QR_DESC_SIZE, "op: QUERY");
            }
            break;
        case OP_IQUERY:
            if (verbose){
                snprintf(desc, QR_DESC_SIZE, "Message has: Inverse query (%d)", opcode);
            } else {
                snprintf(desc, QR_DESC_SIZE, "op: IQUERY");
            }
            break;
        case OP_STATUS:
            if (verbose){
                snprintf(desc, QR_DESC_SIZE, "Message has: Server status request (%d)", opcode);
            } else {
                snprintf(desc, QR_DESC_SIZE, "op: STATUS");
            }
            break;
        default:
            if (verbose){
                snprintf(desc, QR_DESC_SIZE, "Message has: Unknown (%d)", opcode);
            } else {
                snprintf(desc, QR_DESC_SIZE, "op: ?");
            }
            break;
    }
}

