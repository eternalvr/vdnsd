#include "dns.h"
#include "config.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>


extern eredis_t *redis;

/***
 * free dns_request struct
 * @param dns
 */
void dns_request_free(struct dns_request *dns) {
    free(dns);
    dns = NULL;
}

void dns_parse_request(struct dns_request *dns, int type, DnsWorker *worker) {
    struct addrinfo *host, *p;
    struct sockaddr_storage *h = NULL;
    char *ip = NULL;
    struct dns_ctx *dns_context = NULL;
    struct timeval tval_before, tval_after, tval_result;
    gettimeofday(&tval_before, NULL);

    char *typeName = dns_cltos(type);

    switch(worker->sender->sa_family) {
        case AF_INET: {
            struct sockaddr_in *addr_in = (struct sockaddr_in *)worker->sender;
            ip = malloc(INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(addr_in->sin_addr), ip, INET_ADDRSTRLEN);
            break;
        }
        case AF_INET6: {
            struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)worker->sender;
            ip = malloc(INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(addr_in6->sin6_addr), ip, INET6_ADDRSTRLEN);
            break;
        }
        default:
            break;
    }


    int i;
    struct dns_response_t *dns_response =
            dns_response_create_from_dns_request(dns);

   if(dns_find_cached_entry(dns, type, dns_response, DNS_RRTYPE_ANSWER)) {

       dns_response_send(dns->fd, dns_response);
       gettimeofday(&tval_after, NULL);
       timersub(&tval_after, &tval_before, &tval_result);

       if(config_get_int(CONFIG_LOG_QUERIES)){
           L_DEBUG("[CACHED]: %s %s (%ld.%06ld s) from %s", typeName, dns->hostname, (long int)tval_result.tv_sec, (long int)tval_result.tv_usec, ip);
       }

       dns_response_destroy(dns_response);

       dns_request_free(dns);
       return;
   }



    int dnssize = 1024;
    char *dnsbuf = malloc(1024);
    ns_msg handle;
    //ns_sect ns_s_an;
    int *iLen = malloc(sizeof *iLen);
    ns_rr rr;
    int mx_index, ns_index, limit, msglen;
    limit = 5;
    char dispbuf[4096];

    int answlen = res_nquery(dns->worker->thread.resolv_state, dns->hostname, DNS_QCLASS_IN, type, dnsbuf, dnssize);

    if (answlen > 0 && answlen < 1024) {

        if (ns_initparse(dnsbuf, answlen, &handle) >= 0) {
            HEADER *hdr_ok = (HEADER *)dnsbuf;
            struct dns_cache_result_t *dnscache = dns_cache_create();
            msglen = ns_msg_count(handle, ns_s_an);
            for (mx_index = 0, ns_index = 0;
                 mx_index < limit && ns_index < msglen;
                 ns_index++) {
                if (ns_parserr(&handle, ns_s_an, ns_index, &rr)) {
                    continue;
                }
                dns_response_add_answer(DNS_RRTYPE_ANSWER, dns_response, rr.type, rr.rr_class, rr.ttl, (char *) rr.rdata, rr.rdlength);
                dns_cache_add_entry(dnscache, rr.type, rr.ttl, (char *) rr.rdata, rr.rdlength);
            }

            dns_cache_save(dnscache, typeName, dns->hostname, hdr_ok->rcode);

        } else {
            dns_response->flags->rcode = DNS_RCODE_SERVFAIL;
        }
    } else {
        HEADER *hdr = (HEADER *)dnsbuf;
        dns_response->flags->rcode = hdr->rcode;
        struct dns_cache_result_t *negCache = dns_cache_create();

        // Search for SOA in cache
        if(!dns_find_cached_entry(dns, DNS_TYPE_SOA, dns_response, DNS_RRTYPE_AUTHORITY)) {
            answlen = res_nquery(dns->worker->thread.resolv_state, dns->hostname, DNS_QCLASS_IN, DNS_TYPE_SOA, dnsbuf,
                                 dnssize);
            if (answlen > 0 && answlen < 1024) {
                if (ns_initparse(dnsbuf, answlen, &handle) >= 0) {
                    msglen = ns_msg_count(handle, ns_s_an);
                    for (mx_index = 0, ns_index = 0;
                         mx_index < limit && ns_index < msglen;
                         ns_index++) {
                        if (ns_parserr(&handle, ns_s_an, ns_index, &rr)) {
                            continue;
                        }
                        dns_response_add_answer(DNS_RRTYPE_AUTHORITY, dns_response, rr.type, rr.rr_class, rr.ttl,
                                                (char *) rr.rdata, rr.rdlength);
                        dns_cache_add_entry(negCache, rr.type, rr.ttl, (char *) rr.rdata, rr.rdlength);
                    }
                }
            }
        } else {
            if(config_get_int(CONFIG_LOG_QUERIES)) {
                L_DEBUG("[NCACHE]: %s %s (%ld.%06ld s) from %s", typeName, dns->hostname, (long int)tval_result.tv_sec, (long int)tval_result.tv_usec, ip);
            }

        }
        dns_cache_save(negCache, typeName, dns->hostname, hdr->rcode);
    }

    free(dnsbuf);
    dnsbuf = NULL;

    free(iLen);
    iLen = NULL;

    dns_response_send(dns->fd, dns_response);
    gettimeofday(&tval_after, NULL);
    timersub(&tval_after, &tval_before, &tval_result);

    if(config_get_int(CONFIG_LOG_QUERIES)) {
        L_DEBUG("[RESOLVE]: %s %s (%ld.%06ld s) from %s", typeName, dns->hostname, (long int) tval_result.tv_sec,
                (long int) tval_result.tv_usec, ip);
    }

    dns_response_destroy(dns_response);
    dns_request_free(dns);
    free(ip);
    ip = NULL;
}
int dns_find_cached_entry(struct dns_request *dns, int type, struct dns_response_t *dns_response, dns_rrtype_t answer_type)
{
    // CHECK if cached
    struct dns_cache_result_t *cache = cached_entry(dns->hostname, type);
    if (cache != NULL) {


        struct dns_cache_entry_t *curr;
        for (curr = cache->entry; curr != NULL; curr = curr->next) {
            if (curr->len > 0) {
                dns_response_add_answer(answer_type, dns_response, curr->type, DNS_QCLASS_IN, curr->ttl,
                                        curr->data, curr->len);
            }
        }
        dns_response->flags->rcode = cache->rCode;
        dns_cache_free(cache);
        return 1;
    }
    return 0;
}
/***
 * Entry Point for new DNS Requests
 * @param worker
 */
void dns_handle_request(DnsWorker *worker) {

    int i;
    int j = 0;
    int psize = worker->len - SIZE_DNS;
    if (psize <= 0) {
        L_WARN("WARNING: Too small to be DNS");
    }
    u_char *payload = ((u_char *) worker->dns) + SIZE_DNS;
    int qdc = htons(worker->dns->dns_qdc);

    for (i = 0; i < qdc; i++) {
        // format as cool domain name
        int isize = dns_dntop_size(payload + j);
        u_char *domain = malloc(isize); //= parseDomain(payload, &j, psize);
        int dlen = dns_dntop(payload + j, domain, isize);

        ////  u_char *domain = parseDomain (payload, &j, psize);
        j += strlen(payload + j) + 1; // move dn-size forward + \0 byte

        if (j + 4 > psize) {
            L_WARN("Question header end faulty\n");
            return;
        }
        int type = (payload[j + 1] | payload[j] << 8);

        j += 2;
        int qclass = (payload[j + 1] | payload[j] << 8);
        j += 2;

        struct dns_request *DnsRequest =
                (struct dns_request *) malloc(sizeof(*DnsRequest));
        memset(DnsRequest, 0, sizeof(*DnsRequest));

        DnsRequest->transaction_id = htons(worker->dns->dns_id);
        DnsRequest->questions_num = htons(worker->dns->dns_qdc);
        DnsRequest->flags = htons(worker->dns->dns_flags);
        DnsRequest->qtype = type;
        DnsRequest->qclass = qclass;
        DnsRequest->fd = worker->fd;
        DnsRequest->hostname_len = strlen(domain) + 1;
        DnsRequest->sender = worker->sender;
        DnsRequest->sendersize = worker->sendersize;
        DnsRequest->worker = worker;

        strncpy(DnsRequest->hostname, domain, strlen(domain));

        memset(DnsRequest->query, 0, sizeof(DnsRequest->query));
        memcpy(DnsRequest->query, payload, psize);

        dns_parse_request(DnsRequest, type, worker);
        free(domain);
        domain = NULL;
    }
}

int dns_response_send(int sd, struct dns_response_t *dns) {
    uint16_t *packetSize = malloc(sizeof(*packetSize));
    int i = 0;
    char *packet = dns_response_get_packet(dns, packetSize);

    /*printf("[NEW] Sending packet of size %i: ", *packetSize);
    for(i = 0; i < *packetSize;i++) {
        printf(" %c (%u),", packet[i], packet[i] & 0xff);
    }
    printf("\n\n");
    */

    struct sockaddr *sa = (struct sockaddr *) dns->req->sender;
    int bytes_sent = 0;
    //int bytes_sent = sendto(sd, packet, *packetSize, MSG_DONTWAIT, sa, dns->req->sendersize);

    worker_send(dns->req->worker, packet, *packetSize);

    //free(sa);
    free(packetSize);
    packetSize = NULL;

    free(packet);
    packet = NULL;
}

struct dns_response_t *dns_response_create() {
    struct dns_response_t *dns_response = malloc(sizeof *dns_response);
    memset(dns_response, 0, sizeof(*dns_response));
    dns_response->flags = malloc(sizeof(dns_response->flags));
    memset(dns_response->flags, 0, sizeof(dns_response->flags));

    return dns_response;
}

struct dns_response_t * dns_response_create_from_dns_request(struct dns_request *dns_req) {
    struct dns_response_t *dns_r = dns_response_create();

    dns_r->txid = dns_req->transaction_id;

    dns_r->flags->qrflag = DNS_QR_RESPONSE;
    dns_r->flags->opcode = DNS_OPCODE_QUERY;
    dns_r->flags->aa = DNS_AA_NONAUTH;
    dns_r->flags->trflag = DNS_TC_UNTRUNCATED;
    dns_r->flags->rec = DNS_REC_RECURSION;
    dns_r->flags->rec_avail = DNS_RECAVAIL_AVAIL;
    dns_r->flags->rcode = DNS_RCODE_NOERROR;

    dns_r->question_count = dns_req->questions_num;
    dns_r->answer_count = 0;
    dns_r->authority_count = 0;

    dns_r->ar_count = 0;

    dns_r->question = malloc(sizeof(*dns_r->question));
    dns_r->question->qname = malloc(sizeof(dns_req->query));

    strncpy(dns_r->question->qname, dns_req->query, sizeof(dns_req->query));
    uint8_t offset = strlen(dns_r->question->qname) + 1; // skip \0 byte

    dns_r->question->qtype = ((uint16_t) dns_req->query[offset] << 8) | (dns_req->query[offset + 1] & 0xff);
    offset += 2;

    dns_r->question->qclass =
            (dns_req->query[offset + 1] | dns_req->query[offset] << 8);
    dns_r->question->qnamelength = strlen(dns_r->question->qname);

    dns_r->req = dns_req;
    dns_r->rr = NULL;
    return dns_r;
}

void dns_response_add_answer(dns_rrtype_t answer_type, struct dns_response_t *dns_r, uint16_t type,
                             uint16_t cls, uint32_t ttl, char *data,
                             uint16_t datalength) {
    if (data == NULL)
        return;


    // construct answer
    struct dns_response_answer_t *answer = malloc(sizeof *answer);
    answer->type = type;
    answer->aclass = cls;
    answer->ttl = ttl;
    answer->rdatalen = datalength;

    answer->rdata = malloc(datalength);
    memcpy(answer->rdata, data, datalength);




    switch(answer_type){
        case DNS_RRTYPE_ANSWER:
            dns_r->answer_count++;
            if (dns_r->answer_count > 1) {
                dns_r->rr = realloc(dns_r->rr, sizeof(struct dns_response_answer_t *) *
                                               dns_r->answer_count);
            } else {
                dns_r->rr = malloc(sizeof(struct dns_response_t *) * dns_r->answer_count);
                memset(dns_r->rr, 0, sizeof(struct dns_response_t *) * dns_r->answer_count);
            }
            dns_r->rr[dns_r->answer_count - 1] = answer;
            break;
        case DNS_RRTYPE_AUTHORITY:
            dns_r->authority_count++;
            if (dns_r->authority_count > 1) {
                dns_r->authr = realloc(dns_r->authr, sizeof(struct dns_response_answer_t *) *
                                               dns_r->authority_count);
            } else {
                dns_r->authr = malloc(sizeof(struct dns_response_t *) * dns_r->authority_count);
                memset(dns_r->authr, 0, sizeof(struct dns_response_t *) * dns_r->authority_count);
            }
            dns_r->authr[dns_r->authority_count - 1] = answer;
            break;
        case DNS_RRTYPE_ADDITIONAL:
            dns_r->ar_count++;
            if (dns_r->ar_count > 1) {
                dns_r->ar = realloc(dns_r->ar, sizeof(struct dns_response_answer_t *) *
                                               dns_r->ar_count);
            } else {
                dns_r->ar = malloc(sizeof(struct dns_response_t *) * dns_r->ar_count);
                memset(dns_r->ar, 0, sizeof(struct dns_response_t *) * dns_r->ar_count);
            }
            dns_r->ar[dns_r->ar_count - 1] = answer;
            break;
    }


}

void dns_response_destroy(struct dns_response_t *dns) {
    if (dns == NULL) {

        return;
    }

    free(dns->flags);
    dns->flags = NULL;

    free(dns->question->qname);
    dns->question->qname = NULL;

    free(dns->question);
    dns->question = NULL;

    if (dns->rr != NULL && dns->answer_count > 0) {
        int i = 0;
        for (i = 0; i < dns->answer_count; i++) {
            if (dns->rr[i]->rdatalen > 0) {
                free(dns->rr[i]->rdata);
                dns->rr[i]->rdata = NULL;
            }
            free(dns->rr[i]);
            dns->rr[i] = NULL;
        }
        free(dns->rr);
        dns->rr = NULL;
    }

    free(dns);
    dns = NULL;
}

char *dns_response_get_packet(struct dns_response_t *dns, uint16_t *datalen) {
    char *response_ptr;
    int i;
    char *response = malloc(1024);

    memset(response, 0, 1024);
    response_ptr = response;

    // header
    // TX ID

    response[0] = (uint8_t)(dns->txid >> 8);
    response[1] = (uint8_t) dns->txid;
    response += 2;

    int b = (dns->flags->data);
    // printf("Flags: %u", dns->flags->data & 0xff);
    // flags 16bit
    response[0] = (uint8_t)(b >> 8);
    response[1] = (uint8_t) b;
    response += 2;

    // question count
    response[0] = (uint8_t)(dns->question_count >> 8);
    response[1] = (uint8_t) dns->question_count;
    response += 2;

    // answer count
    response[0] = (uint8_t)(dns->answer_count >> 8);
    response[1] = (uint8_t) dns->answer_count;
    response += 2;

    // Authority RRs
    response[0] = (uint8_t)(dns->authority_count >> 8);
    response[1] = (uint8_t) dns->authority_count;
    response += 2;

    // Additional RRs
    response[0] = (uint8_t)(dns->ar_count >> 8);
    response[1] = (uint8_t) dns->ar_count;
    response += 2;


    // QUESTION SECTOR

    strncat(response, dns->question->qname, dns->question->qnamelength);
    response += dns->question->qnamelength + 1;

    int qtype = htons(dns->question->qtype);
    /* Type */
    response[1] = (uint8_t)(qtype >> 8);
    response[0] = (uint8_t) qtype;
    response += 2;

    /* Class */
    response[0] = (uint8_t)(dns->question->qclass >> 8);
    response[1] = (uint8_t) dns->question->qclass;
    response += 2;

    // RR
    char *rrbytes = NULL;
    int rrlen = 0;

    for (i = 0; i < dns->answer_count; i++) {
        rrlen = _dns_rr_get_bytes(dns->rr[i], &rrbytes);
        memcpy(response, rrbytes, rrlen);
        response+=rrlen;
        free(rrbytes);
        rrbytes = NULL;
    }
    for(i=0;i<dns->authority_count;i++) {
        rrlen = _dns_rr_get_bytes(dns->authr[i], &rrbytes);
        memcpy(response, rrbytes, rrlen);
        response+=rrlen;
        free(rrbytes);
        rrbytes = NULL;
    }
    for(i=0;i<dns->ar_count;i++) {
        rrlen = _dns_rr_get_bytes(dns->authr[i], &rrbytes);
        memcpy(response, rrbytes, rrlen);
        response+=rrlen;
        free(rrbytes);
        rrbytes = NULL;
    }

    *datalen = (int) (response - response_ptr);

    return response_ptr;
}
int _dns_rr_get_bytes( struct dns_response_answer_t *answer, char **retStart)
{
    char *retBuf = malloc(sizeof(char)*(12+answer->rdatalen));
    *retStart = retBuf;
    int idx = 0;

    retBuf[idx++] = 0xc0; // pointer to host
    retBuf[idx++] = 0x0c;

    // Qtype (A = 1, AAAA = 28)
    retBuf[idx++] = (uint8_t)(answer->type >> 8);
    retBuf[idx++] = (uint8_t)(answer->type);

    // Class (1 = IN)
    retBuf[idx++] = (uint8_t)(answer->aclass >> 8);
    retBuf[idx++] = (uint8_t)(answer->aclass);

    // TTL 32 bit
    retBuf[idx++] = (uint8_t)(answer->ttl >> 24);
    retBuf[idx++] = (uint8_t)(answer->ttl >> 16);
    retBuf[idx++] = (uint8_t)(answer->ttl >> 8);
    retBuf[idx++] = (uint8_t)(answer->ttl);

    // RDataLength
    int rdlen = (answer->rdatalen);

    retBuf[idx++] = (uint8_t)(rdlen >> 8);
    retBuf[idx++] = (uint8_t)(rdlen);

    retBuf += idx;

    // RData
    memcpy(retBuf, answer->rdata, answer->rdatalen);
    retBuf += answer->rdatalen;

    return retBuf - *retStart;
}
struct dns_cache_result_t *cached_entry(char *hostname, uint8_t type) {


    eredis_reply_t *erep = eredis_text_cmd(redis, "GET h%s:%s", dns_cltos(type), hostname);

    if (erep == NULL) {
        return NULL;
    }

    if (erep->type == REDIS_REPLY_STRING) {

        struct dns_cache_result_t *s = dns_cache_unserialize(erep->str, erep->len);

        eredis_reply_free(erep);
        return s;
    }
    eredis_reply_free(erep);
    return NULL;
}

unsigned dns_dntop_size(char *dn) {
    unsigned size = 0;        /* the size reqd */
    char *le;            /* label end */

    while (*dn) {
        /* *dn is the length of the next label, non-zero */
        if (size)
            ++size;        /* for the dot */
        le = dn + *dn + 1;
        ++dn;
        do {
            switch (*dn) {
                case '.':
                case '\\':
                    /* Special modifiers in zone files. */
                case '"':
                case ';':
                case '@':
                case '$':
                    size += 2;
                    break;
                default:
                    if (*dn <= 0x20 || *dn >= 0x7f)
                        /* \ddd decimal notation */
                        size += 4;
                    else
                        size += 1;
            }
        } while (++dn < le);
    }
    size += 1;    /* zero byte at the end - string terminator */
    return size > 1024 ? 0 : size;
}

int dns_dntop(char *dn, char *name, unsigned namesiz) {
    char *np = name;            /* current name ptr */
    char *const ne = name + namesiz;    /* end of name */
    char *le;        /* label end */

    while (*dn) {
        /* *dn is the length of the next label, non-zero */
        if (np != name) {
            if (np >= ne) goto toolong;
            *np++ = '.';
        }
        le = dn + *dn + 1;
        ++dn;
        do {
            switch (*dn) {
                case '.':
                case '\\':
                    /* Special modifiers in zone files. */
                case '"':
                case ';':
                case '@':
                case '$':
                    if (np + 2 > ne) goto toolong;
                    *np++ = '\\';
                    *np++ = *dn;
                    break;
                default:
                    if (*dn <= 0x20 || *dn >= 0x7f) {
                        /* \ddd decimal notation */
                        if (np + 4 >= ne) goto toolong;
                        *np++ = '\\';
                        *np++ = '0' + (*dn / 100);
                        *np++ = '0' + ((*dn % 100) / 10);
                        *np++ = '0' + (*dn % 10);
                    } else {
                        if (np >= ne) goto toolong;
                        *np++ = *dn;
                    }
            }
        } while (++dn < le);
    }
    if (np >= ne) goto toolong;
    *np++ = '\0';
    return np - name;
    toolong:
    return namesiz >= 1024 ? -1 : 0;
}

char *dns_cltos(int class) {
    switch (class) {
        case DNS_TYPE_A:
            return "A";
        case DNS_TYPE_AAAA:
            return "AAAA";
        case DNS_TYPE_ANY:
            return "ANY";
        case DNS_TYPE_CNAME:
            return "CNAME";
        case DNS_TYPE_HINFO:
            return "HINFO";
        case DNS_TYPE_MB:
            return "MB";
        case DNS_TYPE_MD:
            return "MD";
        case DNS_TYPE_MF:
            return "MF";
        case DNS_TYPE_MG:
            return "MG";
        case DNS_TYPE_MINFO:
            return "MINFO";
        case DNS_TYPE_MR:
            return "MR";
        case DNS_TYPE_MX:
            return "MX";
        case DNS_TYPE_NS:
            return "NS";
        case DNS_TYPE_PTR:
            return "PTR";
        case DNS_TYPE_SOA:
            return "SOA";
        case DNS_TYPE_TXT:
            return "TXT";
        case DNS_TYPE_NULL:
            return "NULL";
        default:
            return "U";
    }
}