#pragma once

#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>



#include <netinet/in.h>
#include <arpa/inet.h>
//#include <arpa/nameser.h>
#include <resolv.h>

#include <pthread.h>

#include "dnsworker.h"
#include "redis.h"
//#include "udns/udns.h"

#include "dns_cache.h"
#include "logger.h"

#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_MD 3
#define DNS_TYPE_MF 4
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_SOA 6
#define DNS_TYPE_MB 7
#define DNS_TYPE_MG 8
#define DNS_TYPE_MR 9
#define DNS_TYPE_NULL 10
#define DNS_TYPE_WKS 11
#define DNS_TYPE_PTR 12
#define DNS_TYPE_HINFO 13
#define DNS_TYPE_MINFO 14
#define DNS_TYPE_MX 15
#define DNS_TYPE_TXT 16
#define DNS_TYPE_AAAA 28
#define DNS_TYPE_ANY 255

#define DNS_RRTYPE_ANSWER 0
#define DNS_RRTYPE_AUTHORITY 1
#define DNS_RRTYPE_ADDITIONAL 2

#define UDP_DATAGRAM_SIZE   512
#define DNS_MODE_ANSWER     1
#define DNS_MODE_ERROR      2
#define DNS_MODE_NXDOMAIN   3

typedef uint8_t dns_rrtype_t;

#define DNS_QUERY_ALLOC 128
/* DNS header */
#pragma pack(1)
struct sniff_dns {
    u_short dns_id;
    u_short dns_flags;
    u_short dns_qdc;
    u_short dns_anc;
    u_short dns_nsc;
    u_short dns_arc;
};

struct dns_request
{
    uint16_t transaction_id,
             questions_num,
             flags,
             qtype,
             qclass;
    char hostname[128],
         query[DNS_QUERY_ALLOC];
    size_t hostname_len;
    int    fd;
    struct sockaddr *sender;
    int	   sendersize;
    DnsWorker *worker;
};  
#pragma pack(1)
struct dns_response_flags_t
{
	union {
		uint16_t data;
		struct {
			/*uint8_t qrflag:1; // query response flag
			uint8_t opcode:4; // opcode
			uint8_t aa:1; 	// authorative answer
			uint8_t trflag:1; // truncated flag
			uint8_t rec:1;    // recursion desired
			uint8_t rec_avail:1; // recursion available
			uint8_t reserved:3;
			uint8_t rcode:4; // response codeÜ*/

			uint8_t rcode:4; // response code
			uint8_t reserved:3;
			uint8_t rec_avail:1; // recursion available
			uint8_t rec:1;    // recursion desired
			uint8_t trflag:1; // truncated flag
			uint8_t aa:1; 	// authorative answer
			uint8_t opcode:4; // opcode
			uint8_t qrflag:1; // query response flag //Reversed
		};
	};
	
};
struct dns_response_t
{
	uint16_t txid;
	struct dns_response_flags_t *flags;
	uint16_t question_count;
	uint16_t answer_count;
	uint16_t authority_count;
	uint16_t ar_count; // additional record count

	struct dns_response_question_t *question;
	struct dns_response_answer_t **rr;
    struct dns_response_answer_t **authr;
    struct dns_response_answer_t **ar;

	
	struct dns_request *req;
};
#pragma pack(1)
struct dns_response_question_t {
	char *qname;
	uint16_t qtype;
	uint16_t qclass;
	uint8_t qnamelength;
};

struct dns_response_answer_t {
	char 	*name;
	uint16_t type;
	uint16_t aclass;
	uint32_t ttl;
	uint16_t rdatalen;
	char 	 *rdata;
	
};



#define DNS_QR_QUERY 0
#define DNS_QR_RESPONSE 1

#define DNS_OPCODE_QUERY 0
#define DNS_OPCODE_IQUERY 1
#define DNS_OPCODE_STATUS 2
#define DNS_OPCODE_RES 3
#define DNS_OPCODE_NOTIFY 4
#define DNS_OPCODE_UPDATE 5

#define DNS_AA_AUTH 1
#define DNS_AA_NONAUTH 0

#define DNS_TC_TRUNCATED 1
#define DNS_TC_UNTRUNCATED 0

#define DNS_REC_RECURSION 1
#define DNS_REC_NORECURSION 0

#define DNS_RECAVAIL_AVAIL 1
#define DNS_RECAVAIL_UNAVAIL 0

#define DNS_RCODE_NOERROR 0
#define DNS_RCODE_FORMATERROR 1
#define DNS_RCODE_SERVFAIL 2
#define DNS_RCODE_NXDOMAIN 3
#define DNS_RCODE_NOTIMPL 4
#define DNS_RCODE_REFUSED 5
#define DNS_RCODE_YXDOMAIN 6
#define DNS_RCODE_YXRRSET 7
#define DNS_RCODE_NXRRSET 8
#define DNS_RCODE_NOTAUTH 9
#define DNS_RCODE_NOTZONE 10

#define DNS_QTYPE_A 1
#define DNS_QTYPE_NS 2
#define DNS_QTYPE_CNAME 5
#define DNS_QTYPE_SOA 6
#define DNS_QTYPE_WKS 11
#define DNS_QTYPE_PTR 12
#define DNS_QTYPE_MX 15
#define DNS_QTYPE_SRV 33
#define DNS_QTYPE_AAAA 28
#define DNS_QTYPE_ANY 255

#define DNS_QCLASS_IN 1

#define SIZE_DNS sizeof(struct sniff_dns)


void dns_handle_request(DnsWorker *worker);
static struct addrinfo *resolve_host(char *hostname, uint16_t port, uint8_t use_ipv6);
void dns_parse_request(struct dns_request *dns, int type, DnsWorker *worker);
void dns_build_response(int sd, struct dns_request *dns_req, const char *ip, int mode, struct sockaddr_storage *addr);
struct dns_response_t *dns_response_create();
struct dns_response_t *dns_response_create_from_dns_request( struct dns_request *dns_req );
void dns_response_destroy( struct dns_response_t *dns );
void dns_response_add_answer(dns_rrtype_t answer_type, struct dns_response_t *dns_r, uint16_t type,
                             uint16_t cls, uint32_t ttl, char *data,
                             uint16_t datalength);
char *dns_response_get_packet(struct dns_response_t *dns, uint16_t *datalen);
int dns_response_send(int sd, struct dns_response_t *dns);
struct dns_cache_result_t *cached_entry( char *hostname, uint8_t type);
unsigned dns_dntop_size(char *dn);
int dns_dntop(char *dn, char *name, unsigned namesiz);
char *dns_cltos(int class);
void _dns_response_add_rr( struct dns_response_answer_t *answer, char **response);
int dns_find_cached_entry(struct dns_request *dns, int type, struct dns_response_t *dns_response, dns_rrtype_t answer_type);
