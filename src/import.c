#include "import.h"
#include "config.h"

extern eredis_t *redis;

void import_file( char *filename )
{
    char *ipv4data      = malloc(sizeof(char) * IPV4LENGTH);
    char *ipv6data      = malloc(sizeof(char) * IPV6LENGTH);

    unsigned char bin_ipv4[sizeof(struct in_addr)];
    unsigned char bin_ipv6[sizeof(struct in6_addr)];

    int  *iLen          = malloc(sizeof(int));
    long    importCount = 0,
            lineCount   = 0;
    FILE *fp;
    char line[MAX_LINE_LENGTH];
    char *cachebin;
    int use_adspoof_ip = 0;

    eredis_reader_t *r;

    memset(ipv4data, 0, sizeof(char) * IPV4LENGTH);
    memset(ipv6data, 0, sizeof(char) * IPV6LENGTH);

    char *adspoof_ipv4 = config_get_string(CONFIG_ADSPOOF_IPV4);
    if(!inet_pton(AF_INET, adspoof_ipv4, bin_ipv4)){
        L_WARN("adspoof_ipv4 is not a valid IPv4: %s", adspoof_ipv4);
    }
    char *adspoof_ipv6 = config_get_string(CONFIG_ADSPOOF_IPV6);
    if(!inet_pton(AF_INET6, adspoof_ipv6, bin_ipv6)){
        L_WARN("adspoof_ipv6 is not a valid IPv6: %s", adspoof_ipv6);
    }
    r = eredis_r(redis);


    fp = fopen(filename, "r");

    if(fp == NULL) {
        fprintf(stderr, "Could not open file: %s\n", filename);
        exit(1);
    }

    while(fgets(line, MAX_LINE_LENGTH, fp)) {
        lineCount++;

        if(line[0] == '#') { // strip comments
            continue;
        }
        if( strpbrk(line, ".") == NULL) { // line does not contain a domain
            L_WARN("[%s:%ld] Invalid Entry, no '.' found", filename, lineCount);
            continue;
        }
        if(strpbrk(line, " ")) {
            L_WARN("[%s:%ld] Forbidden whitespace found", filename, lineCount);
            continue;
        }

        line[strcspn(line, "\n")] = 0; // remove newline at the end
        if(line[0] == '!'){
            use_adspoof_ip = 1;
            memmove(line, line+1, strlen(line));
        } else {
            use_adspoof_ip = 0;
        }

        memset(iLen, 0, sizeof(int));



        // create A RECORD
        struct dns_cache_result_t *dns_cache = dns_cache_create();
        if(use_adspoof_ip) {
            dns_cache_add_entry(dns_cache, DNS_TYPE_A, 65535, bin_ipv4, IPV4LENGTH);
        } else {
            dns_cache_add_entry(dns_cache, DNS_TYPE_A, 65535, ipv4data, IPV4LENGTH);
        }
        cachebin = dns_cache_serialize(dns_cache, iLen);
        eredis_r_append_cmd(r, "SET h%s:%s %b", "A", line, cachebin, *iLen);
        eredis_reply_t *reply = eredis_r_reply(r);
        free(cachebin);
        cachebin = NULL;
        dns_cache_free(dns_cache);

        // create AAAA RECORD
        struct dns_cache_result_t *dns_cache6 = dns_cache_create();
        if(use_adspoof_ip) {
            dns_cache_add_entry(dns_cache6, DNS_TYPE_AAAA, 65535, bin_ipv6, IPV6LENGTH);
        } else {
            dns_cache_add_entry(dns_cache6, DNS_TYPE_AAAA, 65535, ipv6data, IPV6LENGTH);
        }
        cachebin = dns_cache_serialize(dns_cache6, iLen);
        eredis_r_append_cmd(r, "SET h%s:%s %b", "AAAA", line, cachebin, *iLen);
        eredis_reply_t *reply6 = eredis_r_reply(r);

        free(cachebin);
        cachebin = NULL;
        dns_cache_free(dns_cache);


        importCount++;
    }

    eredis_r_clear(r);


    L_INFO("Import completed. %ld hosts imported\n", importCount);

    free(iLen);
    iLen = NULL;

    free(ipv4data);
    ipv4data = NULL;

    free(ipv6data);
    ipv6data = NULL;

    eredis_r_release(r);
}