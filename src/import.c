#include "import.h"
#include "logger.h"

extern eredis_t *redis;

void import_file( char *filename )
{
    char *ipv4data      = malloc(sizeof(char) * IPV4LENGTH);
    char *ipv6data      = malloc(sizeof(char) * IPV6LENGTH);


    int  *iLen          = malloc(sizeof(int));
    long    importCount = 0,
            lineCount   = 0;
    FILE *fp;
    char line[MAX_LINE_LENGTH];
    char *cachebin;

    eredis_reader_t *r;

    memset(ipv4data, 0, sizeof(char) * IPV4LENGTH);
    memset(ipv6data, 0, sizeof(char) * IPV6LENGTH);

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

        memset(iLen, 0, sizeof(int));

        struct dns_cache_result_t *dns_cache = dns_cache_create();
        dns_cache_add_entry(dns_cache, DNS_TYPE_A, 65535, ipv4data, IPV4LENGTH);
        cachebin = dns_cache_serialize(dns_cache, iLen);

        /*if(eredis_text_cmd(redis, "SET h%s:%s %b", "A", line, cachebin, (size_t) * iLen) != EREDIS_OK){
            printf("Command failed: SET h%s:%s\n", "A", line);
        }*/
        eredis_r_append_cmd(r, "SET h%s:%s %b", "A", line, cachebin, *iLen);
        eredis_reply_t *reply = eredis_r_reply(r);
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