#include "dns_cache.h"
#include "dns.h"
extern eredis_t *redis;
struct dns_cache_result_t *dns_cache_create() {
    struct dns_cache_result_t *dr = malloc(sizeof(*dr));
    memset(dr, 0, sizeof(*dr));
    struct dns_cache_entry_t *head = malloc(sizeof(*head));
    dr->rCode = DNS_RCODE_NOERROR;
    head->len = 0;
    head->next = 0;
    head->data = 0;

    dr->entry = head;

    return dr;
}


void dns_cache_add_entry(struct dns_cache_result_t *res, uint8_t type, uint16_t ttl,
                         char *data, int datalen) {

    res->numEntries++;
    // printf("\n[DNS CACHE][%u] Adding Entry TTL %u LEN %u\n", res->numEntries,
    // ttl, datalen);
    struct dns_cache_entry_t *new_entry = malloc(sizeof(*new_entry));

    char *newData = malloc(datalen);
    memcpy(newData, data, datalen);

    new_entry->type = type;
    new_entry->ttl = ttl;
    new_entry->data = newData;
    new_entry->next = 0;
    new_entry->len = datalen;

    struct dns_cache_entry_t *c = res->entry;
    while (c->next != NULL)
        c = c->next;
    c->next = new_entry;
}

char *dns_cache_serialize(struct dns_cache_result_t *res, int *l) {
    char *t = malloc(sizeof(char) * 1024);
    char *tStart = t;

    t[0] = res->numEntries;
    t[1] = res->rCode;
    t += 2;

    uint8_t i = 0;
    struct dns_cache_entry_t *c;
    for (c = res->entry; c != NULL; c = c->next) {
        if (c->len != 0) {
            t[0] = c->type;
            t[1] = (uint8_t) (c->ttl << 8);
            t[2] = (uint8_t) (c->ttl);
            t[3] = (uint8_t) (c->len << 8);
            t[4] = (uint8_t) (c->len);
            t += 5;

            memcpy(t, c->data, c->len);
            t += c->len;
        }
    }
    *l = t - tStart;

    char *r = malloc(*l);
    memcpy(r, tStart, *l);

    free(tStart);
    tStart = NULL;

    return r;
}

struct dns_cache_result_t *dns_cache_unserialize(char *data, int len) {
    if (len == 0) {

        return NULL;
    }
    struct dns_cache_result_t *res = dns_cache_create();

    int idx = 0;
    res->numEntries = (uint8_t) data[idx++];
    res->rCode = (uint8_t) data[idx++];

    while (idx < len) {
        uint8_t type = data[idx];
        idx++;

        uint16_t ttl = (data[idx + 1] << 8 | data[idx]);
        idx += sizeof(ttl);

        uint16_t len_data = (data[idx + 1] | data[idx] << 8);
        idx += sizeof(uint16_t);

        char *b = malloc(len_data);
        memcpy(b, &data[idx], len_data);

        dns_cache_add_entry(res, type, ttl, b, len_data);
        free(b);
        b = NULL;

        idx += len_data;
    }
    // printf("\nUNSERIALIZE\n\n");
    // dns_cache_result_dump(res);
    return res;
}


void dns_cache_free(struct dns_cache_result_t *res) {
    int i = 0;
    struct dns_cache_entry_t *curr, *head;
    head = res->entry;

    while ((curr = head) != NULL) {
        head = head->next;

        if (curr->data) {
            free(curr->data);
            curr->data = NULL;
        }

        free(curr);
        curr = NULL;


    }
    free(res);
    res = NULL;
}

void dns_cache_result_dump(struct dns_cache_result_t *res) {
    int i = 0;

    printf("\n\n ==== DNS CACHE RESULT ====\n\n");
    printf("Entries: %d\n", res->numEntries);
    struct dns_cache_entry_t *curr;
    for (curr = res->entry; curr != NULL; curr = curr->next) {
        printf(" TTL %d LEN %d DATA ", curr->ttl, curr->len);
        for (i = 0; i < curr->len; i++) {
            printf("%u, ", curr->data[i] & 0xff);
        }
        printf("\n");
    }

    printf(" ==== END DNS CACHE RESULT ====\n\n");
}

void dns_cache_save(struct dns_cache_result_t *dnscache, char *typeName, char *hostname, uint8_t rcode) {


    int iLen = 0;
    int ttl = 60;
    dnscache->rCode = rcode;
    char *cachebin = dns_cache_serialize(dnscache, &iLen);
    eredis_text_update(redis, "SET h%s:%s %b", typeName, hostname, cachebin, (size_t) iLen);
    if(dnscache->numEntries > 0) {
        if(dnscache->entry->next->ttl > 0) {
            ttl = dnscache->entry->next->ttl;
        }
    }
    if(dnscache->rCode == DNS_RCODE_NXDOMAIN) {
        ttl = 60;
    }
    eredis_text_update(redis, "EXPIRE h%s:%s %d", typeName, hostname, ttl);
    free(cachebin);
    cachebin = NULL;


    dns_cache_free(dnscache);
}