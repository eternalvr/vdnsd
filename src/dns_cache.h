#pragma once
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


struct dns_cache_result_t
{
        uint8_t numEntries;
		uint8_t rCode;
        struct dns_cache_entry_t *entry;
};


struct dns_cache_entry_t
{
	uint8_t type;
	uint16_t ttl;
	char *data;
	uint8_t len;
	struct dns_cache_entry_t *next;
};

struct dns_cache_result_t *dns_cache_create();
void dns_cache_add_entry(struct dns_cache_result_t *res, uint8_t type, uint16_t ttl, char *data, int datalen);
char *dns_cache_serialize(struct dns_cache_result_t *res, int *l);
void dns_cache_free( struct dns_cache_result_t *res );
void dns_cache_result_dump( struct dns_cache_result_t *res);
struct dns_cache_result_t * dns_cache_unserialize(char *data, int len);
void dns_cache_save(struct dns_cache_result_t *dnscache, char *typeName, char *hostname, uint8_t rcode);