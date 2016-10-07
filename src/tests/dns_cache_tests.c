#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "dns_cache.h"


int main()
{
	struct dns_cache_result_t *r = dns_cache_create();	
	
	char t[] = "1234";
	int len = 4;

	dns_cache_add_entry(r, 300, t, len);
	int *iLen;
	
	char *bin = dns_cache_serialize( r, iLen);
	
	int i;
	for(i=0;i < *iLen; i++)
	{
		printf("%u ", bin[i] & 0xff);
	}
	dns_cache_free(r);
		

}
