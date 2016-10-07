//
// Created by vr on 30.09.2016.
//

#ifndef VDNS_IMPORT_H
#define VDNS_IMPORT_H

#include "redis.h"
#include "dns.h"
#include "dns_cache.h"

#define MAX_LINE_LENGTH 256
#define IPV4LENGTH 4
#define IPV6LENGTH 16
#define CACHEBINLENGTH 32

void import_file( char *filename );

#endif //VDNS_IMPORT_H
