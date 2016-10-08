#pragma once
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

struct config_t {
    char *configfile;
    int num_threads;
    char *port;
    char *importfile;
    char *redis_host;
    char *logfile;
    int redis_port;
    int reset_on_start;
    int daemonize;
    int import_on_start;
    char *euser;
    char *egrp;
    char *pidfile;
    int log_queries;
    char *captive_ipv4;
    char *captive_ipv6;
    char *adspoof_ipv4;
    char *adspoof_ipv6;


};

#define CONFIG_NUM_THREADS          0x00
#define CONFIG_PORT                 0x01
#define CONFIG_IMPORTFILE           0x02
#define CONFIG_RESET_ON_START       0x03
#define CONFIG_DAEMONIZE            0x04
#define CONFIG_REDIS_HOST           0x05
#define CONFIG_REDIS_PORT           0x06
#define CONFIG_IMPORT_ON_START      0x07
#define CONFIG_CONFIGFILE           0x08
#define CONFIG_LOGFILE              0x09
#define CONFIG_EUSER                0x10
#define CONFIG_EGRP                 0x11
#define CONFIG_PIDFILE              0x12
#define CONFIG_LOG_QUERIES          0x13
#define CONFIG_CAPTIVE_IPV4           0x14
#define CONFIG_ADSPOOF_IPV4           0x15
#define CONFIG_CAPTIVE_IPV6           0x16
#define CONFIG_ADSPOOF_IPV6           0x17

void config_initialize();
void *config_get_variable(int config_type);
int config_get_int(int config_type);
char *config_get_string(int config_type);
int config_parse(char *filename);
void config_set_string(int config_type, char* value);
void config_set_int(int config_type, int value);
void config_dump();
char *_config_find_file();