

#include "config.h"

struct config_t __config;

void config_initialize()
{
    __config.num_threads = 1;
    __config.daemonize = 0;
    __config.importfile = 0;
    __config.port = "53";
    __config.reset_on_start = 0;
    __config.import_on_start = 0;
    __config.redis_host = "127.0.0.1";
    __config.redis_port = 6379;
    __config.configfile = 0;
    __config.logfile = 0;
    __config.pidfile = "vdns.pid";
    __config.log_queries=0;
    __config.adspoof_ipv4 = "0.0.0.0";
    __config.adspoof_ipv6 = "::1";
    __config.captive_ipv4 = "0.0.0.0";
    __config.captive_ipv6 = "::1";
}

inline int config_get_int(int config_type){
    return (*(int *)config_get_variable(config_type));
}

inline char *config_get_string(int config_type) {
    return (*(char **)config_get_variable(config_type));
}

char *_config_find_file()
{
    if(access("~/.vdnsd.conf", F_OK) != -1) {

        return "~/.vdnsd.conf";
    }
    if(access("./vdnsd.conf", F_OK) != -1) {

        return "./vdnsd.conf";
    }
    if(access("/etc/vdnsd/vdnsd.conf", F_OK) != -1){

        return "/etc/vdnsd/vdnsd.conf";
    }
    return NULL;
}
int config_parse(char *filename) {
    if(filename == NULL) {
        filename = _config_find_file();
    }
    if(filename == NULL) {
        return 0;
    }
    __config.configfile = filename;

    return _config_read_configfile(__config.configfile);
}
int _config_read_configfile( char *configfile )
{
    char key[512], value[512];
    char line[1024];

    memset(&line, 0, sizeof(line));
    memset(&key, 0, sizeof(key));
    memset(&value, 0, sizeof(value));

    FILE *fp;

    if(access(configfile, F_OK) == -1) {

        return 0;
    }
    if((fp = fopen(configfile,"r")) != NULL){
        /* then file opened successfully. */
        while(!feof(fp)){
            fgets(line, sizeof(line), fp);
            if(line[0] == '#') continue;
            if(strlen(line) < 5) continue;

            if(sscanf(line, "%s %s",&key, &value)) {
                if(strncasecmp(key, "num_threads", strlen(key))==0){
                    config_set_int(CONFIG_NUM_THREADS, atoi(value));
                    continue;
                }
                if(strncasecmp(key, "port", strlen(key))==0){
                    config_set_string(CONFIG_PORT, value);
                    continue;
                }
                if(strncasecmp(key, "importfile", strlen(key))==0){
                    config_set_string(CONFIG_IMPORTFILE, value);
                    continue;
                }
                if(strncasecmp(key, "redis_host", strlen(key))==0){
                    config_set_string(CONFIG_REDIS_HOST, value);
                    continue;
                }
                if(strncasecmp(key, "redis_port", strlen(key))==0){
                    config_set_int(CONFIG_REDIS_PORT, atoi(value));
                    continue;
                }
                if(strncasecmp(key, "reset_on_start", strlen(key))==0){
                    config_set_int(CONFIG_RESET_ON_START, atoi(value));
                    continue;
                }
                if(strncasecmp(key, "daemonize", strlen(key))==0){
                    config_set_int(CONFIG_DAEMONIZE, atoi(value));
                    continue;
                }
                if(strncasecmp(key, "import_on_start", strlen(key))==0){
                    config_set_int(CONFIG_IMPORT_ON_START, atoi(value));
                    continue;
                }
                if(strncasecmp(key, "logfile", strlen(key))==0){
                    config_set_string(CONFIG_LOGFILE, value);
                    continue;
                }
                if(strncasecmp(key, "user", strlen(key))==0){
                    config_set_string(CONFIG_EUSER, value);
                    continue;
                }
                if(strncasecmp(key, "group", strlen(key))==0){
                    config_set_string(CONFIG_EGRP, value);
                    continue;
                }
                if(strncasecmp(key, "pidfile", strlen(key))==0){
                    config_set_string(CONFIG_PIDFILE, value);
                    continue;
                }
                if(strncasecmp(key, "captive_ipv4", strlen(key))==0){
                    config_set_string(CONFIG_CAPTIVE_IPV4, value);
                    continue;
                }
                if(strncasecmp(key, "adspoof_ipv4", strlen(key))==0){
                    config_set_string(CONFIG_ADSPOOF_IPV4, value);
                    continue;
                }
                if(strncasecmp(key, "captive_ipv6", strlen(key))==0){
                    config_set_string(CONFIG_CAPTIVE_IPV4, value);
                    continue;
                }
                if(strncasecmp(key, "adspoof_ipv6", strlen(key))==0){
                    config_set_string(CONFIG_ADSPOOF_IPV4, value);
                    continue;
                }
                if(strncasecmp(key, "log_queries", strlen(key))==0){
                    config_set_int(CONFIG_LOG_QUERIES, atoi(value));
                    continue;
                }
                printf("Warning: unknown key found in config_file: %s", key);

            }

            memset(line, 0, sizeof(line));
        }


    } else {
        printf("Error while reading config: %s", configfile);
        perror("Config:");
        return 0;
    }
    fclose(fp);
    return 1;
}
void config_set_string(int config_type, char *value) {
    char **cp = (char **)config_get_variable(config_type);

    char *t = malloc(strlen(value)+1);
    memset(t, 0, strlen(value)+1);

    strncpy(t, value, strlen(value));
    *cp = t;
}

void config_set_int(int config_type, int value) {
    int *cp = (int *)config_get_variable(config_type);
    *cp = value;
}
void *config_get_variable(int config_type)
{
    switch(config_type){
        case CONFIG_DAEMONIZE: return &__config.daemonize;
        case CONFIG_NUM_THREADS: return &__config.num_threads;
        case CONFIG_RESET_ON_START: return &__config.reset_on_start;
        case CONFIG_IMPORT_ON_START: return &__config.import_on_start;
        case CONFIG_REDIS_PORT: return &__config.redis_port;
        case CONFIG_LOG_QUERIES: return &__config.log_queries;




        // strings
        case CONFIG_PORT: return &__config.port;
        case CONFIG_IMPORTFILE: return &__config.importfile;
        case CONFIG_REDIS_HOST: return &__config.redis_host;
        case CONFIG_CONFIGFILE: return &__config.configfile;
        case CONFIG_LOGFILE: return &__config.logfile;
        case CONFIG_EUSER: return &__config.euser;
        case CONFIG_EGRP: return &__config.egrp;
        case CONFIG_PIDFILE: return &__config.pidfile;
        case CONFIG_CAPTIVE_IPV4: return &__config.captive_ipv4;
        case CONFIG_ADSPOOF_IPV4: return &__config.adspoof_ipv4;
        case CONFIG_CAPTIVE_IPV6: return &__config.captive_ipv6;
        case CONFIG_ADSPOOF_IPV6: return &__config.adspoof_ipv6;

        default:
            return 0;
    }
}
void config_dump()
{
    printf("configuration:\n");
    printf("  running as user %s in group %s\n", __config.euser, __config.egrp);
    printf("  configfile: %s\n", __config.configfile);
    printf("  pidfile: %s\n", __config.pidfile);
    printf("  logfile: %s\n", __config.logfile);
    printf("  num_threads: %d\n", __config.num_threads);
    printf("  Listening Port: %s\n", __config.port);
    printf("  ImportFile: %s\n", __config.importfile);
    printf("  Redis\n");
    printf("   - Host: %s\n", __config.redis_host);
    printf("   - Port: %d\n", __config.redis_port);
    printf("   - Reset on Start: %d\n", __config.reset_on_start);
    printf("  Import on Start: %d\n", __config.import_on_start);
    printf("  Daemonize: %d\n", __config.daemonize);
    printf("  log_queries: %d\n", __config.log_queries);
}
void config_free()
{
    if(__config.redis_host != NULL) {
        free(__config.redis_host);
        __config.redis_host = NULL;
    }
    if(__config.port != NULL) {
        free(__config.port);
        __config.port = NULL;
    }
    if(__config.importfile != NULL) {
        free(__config.importfile);
        __config.importfile = NULL;
    }
    if(__config.logfile != NULL){
        free(__config.logfile);
        __config.logfile = NULL;
    }
    if(__config.pidfile != NULL) {
        free(__config.pidfile);
        __config.pidfile = NULL;
    }
}