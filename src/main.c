#include "main.h"


#define NUM_THREADS 1

threadpool thpool;
eredis_t *redis;


void sigint_cb(struct ev_loop *loop, ev_signal *w, int revents) {

    L_INFO("Sigint received. Cleaning up.");
    printf("Sigint received. Cleaning up.");
    ev_break(loop, EVBREAK_ALL);
    eredis_shutdown(redis);
    eredis_free(redis);
    thpool_destroy(thpool);
    logger_free();
    config_free();
    pid_delete(config_get_string(CONFIG_PIDFILE));
    exit(0);

}

int main(int argc, char *argv[]) {

    if (getuid() != 0) {
        printf("Start as root!\n");
        exit(1);
    }


    int server_tcpfd, server_;
    int server_len;
    int numServers = 0;
    struct server_t servers[MAX_LISTEN_IPS];
    char *configfile = 0;
    char *importfile = 0;

    int fd[5];
    int cfd = 0;

    struct sockaddr_in server_address;

    struct ev_loop *loop = ev_default_loop(0);
    struct ev_io stdin_watcher;
    struct ev_signal signal_watcher;

    char port[6] = "53";
    int num_threads = NUM_THREADS;
    int option = 0;
    int reset_on_start = 0;
    char *logfile = "vdns.log";


    ev_signal_init(&signal_watcher, sigint_cb, SIGINT);
    ev_signal_start(loop, &signal_watcher);

    config_initialize();
    if (!config_parse(NULL)) {
        printf("Configfile not found. Using default values\n");
    } else {
        printf("Initializing with config: %s\n", config_get_string(CONFIG_CONFIGFILE));
    }


    while ((option = getopt(argc, argv, "c:t:p:i:rdF")) != -1) {
        switch (option) {
            case 'c':
                if (!config_parse(optarg)) {
                    fprintf(stderr, "Configuration could not be parsed.Exit.\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 't':
                config_set_int(CONFIG_NUM_THREADS, atoi(optarg));
                break;
            case 'p':
                config_set_string(CONFIG_PORT, optarg);
                break;
            case 'i':
                config_set_string(CONFIG_IMPORTFILE, optarg);
                break;
            case 'r':
                config_set_int(CONFIG_RESET_ON_START, 1);
                break;
            case 'd':
                config_dump();
                exit(0);
            case 'F':
                config_set_int(CONFIG_DAEMONIZE, 0);
                break;

            default:
                usage();
                exit(1);


        }
    }



    if(config_get_int(CONFIG_DAEMONIZE)) {

        pid_t pid;
        pid = fork();
        if(pid < 0) {
            fprintf(stderr, "Failed to daemonize.Exit.");
            exit(EXIT_FAILURE);
        }
        if(pid>0) {
            exit(EXIT_SUCCESS);
        }

        if(setsid() < 0) {
            fprintf(stderr, "setsid() failed. Exit.");
            exit(EXIT_FAILURE);
        }
        // second fork!
        pid = fork();
        if(pid < 0) {
            fprintf(stderr, "fork()2 failed.Exit.");
            exit(EXIT_FAILURE);
        }
        if(pid > 0) {
            exit(EXIT_SUCCESS);
        }
        //umask(0);
        //setuid(99);

    }
    int rpid = pid_check(config_get_string(CONFIG_PIDFILE));

    if(!rpid) {
        if(!pid_write(config_get_string(CONFIG_PIDFILE))) {
            fprintf(stderr, "Could not write pid to %s\n", config_get_string(CONFIG_PIDFILE));
            exit(EXIT_FAILURE);
        }
    } else {
        fprintf(stderr, "Process already exists PID: %d! PIDFile: %s\n", rpid, config_get_string(CONFIG_PIDFILE));
        exit(EXIT_FAILURE);
    }


    logger_init(logfile);

    redis = eredis_init(config_get_string(CONFIG_REDIS_HOST), config_get_int(CONFIG_REDIS_PORT));


    if (config_get_int(CONFIG_IMPORT_ON_START)) {
        printf("Importing blocklist from: %s\n", config_get_string(CONFIG_IMPORTFILE));
        import_file(config_get_string(CONFIG_IMPORTFILE));
        exit(EXIT_SUCCESS);
    }


    thpool = thpool_init(config_get_int(CONFIG_NUM_THREADS));


    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof hints);

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = 0x001;

    //snprintf(port, sizeof(port), "%u");

    int retif = getaddrinfo(NULL, port, &hints, &res);
    if (retif != 0) {

        perror("getaddrinfo failed: ");
        exit(1);
    }
    char buf[INET6_ADDRSTRLEN];
    for (p = res; p != NULL; p = p->ai_next) {

        if(numServers >= MAX_LISTEN_IPS) continue;
        void *addr;
        char *ipver;

        // get the pointer to the address itself,
        // different fields in IPv4 and IPv6:
        if (p->ai_family == AF_INET) { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *) p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
        } else { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *) p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }

        // convert the IP to a string and print it:
        inet_ntop(p->ai_family, addr, buf, sizeof buf);
        L_INFO("  %s: %s", ipver, buf);


        servers[cfd].fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (servers[cfd].fd == -1) {
            printf("Could not create sockt for address %s:", buf);
            perror("SocketError");
        }

        int bReuseaddr = 1;
        setsockopt(servers[cfd].fd, SOL_SOCKET, SO_REUSEADDR, (const char *) &bReuseaddr,
                   sizeof(bReuseaddr));

        int status = fcntl(servers[cfd].fd, F_SETFL, fcntl(servers[cfd].fd, F_GETFL, 0) | O_NONBLOCK);

        if (status == -1) {
            perror("calling fcntl");
        }

        if (bind(servers[cfd].fd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("BindError");
        }

        ev_io_init(&servers[cfd].watcher, recv_string, servers[cfd].fd, EV_READ);
        ev_io_start(loop, &servers[cfd].watcher);
        cfd++;
        numServers = cfd;


    }
    freeaddrinfo(res);


    if(config_get_string(CONFIG_EUSER)){
        struct passwd *pw = getpwnam(config_get_string(CONFIG_EUSER));

        if(pw == NULL) {
            fprintf(stderr, "Unknown user %s", config_get_string(CONFIG_EUSER));
            exit(EXIT_FAILURE);
        }
        seteuid(pw->pw_uid);
    }
    if(config_get_string(CONFIG_EGRP)){
        struct group *gr = getgrnam(config_get_string(CONFIG_EGRP));
        if(gr == NULL) {
            fprintf(stderr, "Unknown group %s", config_get_string(CONFIG_EGRP));
            exit(EXIT_FAILURE);
        }
        setegid(gr->gr_gid);
    }

    // attach a stats event
    ev_periodic tick;
    ev_periodic_init (&tick, stats_cb, 0., 10., 0);
    ev_periodic_start (loop, &tick);

    ev_periodic qps_timer;
    ev_periodic_init( &qps_timer, qps_cb, 0., 1., 0);
    ev_periodic_start(loop, &qps_timer);


    L_INFO("Server is ready PID: %d Threads: %d", getpid(), config_get_int(CONFIG_NUM_THREADS));
    // start event loop
    while (1) {
        ev_loop(loop, 0);
    }
    thpool_destroy(thpool);
    return 0;
}

void recv_string(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    char buffer[512];
    struct sockaddr_storage *sender = malloc(sizeof *sender);

    socklen_t sendsize = sizeof(sender);
    memset(sender, 0, sizeof(sender));


    int read = recvfrom(watcher->fd, buffer, sizeof(buffer), 0,
                        (struct sockaddr *) sender, &sendsize);

    if (read < 0) {
        perror("read ");
        return;
    } else if (read == 0) {
        ev_io_stop(loop, watcher);
        free(watcher);
        watcher = NULL;
        L_DEBUG("connection closed");
        return;
    }

    struct sniff_dns *dns = (struct sniff_dns *) malloc(read);
    memcpy(dns, &buffer, read);

    DnsWorker *dworker = worker_create(1, dns, read, watcher->fd,
                                       (struct sockaddr *) sender, sendsize, loop);
    qps_add_query();
    thpool_add_work(thpool, (void *) worker_thread, (void *) dworker);
}

void usage() {
    printf("Usage: vdns [-t threads] [-p port] [-c configfile] [-i blockfile] [-r] [-d] [-F]\n");
}
static void qps_cb (struct ev_loop *loop, ev_periodic *w, int revents){
    qps_tick();
}
static void stats_cb (struct ev_loop *loop, ev_periodic *w, int revents){
    char *qps_str = qps_load_str();
    L_INFO("[STATS] Threads %d/%d QPS %s", thpool->num_threads_alive, thpool->num_threads_working, qps_str);
    free(qps_str);
}