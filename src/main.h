#include <fcntl.h>
#include <ev.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#include <sys/socket.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>

#include "thpool.h"
#include "dnsworker.h"
#include "redis.h"

#include <resolv.h>

#include "dns.h"
#include "import.h"
#include "config.h"
#include "logger.h"
#include "pid.h"

#define MAX_LISTEN_IPS 5

struct server_t {
    int fd;
    ev_io watcher;
};
void usage();
void recv_string(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void stats_cb (struct ev_loop *loop, ev_periodic *w, int revents);