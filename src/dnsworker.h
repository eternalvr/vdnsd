#pragma once
#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <ev.h>

#include "thpool.h"

typedef struct {
	uint8_t id;
	struct sniff_dns *dns;
	uint16_t len;
	int fd;
	struct sockaddr* sender;
	int sendersize;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
	struct ev_loop *loop;
	struct ev_io *io_worker;
	char sendbuffer[1024];
	int sendbufferlen;
	thread thread;


} DnsWorker;

DnsWorker *worker_create(uint8_t id, struct sniff_dns *dns, uint16_t len, int fd, struct sockaddr* sender, int sendersize, struct ev_loop *loop);
void *worker_thread(void *arg, thread *t);
void worker_free(DnsWorker *worker);
void worker_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
