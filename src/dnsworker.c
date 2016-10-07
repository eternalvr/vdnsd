#include "dnsworker.h"
#include "dns.h"
#include "thpool.h"

DnsWorker *worker_create(uint8_t id, struct sniff_dns *dns, uint16_t len, int fd, struct sockaddr* sender, int sendersize, struct ev_loop *loop)
{
	DnsWorker *worker = malloc(sizeof(*worker));
    memset(worker, 0, sizeof(*worker));
    
	worker->id = id;
	worker->dns = dns;
	worker->len = len;
	worker->fd = fd;
    worker->sender = sender;
	worker->sendersize = sendersize;	
	worker->loop = loop;
	worker->sendbufferlen = 0;
	memset(&worker->sendbuffer, 0, 512);
    
	worker->io_worker = malloc( sizeof *worker->io_worker );
	ev_io_init(worker->io_worker, worker_write_cb, worker->fd, EV_WRITE);
    worker->io_worker->data = worker;


    
    
    return worker;
}
void worker_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) 
{
	printf("Socket is available for writing...\n");
	DnsWorker *worker = (DnsWorker*)watcher->data;
	printf("Sending %u bytes\n", worker->sendbufferlen);

	


	memset(worker->sendbuffer, 0, 512);
	worker->sendbufferlen = 0;

	ev_io_stop(loop, watcher);

}
void worker_send(DnsWorker *worker, char *buffer, int buffersize)
{
	memcpy(&worker->sendbuffer, buffer, buffersize);
	worker->sendbufferlen = buffersize;

	int bytes_sent = sendto(worker->fd, worker->sendbuffer, worker->sendbufferlen, MSG_DONTWAIT, worker->sender, worker->sendersize);
	if(bytes_sent <= 0) {
		perror("sendError");
	}
	//ev_io_start(worker->loop, worker->io_worker);
}
void *worker_thread(void *arg, thread *t)
{
	//printf("Worker Thread started.\n");
	DnsWorker *worker = (DnsWorker*)arg;
    worker->thread = *t;
	dns_handle_request(worker);
    worker_free(worker);
}

void worker_free(DnsWorker *worker)
{
	free(worker->sender);
    worker->sender = NULL;

	free(worker->dns);
    worker->dns = NULL;

	free(worker->io_worker);
    worker->io_worker = NULL;

	free(worker);
    worker = NULL;
}
