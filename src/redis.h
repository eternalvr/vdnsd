#include <eredis.h>

#include <stdlib.h>


#define REDIS_DEBUG 1



eredis_t *eredis_init(char *host, int port);

int eredis_update(eredis_t *e, char *data, int datalen);
int eredis_text_update(eredis_t *e, char *format, ...);
eredis_reply_t *eredis_text_cmd( eredis_t * e, char *format, ...);