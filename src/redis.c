#include "redis.h"

eredis_t *eredis_init(char *host, int port)
{
    eredis_t *e = eredis_new();
    eredis_timeout(e, 200);
    eredis_r_max(e, 10);
    eredis_r_retry(e, 1);
 
    eredis_host_add(e, "127.0.0.1", 6379);
    
    eredis_run_thr(e); // non blocking start
    
    return e;
}

int eredis_update(eredis_t *e, char *data, int datalen)
{
    return eredis_w_cmd( e, data, datalen);
}
int eredis_text_update(eredis_t *e, char *format, ...) 
{
    va_list valist;
    va_start(valist, format);
      
    int t = eredis_w_vcmd( e,
                           format,
                           valist);
    va_end(valist);

    return t;
}
eredis_reply_t *eredis_text_cmd( eredis_t * e, char *format, ...)
{
    va_list valist;
    va_start(valist, format);


    eredis_reader_t *r = eredis_r( e );

    eredis_r_clear(r);
    eredis_r_append_vcmd( r, format, valist);
    
    va_end(valist);

   
    eredis_reply_t *reply = eredis_r_reply(r);
    eredis_r_reply_detach(r);
    if(!reply){  
        eredis_r_release( r );
        return NULL;
    }
    if (0) {
        eredis_reply_dump(reply);
        
    }
    eredis_r_release(r); 
        
    return reply;
}
