#include "qps_counter.h"

#include <stdio.h>
#include <stdlib.h>
int queries = 0;
int qps_bufferPos = 0;

void qps_add_query()
{
    queries++;
}
void qps_tick()
{
    query_log[qps_bufferPos++] = queries;
    if(qps_bufferPos > MAX_BUFFER) {
        qps_bufferPos = 0;
    }
    queries = 0;
}
char *qps_load_str()
{
    char *t = malloc(sizeof(char)*16);
    snprintf(t, 16, "%0.2f, %0.2f, %0.2f", _qps_approx_of(10), _qps_approx_of(30), _qps_approx_of(60));
    return t;
}
float _qps_approx_of(int num)
{
    int k = 0;
    int l = qps_bufferPos-num;
    if(l < 0) {
        l = MAX_BUFFER+l;
    }
    int val = 0;

    while(k<num) {
        val += query_log[l++];
        if(l > MAX_BUFFER) {
            l = 0;
        }
        k++;
    }
    return (float)val / (float)k;
}