#pragma once

#define MAX_BUFFER 100



int query_log[100];

void qps_add_query();
void qps_tick();
char *qps_load_str();
float _qps_approx_of(int num);