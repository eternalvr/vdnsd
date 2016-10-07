#ifndef LOGGER_H
#define LOGGER_H

#pragma once

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#define LOG_DEBUG   1 << 4
#define LOG_INFO    1 << 3
#define LOG_WARN    1 << 2
#define LOG_CRIT    1 << 1

#define L_DEBUG(...) logger_log(LOG_DEBUG, __VA_ARGS__)
#define L_INFO(...) logger_log(LOG_INFO, __VA_ARGS__)
#define L_WARN(...) logger_log(LOG_WARN, __VA_ARGS__)
#define L_CRIT(...) logger_log(LOG_CRIT, __VA_ARGS__)


void logger_init( char *path);
void *logger_thread(void *empty);
void logger_log(int loglevel, char *format, ...);
void logger_free();

#endif