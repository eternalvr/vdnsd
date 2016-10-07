#include "logger.h"

FILE *lfP;
pthread_t logThread;
pthread_mutex_t logMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t writeMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t writeCondition = PTHREAD_COND_INITIALIZER;
int log_running = 1;

int currentLevel = LOG_DEBUG;

char buffer[4096];

int bufferPos = 0;

void logger_init( char *path ) {

    if(pthread_mutex_init(&logMutex, NULL) != 0)
    {
        fprintf(stderr, "Mutex init failed.");
        exit(EXIT_FAILURE);
    }
    if(pthread_mutex_init(&writeMutex, NULL) != 0)
    {
        fprintf(stderr, "Writemutex init failed.");
        exit(EXIT_FAILURE);
    }
    if(pthread_create(&logThread, NULL, logger_thread, NULL) != 0){
        fprintf(stderr, "Couldn't create log thread");
        exit(EXIT_FAILURE);
    }
    lfP = fopen(path, "a+");
    setvbuf(lfP, NULL, _IOLBF, 0);
    if(!lfP) {
        fprintf(stderr, "Could not open logfile: %s", path);
        exit(EXIT_FAILURE);
    }
}

void logger_log(int loglevel, char *format, ...) {

    if(loglevel & currentLevel != currentLevel)
    {
        return;
    }
    va_list val;
    time_t t_time;


    va_start(val, format);
    pthread_mutex_lock(&logMutex);

    t_time = time(NULL);
    struct tm *ltime = localtime(&t_time);

    int len = strftime(&buffer[bufferPos], 4096, "[%F %T]", ltime);
    bufferPos+=len;

    len = snprintf(&buffer[bufferPos], sizeof(buffer)-bufferPos, "[#%ld] ", pthread_self ());
    bufferPos+=len;

    len = vsnprintf(&buffer[bufferPos],sizeof(buffer)-bufferPos, format, val);

    bufferPos+=len;
    buffer[bufferPos] = '\n';
    bufferPos++;
    pthread_mutex_unlock(&logMutex);
    pthread_cond_broadcast(&writeCondition);
}

void *logger_thread(void *empty) {
    pthread_mutex_lock(&writeMutex);

    while(log_running){
        pthread_cond_wait(&writeCondition, &writeMutex);
        pthread_mutex_lock(&logMutex);

        fputs(buffer, lfP);
        fflush(lfP);
        memset(buffer, 0, bufferPos);
        bufferPos = 0;

        pthread_mutex_unlock(&logMutex);
    }

    pthread_mutex_unlock(&writeMutex);
}
void logger_free()
{
    log_running = 0;
    pthread_cond_broadcast(&writeCondition);
    pthread_mutex_destroy(&writeMutex);
    pthread_mutex_destroy(&logMutex);
    pthread_cond_destroy(&writeCondition);
    pthread_join(logThread, NULL);
    fclose(lfP);

}

