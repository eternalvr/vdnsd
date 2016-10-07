#include "pid.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

int pid_read( char *file )
{
    FILE *fp;
    int pid;

    fp = fopen(file, "r");
    if(!fp) {
        return 0;
    }
    fscanf(fp, "%d", &pid);
    fclose(fp);

    return pid;
}

int pid_write( char *file )
{
    FILE *fp;
    int fd;
    int pid;

    pid = getpid();


    fd = open(file, O_RDWR|O_CREAT, 0600);
    if(fd == -1) {
        fprintf(stderr, "Could not create pidfile: %s\n", file);
        return 0;
    }

    fp = fdopen(fd, "r+");
    if(fp == NULL) {
        fprintf(stderr, "Could not open pidfile for reading: %s", file);
        close(fd);
        return 0;
    }


    if(flock(fd, LOCK_EX|LOCK_NB) == -1) {
        fscanf(fp, "%d", &pid);
        close(fd);
        printf("Process locked by %d.\n", pid);
        return 0;
    }

    int bytes_written = 0;
    bytes_written = fprintf(fp, "%d\n", pid);
    fflush(fp);


    if(!bytes_written){
        perror("Could not write pidfile");
        close(fd);
        return 0;
    }

    if(flock(fd, LOCK_UN) == -1) {
        perror("Failed to unlock pidfile");
        close(fd);
        return 0;
    }
    fclose(fp);
    close(fd);

    return pid;
}
int pid_check(char *file)
{
    int pid;
    pid = pid_read(file);

    if( pid == getpid()) {
        return 0;
    }
    if (kill(pid, 0) && errno == ESRCH)
        return(0);

    return pid;
}
int pid_delete(char *file)
{
    return unlink(file);
}
