#include <sys/shm.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]){
    key_t key = ftok("/dev/myshm1", 0);
    int shmid = shmget(key, 0x400000, IPC_CREAT | 0666);
    char *p = (char *)shmat(shmid,  NULL, 0);
    memset(p, 'A', 0x400000);
    shmdt(p);

    return 0;
}