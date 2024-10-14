#include <sys/shm.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv){
    key_t key = ftok("/dev/myshm1", 0);
    int shmid = shmget(key, 0x400000, 0666);
    char *p = (char *)shmat(shmid, NULL, 0);

    printf("%c\t%c\t%c\t%c\n", p[0], p[1], p[2], p[3]);

    if (shmctl(shmid, IPC_RMID, NULL) < 0) {
        perror("shmctl");
        return 1;
    }

    printf("共享内存已删除\n");

    return 0;

}