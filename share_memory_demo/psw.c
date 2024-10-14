#include <sys/mman.h>
#include <sys/stat.h>   /*For mode constants*/
#include <fcntl.h>  /*For O_* constants*/
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    int fd = shm_open("posixsm", O_CREAT | O_RDWR, 666);
    ftruncate(fd, 0x400000);

    char *p = (char *)mmap(NULL, 0x400000, 
                            PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    memset(p, 'a', 0x400000);
    munmap(p, 0x400000);

    return 0;

}