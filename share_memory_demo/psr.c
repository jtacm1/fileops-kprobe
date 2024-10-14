#include <sys/mman.h>
#include <sys/stat.h>   /*For mode constants*/
#include <fcntl.h>  /*For O_* constants*/
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    int fd = shm_open("posixsm", O_RDONLY, 0666);
    ftruncate(fd, 0x400000);

    char *p =  (char *)mmap(NULL, 0x400000, 
                    PROT_READ, MAP_SHARED, fd, 0);
    
    printf("%c\t%c\t%c\t%c\n", p[0], p[1], p[2], p[3]);
    munmap(p, 0x400000);

    return 0;
}