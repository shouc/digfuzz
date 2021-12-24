#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

struct digfuzz_bucket
{
	long unsigned int PC;
  uint32_t count;
};

typedef struct digfuzz_bucket digfuzz_bucket_t;

#define HASHMAP_SIZE 1000000


#define SHM_SIZE (HASHMAP_SIZE*sizeof(digfuzz_bucket_t))

int main(){
    digfuzz_bucket_t* shmem;

    char* shm_key = getenv("DIGFUZZ_SHM");
    int fd = shm_open(shm_key, O_RDWR, S_IREAD | S_IWRITE);
    if (fd <= -1) {
        fprintf(stderr, "Failed to open shared memory region: %d\n", errno);
        _exit(-1);
    }

    shmem = (digfuzz_bucket_t *)mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (shmem == MAP_FAILED) {
        fprintf(stderr, "Failed to mmap shared memory region\n");
        _exit(-1);
    }

    for (int i = 0; i < HASHMAP_SIZE; i++) 
    if (shmem[i].PC != 0)
        printf("%lu,%d\n", shmem[i].PC, shmem[i].count);
}