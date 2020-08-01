# 网鼎杯2020-boom2

## 题解

mmap了一块地址，这块地址的前面写入了一个栈地址，经过赋值，计算等操作将其改为返回地址，得到返回地址上的libc_start_main+240，再计算和one_gadget偏移，补成One_gadget再移动回去即可