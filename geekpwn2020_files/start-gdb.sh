#!/bin/sh
qemu-system-x86_64 --nographic -monitor /dev/null -kernel ./bzImage_mine -initrd ./initramfs.img -m 128M -append 'console=ttyS0 rdinit=/linuxrc nokaslr quiet oops=panic panic=1' -gdb tcp::1234 -S -no-reboot -net none 2>/dev/null

