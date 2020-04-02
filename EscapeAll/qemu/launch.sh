#! /bin/sh
./qemu-system-x86_64 \
-initrd ./initramfs.cpio \
-kernel ./vmlinuz-4.8.0-52-generic \
-append 'console=ttyS0 root=/dev/ram oops=panic panic=1' \
-monitor /dev/null \
-m 64M --nographic \
-L pc-bios \
-device rfid,id=vda \