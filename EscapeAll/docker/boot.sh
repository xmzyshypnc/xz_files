#! /bin/sh
qemu-system-x86_64 \
-m 256M \
-kernel ./vmlinuz-4.15.0-54-generic \
-initrd  ./initramfs.img \
-append "noexec rdinit=./linuxrc" \
-gdb tcp::1234
