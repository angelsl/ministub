# ministub

A simplified EFI stub that allows you to bundle a Linux kernel image, initial RAM
disk, and command line into a single EFI binary, so that you can sign the image
and use it in a user key Secure Boot setup.

This is just a simplified version of systemd's stub.

### Rationale

systemd's usual EFI stub includes the command line, kernel image and RAM disk as
separate sections in the PE.

I was having random boot failures with that, and so I wondered if the extra sections
were causing issues with my laptop's pretty poor UEFI implementation.

### Usage

`make IMAGE=/boot/vmlinuz-linux INITRAMFS=/boot/initramfs-linux.img CMDLINE=cmdline.txt`
