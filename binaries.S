.section .data
.global vmlinuz
.global vmlinuz_end
.global initramfs
.global initramfs_end
.global cmdline
.global cmdline_end

.type vmlinuz, @object
.type vmlinuz_end, @object
.type initramfs, @object
.type initramfs_end, @object
.type cmdline, @object
.type cmdline_end, @object

.balign 16
cmdline:
.incbin "/dev/null"
.balign 1
cmdline_end:
.byte 0

.balign 16
vmlinuz:
.incbin "/dev/null"
.balign 1
vmlinuz_end:
.byte 0

.balign 16
initramfs:
.incbin "/dev/null"
.balign 1
initramfs_end:
.byte 0
