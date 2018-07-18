.section .data
.global pubkey
.global pubkey_end

.type pubkey, @object
.type pubkey_end, @object

.balign 16
pubkey:
.incbin "pubkey.dat"
.balign 1
pubkey_end:
.byte 0

