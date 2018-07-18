#!/usr/bin/python3

import ed25519
import sys
import struct

if len(sys.argv) < 6:
    print("Usage: {} <output> <privkey> <vmlinuz> <cmdline> <initrd 1> [initrd 2] ...")
    sys.exit()

output_fn = sys.argv[1]
privkey_fn = sys.argv[2]
vmlinuz_fn = sys.argv[3]
cmdline_fn = sys.argv[4]
initrd_fns = sys.argv[5:]

def read_file(fn):
    with open(fn, 'rb') as f:
        return f.read()
vmlinuz_data = read_file(vmlinuz_fn)
cmdline_data = read_file(cmdline_fn)
initrd_datas = [read_file(fn) for fn in initrd_fns]

buf = bytearray(struct.pack("=3Q", len(vmlinuz_data), sum(map(len, initrd_datas)), len(cmdline_data)))
buf += vmlinuz_data
for initrd_data in initrd_datas:
    buf += initrd_data
buf += cmdline_data

privkey = read_file(privkey_fn)
buf += ed25519.signature(buf, privkey, ed25519.publickey(privkey))

with open(output_fn, 'wb') as f:
    f.write(buf)
