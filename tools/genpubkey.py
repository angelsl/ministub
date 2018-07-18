#!/usr/bin/python3

import ed25519
import sys

if len(sys.argv) < 3:
    print("Usage: {} <privkey> <pubkey>")
    sys.exit()

with open(sys.argv[1], 'rb') as f:
    privkey = f.read()

with open(sys.argv[2], 'wb') as f:
    f.write(ed25519.publickey(privkey))
