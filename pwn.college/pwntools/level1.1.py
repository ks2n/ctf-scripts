from pwn import *

context(arch="amd64", os="linux", log_level="info")

challenge_path = "/challenge/pwntools-tutorials-level1.1"
p = process(challenge_path)

payload = b'p' + p8(0x15) + p32(123456789) + b'Bypass Me:)'
p.sendline(payload)

p.interactive()
