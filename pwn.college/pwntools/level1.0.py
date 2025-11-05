from pwn import *

context(arch="amd64", os="linux", log_level="info")

challenge_path = "/challenge/pwntools-tutorials-level1.0"
p = process(challenge_path)

payload = p32(0xdeadbeef)
p.sendline(payload)

p.interactive()
