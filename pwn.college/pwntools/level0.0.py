from pwn import *

context(arch="amd64", os="linux", log_level="info")

challenge_path = "/challenge/pwntools-tutorials-level0.0"
p = process(challenge_path)

payload = b'pokemonA'
p.sendline(payload)

p.interactive()
