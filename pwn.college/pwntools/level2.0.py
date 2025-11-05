from pwn import *

context(arch="amd64", os="linux", log_level="info")
challenge_path = "/challenge/pwntools-tutorials-level2.0"
p = process(challenge_path)

p.sendafter("Please give me your assembly in bytes", asm(
'''
mov rax, 0x12345678
'''))

p.interactive()
