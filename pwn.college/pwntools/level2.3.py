from pwn import *

context(arch="amd64", os="linux", log_level="info")
challenge_path = "/challenge/pwntools-tutorials-level2.3"
p = process(challenge_path)

p.sendafter("Please give me your assembly in bytes", asm(
'''
mov rax, [0x404000]
mov [0x405000], rax
'''))

p.interactive()
