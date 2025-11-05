from pwn import *

context(arch="amd64", os="linux", log_level="info")
challenge_path = "/challenge/pwntools-tutorials-level2.4"
p = process(challenge_path)

p.sendafter("Please give me your assembly in bytes", asm(
'''
pop rax
sub rax, rbx
push rax
'''))

p.interactive()
