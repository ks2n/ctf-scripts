from pwn import *

context(arch="amd64", os="linux", log_level="info")
challenge_path = "/challenge/pwntools-tutorials-level2.2"
p = process(challenge_path)

p.sendafter("Please give me your assembly in bytes", asm(
'''
div rbx
mov rax, rdx
add rax, rcx
sub rax, rsi
'''))

p.interactive()
