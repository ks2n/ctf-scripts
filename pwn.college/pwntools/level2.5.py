from pwn import *

context(arch="amd64", os="linux", log_level="info")
challenge_path = "/challenge/pwntools-tutorials-level2.5"
p = process(challenge_path)

p.sendafter("Please give me your assembly in bytes", asm(
'''
    pop rax
    cmp rax, 0

    jns .done

    neg rax

.done:
    push rax
'''))

p.interactive()
