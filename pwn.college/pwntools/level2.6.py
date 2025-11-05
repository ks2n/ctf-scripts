from pwn import *

context(arch="amd64", os="linux", log_level="info")
challenge_path = "/challenge/pwntools-tutorials-level2.6"
p = process(challenge_path)

#now, i know formula for the sum from 1 to rcx = rcx * (rcx + 1) / 2. but this challenge i will use for loop to practice
p.sendafter("Please give me your assembly in bytes", asm(
'''
.prepare:
    xor rax, rax
    mov rbx, 0x1
    jmp .start_loop

.start_loop:
    cmp rbx, rcx
    jg .end_loop

    add rax, rbx
    inc rbx
    jmp .start_loop

.end_loop:
    nop
'''))

p.interactive()
