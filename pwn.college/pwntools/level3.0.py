from pwn import *

context(arch="amd64", os="linux", log_level="info")

challenge_path = "/challenge/pwntools-tutorials-level3.0"
p = process(challenge_path)

p.sendlineafter(b'Choice >>', b'1')
p.sendlineafter(b'Input your notebook index:', b'0') # Fixed: '0' -> b'0'
p.sendlineafter(b'Input your notebook content:', 'hello \x00') # Fixed: 'hello ' -> b'hello '

p.sendlineafter(b'Choice >>', b'1')
p.sendlineafter(b'Input your notebook index:', b'1') # Fixed: '0' -> b'0'
p.sendlineafter(b'Input your notebook content:', b'world,\x00') # Fixed: 'hello ' -> b'hello '

p.sendlineafter(b'Choice >>', b'1')
p.sendlineafter(b'Input your notebook index:', b'3') # Fixed: '0' -> b'0'
p.sendlineafter(b'Input your notebook content:', b'magic \x00') # Fixed: 'hello ' -> b'hello '

p.sendlineafter(b'Choice >>', b'1')
p.sendlineafter(b'Input your notebook index:', b'5') # Fixed: '0' -> b'0'
p.sendlineafter(b'Input your notebook content:', b'notebook\x00') # Fixed: 'hello ' -> b'hello '

p.sendlineafter(b'Choice >>', b'2')
p.sendlineafter(b'Input your notebook index:', b'1')

p.sendlineafter(b'Choice >>', b'2')
p.sendlineafter(b'Input your notebook index:', b'5')

p.sendlineafter(b'Choice >>', b'4')
p.sendlineafter(b'Input your notebook index:', b'0')

p.sendlineafter(b'Choice >>', b'5')
p.interactive()